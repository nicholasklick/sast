//! File caching and change detection for incremental analysis

use crate::fingerprint::FileFingerprint;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{debug, info, warn};

#[derive(Error, Debug)]
pub enum CacheError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Cache directory not found: {0}")]
    CacheDirectoryNotFound(PathBuf),

    #[error("Invalid cache format")]
    InvalidCacheFormat,
}

/// Configuration for cache behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Directory to store cache files (default: .kodecd/cache)
    pub cache_dir: PathBuf,

    /// Enable file content hashing (slower but more accurate)
    pub content_hashing: bool,

    /// Cache TTL in seconds (0 = infinite)
    pub ttl_seconds: u64,

    /// Maximum cache size in MB (0 = unlimited)
    pub max_size_mb: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            cache_dir: PathBuf::from(".kodecd/cache"),
            content_hashing: true,
            ttl_seconds: 0, // No expiration by default
            max_size_mb: 100, // 100 MB default limit
        }
    }
}

/// File metadata for tracking changes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    /// Relative file path
    pub path: PathBuf,

    /// File fingerprint
    pub fingerprint: FileFingerprint,

    /// Last scan timestamp
    pub last_scanned: u64,
}

/// Scan results for a single file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    /// File metadata
    pub metadata: FileMetadata,

    /// Number of findings
    pub finding_count: usize,

    /// Cached findings (serialized JSON)
    pub findings_json: String,
}

/// Cache for incremental analysis
pub struct Cache {
    config: CacheConfig,
    file_index: HashMap<PathBuf, FileMetadata>,
    results_cache: HashMap<PathBuf, ScanResults>,
}

impl Cache {
    /// Create new cache with configuration
    pub fn new(config: CacheConfig) -> Result<Self, CacheError> {
        // Create cache directory if it doesn't exist
        if !config.cache_dir.exists() {
            std::fs::create_dir_all(&config.cache_dir)?;
        }

        let mut cache = Self {
            config,
            file_index: HashMap::new(),
            results_cache: HashMap::new(),
        };

        // Load existing cache
        cache.load()?;

        Ok(cache)
    }

    /// Load cache from disk
    fn load(&mut self) -> Result<(), CacheError> {
        let index_path = self.config.cache_dir.join("file_index.json");
        let results_path = self.config.cache_dir.join("results.json");

        // Load file index
        if index_path.exists() {
            let content = std::fs::read_to_string(&index_path)?;
            self.file_index = serde_json::from_str(&content)?;
            info!("Loaded cache index with {} files", self.file_index.len());
        }

        // Load results cache
        if results_path.exists() {
            let content = std::fs::read_to_string(&results_path)?;
            self.results_cache = serde_json::from_str(&content)?;
            debug!("Loaded results cache with {} entries", self.results_cache.len());
        }

        Ok(())
    }

    /// Save cache to disk
    pub fn save(&self) -> Result<(), CacheError> {
        let index_path = self.config.cache_dir.join("file_index.json");
        let results_path = self.config.cache_dir.join("results.json");

        // Save file index
        let index_json = serde_json::to_string_pretty(&self.file_index)?;
        std::fs::write(&index_path, index_json)?;

        // Save results cache
        let results_json = serde_json::to_string_pretty(&self.results_cache)?;
        std::fs::write(&results_path, results_json)?;

        info!("Saved cache with {} files", self.file_index.len());
        Ok(())
    }

    /// Get files that have changed since last scan
    pub fn get_changed_files(&mut self, root_dir: impl AsRef<Path>) -> Result<Vec<PathBuf>, CacheError> {
        let root_dir = root_dir.as_ref();
        let mut changed_files = Vec::new();

        // Walk through all source files
        for entry in walkdir::WalkDir::new(root_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| Self::is_source_file(e.path()))
        {
            let path = entry.path();
            let relative_path = path.strip_prefix(root_dir).unwrap_or(path).to_path_buf();

            // Generate current fingerprint
            let current_fp = match FileFingerprint::from_file(path) {
                Ok(fp) => fp,
                Err(e) => {
                    warn!("Failed to fingerprint {}: {}", path.display(), e);
                    continue;
                }
            };

            // Check if file changed
            let is_changed = match self.file_index.get(&relative_path) {
                Some(cached_metadata) => cached_metadata.fingerprint.has_changed(&current_fp),
                None => true, // New file
            };

            if is_changed {
                debug!("File changed: {}", relative_path.display());
                changed_files.push(relative_path.clone());

                // Update file index
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                self.file_index.insert(
                    relative_path,
                    FileMetadata {
                        path: path.to_path_buf(),
                        fingerprint: current_fp,
                        last_scanned: now,
                    },
                );
            }
        }

        info!("Found {} changed files out of {} total",
              changed_files.len(),
              self.file_index.len());

        Ok(changed_files)
    }

    /// Get all tracked files
    pub fn get_all_files(&self) -> Vec<&PathBuf> {
        self.file_index.keys().collect()
    }

    /// Store scan results for a file
    pub fn store_results(
        &mut self,
        file_path: impl AsRef<Path>,
        findings: &[kodecd_query::Finding],
    ) -> Result<(), CacheError> {
        let file_path = file_path.as_ref();

        let metadata = self.file_index.get(file_path).ok_or_else(|| {
            CacheError::InvalidCacheFormat
        })?;

        let findings_json = serde_json::to_string(findings)?;

        self.results_cache.insert(
            file_path.to_path_buf(),
            ScanResults {
                metadata: metadata.clone(),
                finding_count: findings.len(),
                findings_json,
            },
        );

        Ok(())
    }

    /// Get cached results for a file
    pub fn get_results(&self, file_path: impl AsRef<Path>) -> Option<Vec<kodecd_query::Finding>> {
        let results = self.results_cache.get(file_path.as_ref())?;
        serde_json::from_str(&results.findings_json).ok()
    }

    /// Clear cache
    pub fn clear(&mut self) -> Result<(), CacheError> {
        self.file_index.clear();
        self.results_cache.clear();

        // Remove cache files
        let index_path = self.config.cache_dir.join("file_index.json");
        let results_path = self.config.cache_dir.join("results.json");

        if index_path.exists() {
            std::fs::remove_file(&index_path)?;
        }
        if results_path.exists() {
            std::fs::remove_file(&results_path)?;
        }

        info!("Cache cleared");
        Ok(())
    }

    /// Prune old cache entries
    pub fn prune_old_entries(&mut self) -> Result<(), CacheError> {
        if self.config.ttl_seconds == 0 {
            return Ok(()); // No TTL configured
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let cutoff = now - self.config.ttl_seconds;

        // Remove old entries
        self.file_index.retain(|_, metadata| metadata.last_scanned >= cutoff);
        self.results_cache.retain(|_, results| results.metadata.last_scanned >= cutoff);

        Ok(())
    }

    /// Check if file is a source file
    fn is_source_file(path: &Path) -> bool {
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            matches!(
                ext,
                "js" | "ts" | "jsx" | "tsx" | "py" | "java" | "go" | "rs" | "php" | "rb" | "cs" | "swift"
            )
        } else {
            false
        }
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let total_findings: usize = self.results_cache.values()
            .map(|r| r.finding_count)
            .sum();

        CacheStats {
            total_files: self.file_index.len(),
            cached_results: self.results_cache.len(),
            total_findings,
        }
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_files: usize,
    pub cached_results: usize,
    pub total_findings: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_cache_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = CacheConfig {
            cache_dir: temp_dir.path().join(".kodecd/cache"),
            ..Default::default()
        };

        let cache = Cache::new(config);
        assert!(cache.is_ok());
    }

    #[test]
    fn test_cache_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let config = CacheConfig {
            cache_dir: temp_dir.path().join(".kodecd/cache"),
            ..Default::default()
        };

        {
            let cache = Cache::new(config.clone()).unwrap();
            cache.save().unwrap();
        }

        // Load cache again
        let cache2 = Cache::new(config).unwrap();
        assert_eq!(cache2.file_index.len(), 0);
    }
}
