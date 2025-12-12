//! Deep Analysis Caching for intermediate analysis artifacts
//!
//! This module provides caching for expensive intermediate analysis results:
//! - Control Flow Graphs (CFG)
//! - Function Taint Summaries
//! - Symbol Tables (future)
//! - Call Graphs (future)
//!
//! Using binary serialization (bincode) for efficient storage and fast loading.

use crate::fingerprint::FileFingerprint;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{debug, info, warn};

#[derive(Error, Debug)]
pub enum AnalysisCacheError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Bincode(#[from] bincode::Error),

    #[error("Cache directory not found: {0}")]
    CacheDirectoryNotFound(PathBuf),

    #[error("Cache entry not found for: {0}")]
    NotFound(String),

    #[error("Cache entry expired or invalid")]
    Invalid,
}

/// Configuration for the analysis cache
#[derive(Debug, Clone)]
pub struct AnalysisCacheConfig {
    /// Root directory for cache storage
    pub cache_dir: PathBuf,
    /// Enable CFG caching
    pub cache_cfg: bool,
    /// Enable function summary caching
    pub cache_summaries: bool,
    /// Enable AST caching (requires AST serialization support)
    pub cache_ast: bool,
    /// Maximum cache size in MB (0 = unlimited)
    pub max_size_mb: usize,
    /// Cache version (for invalidation on format changes)
    pub version: u32,
}

impl Default for AnalysisCacheConfig {
    fn default() -> Self {
        Self {
            cache_dir: PathBuf::from(".giterra/cache/analysis"),
            cache_cfg: true,
            cache_summaries: true,
            cache_ast: false, // Disabled by default until AST serialization is implemented
            max_size_mb: 500,
            version: 1,
        }
    }
}

/// Metadata for a cached analysis artifact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntryMetadata {
    /// File fingerprint at time of caching
    pub fingerprint: FileFingerprint,
    /// Cache version
    pub version: u32,
    /// Timestamp when cached
    pub cached_at: u64,
    /// Size of cached data in bytes
    pub size_bytes: usize,
}

/// Cached Control Flow Graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedCfg {
    pub metadata: CacheEntryMetadata,
    /// Serialized CFG data (bincode)
    pub cfg_data: Vec<u8>,
}

/// Cached Function Summaries for a file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedSummaries {
    pub metadata: CacheEntryMetadata,
    /// Map of function name to serialized summary
    pub summaries: HashMap<String, Vec<u8>>,
}

/// Index of all cached analysis artifacts
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnalysisCacheIndex {
    /// Version of the cache format
    pub version: u32,
    /// Map of file path to CFG cache entry metadata
    pub cfg_entries: HashMap<PathBuf, CacheEntryMetadata>,
    /// Map of file path to summaries cache entry metadata
    pub summary_entries: HashMap<PathBuf, CacheEntryMetadata>,
    /// Total cache size in bytes
    pub total_size_bytes: usize,
}

/// Deep analysis cache for intermediate artifacts
pub struct AnalysisCache {
    config: AnalysisCacheConfig,
    index: AnalysisCacheIndex,
}

impl AnalysisCache {
    /// Create a new analysis cache
    pub fn new(config: AnalysisCacheConfig) -> Result<Self, AnalysisCacheError> {
        // Create cache directories
        let artifacts_dir = config.cache_dir.join("artifacts");
        if !artifacts_dir.exists() {
            std::fs::create_dir_all(&artifacts_dir)?;
        }

        let mut cache = Self {
            config,
            index: AnalysisCacheIndex::default(),
        };

        // Load existing index
        cache.load_index()?;

        Ok(cache)
    }

    /// Load the cache index from disk
    fn load_index(&mut self) -> Result<(), AnalysisCacheError> {
        let index_path = self.config.cache_dir.join("index.bin");

        if index_path.exists() {
            let file = std::fs::File::open(&index_path)?;
            let reader = BufReader::new(file);

            match bincode::deserialize_from(reader) {
                Ok(index) => {
                    self.index = index;
                    // Check version compatibility
                    if self.index.version != self.config.version {
                        info!("Cache version mismatch, clearing cache");
                        self.clear()?;
                    }
                    info!("Loaded analysis cache index with {} CFG entries, {} summary entries",
                          self.index.cfg_entries.len(),
                          self.index.summary_entries.len());
                }
                Err(e) => {
                    warn!("Failed to load cache index: {}, starting fresh", e);
                    self.index = AnalysisCacheIndex {
                        version: self.config.version,
                        ..Default::default()
                    };
                }
            }
        } else {
            self.index.version = self.config.version;
        }

        Ok(())
    }

    /// Save the cache index to disk
    pub fn save_index(&self) -> Result<(), AnalysisCacheError> {
        let index_path = self.config.cache_dir.join("index.bin");
        let file = std::fs::File::create(&index_path)?;
        let writer = BufWriter::new(file);
        bincode::serialize_into(writer, &self.index)?;
        debug!("Saved analysis cache index");
        Ok(())
    }

    /// Get the artifact file path for a source file
    fn artifact_path(&self, file_path: &Path, artifact_type: &str) -> PathBuf {
        let hash = self.hash_path(file_path);
        self.config.cache_dir
            .join("artifacts")
            .join(format!("{}.{}.bin", hash, artifact_type))
    }

    /// Hash a file path for cache key
    fn hash_path(&self, path: &Path) -> String {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        path.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }

    /// Check if CFG cache is valid for a file
    pub fn has_valid_cfg(&self, file_path: &Path, current_fingerprint: &FileFingerprint) -> bool {
        if !self.config.cache_cfg {
            return false;
        }

        if let Some(meta) = self.index.cfg_entries.get(file_path) {
            !meta.fingerprint.has_changed(current_fingerprint) && meta.version == self.config.version
        } else {
            false
        }
    }

    /// Check if summaries cache is valid for a file
    pub fn has_valid_summaries(&self, file_path: &Path, current_fingerprint: &FileFingerprint) -> bool {
        if !self.config.cache_summaries {
            return false;
        }

        if let Some(meta) = self.index.summary_entries.get(file_path) {
            !meta.fingerprint.has_changed(current_fingerprint) && meta.version == self.config.version
        } else {
            false
        }
    }

    /// Store a CFG in the cache
    pub fn store_cfg<T: Serialize>(
        &mut self,
        file_path: &Path,
        fingerprint: &FileFingerprint,
        cfg: &T,
    ) -> Result<(), AnalysisCacheError> {
        if !self.config.cache_cfg {
            return Ok(());
        }

        let cfg_data = bincode::serialize(cfg)?;
        let size_bytes = cfg_data.len();

        let cached = CachedCfg {
            metadata: CacheEntryMetadata {
                fingerprint: fingerprint.clone(),
                version: self.config.version,
                cached_at: current_timestamp(),
                size_bytes,
            },
            cfg_data,
        };

        // Write to file
        let artifact_path = self.artifact_path(file_path, "cfg");
        let file = std::fs::File::create(&artifact_path)?;
        let writer = BufWriter::new(file);
        bincode::serialize_into(writer, &cached)?;

        // Update index
        self.index.cfg_entries.insert(
            file_path.to_path_buf(),
            cached.metadata,
        );
        self.index.total_size_bytes += size_bytes;

        debug!("Cached CFG for {} ({} bytes)", file_path.display(), size_bytes);
        Ok(())
    }

    /// Load a CFG from the cache
    pub fn load_cfg<T: for<'de> Deserialize<'de>>(
        &self,
        file_path: &Path,
    ) -> Result<T, AnalysisCacheError> {
        let artifact_path = self.artifact_path(file_path, "cfg");

        if !artifact_path.exists() {
            return Err(AnalysisCacheError::NotFound(file_path.display().to_string()));
        }

        let file = std::fs::File::open(&artifact_path)?;
        let reader = BufReader::new(file);
        let cached: CachedCfg = bincode::deserialize_from(reader)?;

        // Deserialize the actual CFG
        let cfg: T = bincode::deserialize(&cached.cfg_data)?;

        debug!("Loaded cached CFG for {}", file_path.display());
        Ok(cfg)
    }

    /// Store function summaries in the cache
    pub fn store_summaries<T: Serialize>(
        &mut self,
        file_path: &Path,
        fingerprint: &FileFingerprint,
        summaries: &HashMap<String, T>,
    ) -> Result<(), AnalysisCacheError> {
        if !self.config.cache_summaries {
            return Ok(());
        }

        let mut serialized_summaries = HashMap::new();
        let mut total_size = 0;

        for (name, summary) in summaries {
            let data = bincode::serialize(summary)?;
            total_size += data.len();
            serialized_summaries.insert(name.clone(), data);
        }

        let cached = CachedSummaries {
            metadata: CacheEntryMetadata {
                fingerprint: fingerprint.clone(),
                version: self.config.version,
                cached_at: current_timestamp(),
                size_bytes: total_size,
            },
            summaries: serialized_summaries,
        };

        // Write to file
        let artifact_path = self.artifact_path(file_path, "summaries");
        let file = std::fs::File::create(&artifact_path)?;
        let writer = BufWriter::new(file);
        bincode::serialize_into(writer, &cached)?;

        // Update index
        self.index.summary_entries.insert(
            file_path.to_path_buf(),
            cached.metadata,
        );
        self.index.total_size_bytes += total_size;

        debug!("Cached {} summaries for {} ({} bytes)",
               summaries.len(), file_path.display(), total_size);
        Ok(())
    }

    /// Load function summaries from the cache
    pub fn load_summaries<T: for<'de> Deserialize<'de>>(
        &self,
        file_path: &Path,
    ) -> Result<HashMap<String, T>, AnalysisCacheError> {
        let artifact_path = self.artifact_path(file_path, "summaries");

        if !artifact_path.exists() {
            return Err(AnalysisCacheError::NotFound(file_path.display().to_string()));
        }

        let file = std::fs::File::open(&artifact_path)?;
        let reader = BufReader::new(file);
        let cached: CachedSummaries = bincode::deserialize_from(reader)?;

        // Deserialize each summary
        let mut result = HashMap::new();
        for (name, data) in cached.summaries {
            let summary: T = bincode::deserialize(&data)?;
            result.insert(name, summary);
        }

        debug!("Loaded {} cached summaries for {}", result.len(), file_path.display());
        Ok(result)
    }

    /// Invalidate cache for a specific file
    pub fn invalidate(&mut self, file_path: &Path) -> Result<(), AnalysisCacheError> {
        // Remove from index
        if let Some(meta) = self.index.cfg_entries.remove(file_path) {
            self.index.total_size_bytes = self.index.total_size_bytes.saturating_sub(meta.size_bytes);
        }
        if let Some(meta) = self.index.summary_entries.remove(file_path) {
            self.index.total_size_bytes = self.index.total_size_bytes.saturating_sub(meta.size_bytes);
        }

        // Remove artifact files
        let cfg_path = self.artifact_path(file_path, "cfg");
        let summaries_path = self.artifact_path(file_path, "summaries");

        if cfg_path.exists() {
            std::fs::remove_file(&cfg_path)?;
        }
        if summaries_path.exists() {
            std::fs::remove_file(&summaries_path)?;
        }

        debug!("Invalidated cache for {}", file_path.display());
        Ok(())
    }

    /// Clear entire cache
    pub fn clear(&mut self) -> Result<(), AnalysisCacheError> {
        // Remove all artifact files
        let artifacts_dir = self.config.cache_dir.join("artifacts");
        if artifacts_dir.exists() {
            for entry in std::fs::read_dir(&artifacts_dir)? {
                if let Ok(entry) = entry {
                    std::fs::remove_file(entry.path())?;
                }
            }
        }

        // Reset index
        self.index = AnalysisCacheIndex {
            version: self.config.version,
            ..Default::default()
        };

        info!("Analysis cache cleared");
        Ok(())
    }

    /// Get cache statistics
    pub fn stats(&self) -> AnalysisCacheStats {
        AnalysisCacheStats {
            cfg_entries: self.index.cfg_entries.len(),
            summary_entries: self.index.summary_entries.len(),
            total_size_bytes: self.index.total_size_bytes,
        }
    }

    /// Prune cache if over size limit
    pub fn prune_if_needed(&mut self) -> Result<(), AnalysisCacheError> {
        if self.config.max_size_mb == 0 {
            return Ok(()); // No limit
        }

        let max_bytes = self.config.max_size_mb * 1024 * 1024;
        if self.index.total_size_bytes <= max_bytes {
            return Ok(());
        }

        // Collect entries with timestamps
        let mut entries: Vec<(&PathBuf, u64, usize)> = Vec::new();

        for (path, meta) in &self.index.cfg_entries {
            entries.push((path, meta.cached_at, meta.size_bytes));
        }
        for (path, meta) in &self.index.summary_entries {
            entries.push((path, meta.cached_at, meta.size_bytes));
        }

        // Sort by timestamp (oldest first)
        entries.sort_by_key(|(_, ts, _)| *ts);

        // Remove oldest entries until under limit
        let mut to_remove = Vec::new();
        let mut current_size = self.index.total_size_bytes;

        for (path, _, size) in entries {
            if current_size <= max_bytes {
                break;
            }
            to_remove.push(path.clone());
            current_size -= size;
        }

        for path in to_remove {
            self.invalidate(&path)?;
        }

        info!("Pruned cache to {} MB", self.index.total_size_bytes / (1024 * 1024));
        Ok(())
    }
}

/// Statistics about the analysis cache
#[derive(Debug, Clone)]
pub struct AnalysisCacheStats {
    pub cfg_entries: usize,
    pub summary_entries: usize,
    pub total_size_bytes: usize,
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_analysis_cache_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = AnalysisCacheConfig {
            cache_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let cache = AnalysisCache::new(config);
        assert!(cache.is_ok());
    }

    #[test]
    fn test_cfg_caching() {
        let temp_dir = TempDir::new().unwrap();
        let config = AnalysisCacheConfig {
            cache_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let mut cache = AnalysisCache::new(config).unwrap();

        // Create a test "CFG" (just a simple struct for testing)
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestCfg {
            nodes: Vec<String>,
            edges: Vec<(usize, usize)>,
        }

        let test_cfg = TestCfg {
            nodes: vec!["entry".to_string(), "exit".to_string()],
            edges: vec![(0, 1)],
        };

        let fingerprint = FileFingerprint {
            content_hash: "abc123".to_string(),
            size: 100,
            modified: 12345,
        };

        let file_path = Path::new("test.js");

        // Store
        cache.store_cfg(file_path, &fingerprint, &test_cfg).unwrap();

        // Check validity
        assert!(cache.has_valid_cfg(file_path, &fingerprint));

        // Load
        let loaded: TestCfg = cache.load_cfg(file_path).unwrap();
        assert_eq!(loaded, test_cfg);

        // Save and reload index
        cache.save_index().unwrap();
    }
}
