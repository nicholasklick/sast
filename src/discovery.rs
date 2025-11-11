//! File discovery module for multi-file analysis
//!
//! Handles recursive directory traversal, file filtering, and language detection

use anyhow::{Context, Result};
use ignore::WalkBuilder;
use kodecd_parser::Language;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Represents a discovered source file ready for analysis
#[derive(Debug, Clone)]
pub struct SourceFile {
    pub path: PathBuf,
    pub language: Language,
}

/// Configuration for file discovery
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Follow symbolic links
    pub follow_links: bool,
    /// Respect .gitignore files
    pub respect_gitignore: bool,
    /// Maximum file size in bytes (None = no limit)
    pub max_file_size: Option<usize>,
    /// Additional glob patterns to include
    pub include_patterns: Vec<String>,
    /// Glob patterns to exclude
    pub exclude_patterns: Vec<String>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            follow_links: false,
            respect_gitignore: true,
            max_file_size: Some(10 * 1024 * 1024), // 10MB default
            include_patterns: vec![],
            exclude_patterns: vec![
                "node_modules/**".to_string(),
                "target/**".to_string(),
                "build/**".to_string(),
                "dist/**".to_string(),
                ".git/**".to_string(),
            ],
        }
    }
}

/// Discovers source files in a given path
pub struct FileDiscovery {
    config: DiscoveryConfig,
}

impl FileDiscovery {
    pub fn new(config: DiscoveryConfig) -> Self {
        Self { config }
    }

    pub fn with_default_config() -> Self {
        Self::new(DiscoveryConfig::default())
    }

    /// Discover all analyzable files in the given path
    pub fn discover(&self, path: &Path) -> Result<Vec<SourceFile>> {
        if !path.exists() {
            anyhow::bail!("Path does not exist: {}", path.display());
        }

        // If it's a single file, return it directly
        if path.is_file() {
            return self.discover_single_file(path);
        }

        // If it's a directory, walk it
        if path.is_dir() {
            return self.discover_directory(path);
        }

        anyhow::bail!("Path is neither a file nor directory: {}", path.display());
    }

    fn discover_single_file(&self, path: &Path) -> Result<Vec<SourceFile>> {
        // Check file size
        if let Some(max_size) = self.config.max_file_size {
            let metadata = std::fs::metadata(path)
                .context("Failed to read file metadata")?;
            if metadata.len() > max_size as u64 {
                warn!("Skipping file (too large): {}", path.display());
                return Ok(vec![]);
            }
        }

        // Detect language
        match Language::from_path(path) {
            Ok(language) => {
                debug!("Discovered file: {} ({})", path.display(), language.name());
                Ok(vec![SourceFile {
                    path: path.to_path_buf(),
                    language,
                }])
            }
            Err(e) => {
                warn!("Skipping unsupported file: {} ({})", path.display(), e);
                Ok(vec![])
            }
        }
    }

    fn discover_directory(&self, path: &Path) -> Result<Vec<SourceFile>> {
        info!("Scanning directory: {}", path.display());

        let mut builder = WalkBuilder::new(path);
        builder
            .follow_links(self.config.follow_links)
            .git_ignore(self.config.respect_gitignore)
            .git_exclude(self.config.respect_gitignore);

        let mut files = Vec::new();
        let mut skipped = 0;
        let mut unsupported = 0;

        for result in builder.build() {
            match result {
                Ok(entry) => {
                    let path = entry.path();

                    // Skip directories
                    if !path.is_file() {
                        continue;
                    }

                    // Check exclusion patterns
                    if self.should_exclude(path) {
                        skipped += 1;
                        continue;
                    }

                    // Check file size
                    if let Some(max_size) = self.config.max_file_size {
                        if let Ok(metadata) = entry.metadata() {
                            if metadata.len() > max_size as u64 {
                                debug!("Skipping file (too large): {}", path.display());
                                skipped += 1;
                                continue;
                            }
                        }
                    }

                    // Try to detect language
                    match Language::from_path(path) {
                        Ok(language) => {
                            debug!("Discovered: {} ({})", path.display(), language.name());
                            files.push(SourceFile {
                                path: path.to_path_buf(),
                                language,
                            });
                        }
                        Err(_) => {
                            unsupported += 1;
                            debug!("Unsupported file type: {}", path.display());
                        }
                    }
                }
                Err(e) => {
                    warn!("Error walking directory: {}", e);
                }
            }
        }

        info!(
            "Discovery complete: {} files found, {} skipped, {} unsupported",
            files.len(),
            skipped,
            unsupported
        );

        Ok(files)
    }

    fn should_exclude(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();

        for pattern in &self.config.exclude_patterns {
            if glob::Pattern::new(pattern)
                .ok()
                .and_then(|p| Some(p.matches(&path_str)))
                .unwrap_or(false)
            {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_discover_single_file() {
        let discovery = FileDiscovery::with_default_config();
        let files = discovery.discover(Path::new("test_clean.ts")).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].language, Language::TypeScript);
    }

    #[test]
    fn test_discover_directory() {
        // Create a temp directory with some test files
        let temp_dir = std::env::temp_dir().join("kodecd_test_discovery");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        // Create some test files
        fs::write(temp_dir.join("test1.ts"), "const x = 1;").unwrap();
        fs::write(temp_dir.join("test2.js"), "const y = 2;").unwrap();
        fs::write(temp_dir.join("test3.py"), "x = 3").unwrap();
        fs::write(temp_dir.join("readme.txt"), "not a source file").unwrap();

        let discovery = FileDiscovery::with_default_config();
        let files = discovery.discover(&temp_dir).unwrap();

        // Should find 3 source files (ts, js, py), skip txt
        assert_eq!(files.len(), 3);

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
