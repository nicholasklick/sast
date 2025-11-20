//! Caching and Incremental Analysis for KodeCD SAST
//!
//! This crate provides:
//! - **File Change Detection**: Track which files have changed since last scan
//! - **Result Caching**: Store and retrieve previous scan results
//! - **Differential Scanning**: Only scan changed files
//! - **False Positive Suppression**: Baseline mode and inline suppressions
//! - **Finding Lifecycle Tracking**: Track findings across scans
//!
//! ## Incremental Analysis
//!
//! ```rust,no_run
//! use kodecd_cache::{Cache, CacheConfig};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create cache in .kodecd directory
//! let config = CacheConfig::default();
//! let mut cache = Cache::new(config)?;
//!
//! // Check which files changed
//! let changed_files = cache.get_changed_files("src")?;
//! println!("Changed files: {}", changed_files.len());
//!
//! // Scan only changed files
//! // ... run analysis ...
//! // let findings = scan_files(&changed_files)?;
//!
//! // Store results for next run
//! // cache.store_results("src/app.js", &findings)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## False Positive Suppression
//!
//! ```rust,no_run
//! use kodecd_cache::{SuppressionManager, SuppressionConfig};
//! use std::path::Path;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = SuppressionConfig::default();
//! let mut suppressions = SuppressionManager::new(config)?;
//!
//! // Load suppressions from .kodecd-ignore
//! suppressions.load()?;
//!
//! // Check if finding is suppressed
//! let is_suppressed = suppressions.is_suppressed(
//!     Path::new("app.js"),
//!     42,
//!     "sql-injection"
//! );
//! # Ok(())
//! # }
//! ```

pub mod cache;
pub mod fingerprint;
pub mod suppression;
pub mod baseline;
pub mod lifecycle;

pub use cache::{Cache, CacheConfig, CacheError, FileMetadata, ScanResults};
pub use fingerprint::{FileFingerprint, FindingFingerprint};
pub use suppression::{
    Suppression, SuppressionConfig, SuppressionError, SuppressionManager, SuppressionReason,
    SuppressionScope,
};
pub use baseline::{Baseline, BaselineConfig, BaselineManager};
pub use lifecycle::{FindingLifecycle, FindingState, LifecycleTracker};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Cache error: {0}")]
    Cache(#[from] CacheError),

    #[error("Suppression error: {0}")]
    Suppression(#[from] SuppressionError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

pub type Result<T> = std::result::Result<T, Error>;
