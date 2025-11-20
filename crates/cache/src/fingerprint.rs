//! Fingerprinting for files and findings
//!
//! Provides stable identifiers for:
//! - Files (content-based hashing)
//! - Findings (location + rule ID hashing)

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// File fingerprint based on content hash
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileFingerprint {
    /// SHA-256 hash of file content
    pub content_hash: String,
    /// File size in bytes
    pub size: u64,
    /// Last modified timestamp (Unix epoch)
    pub modified: u64,
}

impl FileFingerprint {
    /// Generate fingerprint from file path
    pub fn from_file(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read(path)?;
        let metadata = std::fs::metadata(path)?;

        Ok(Self::from_content(&content, metadata.len(), Self::get_modified(&metadata)?))
    }

    /// Generate fingerprint from content
    pub fn from_content(content: &[u8], size: u64, modified: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(content);
        let content_hash = format!("{:x}", hasher.finalize());

        Self {
            content_hash,
            size,
            modified,
        }
    }

    /// Check if file has changed by comparing fingerprints
    pub fn has_changed(&self, other: &FileFingerprint) -> bool {
        self.content_hash != other.content_hash
    }

    /// Get file modified time from metadata
    fn get_modified(metadata: &std::fs::Metadata) -> std::io::Result<u64> {
        Ok(metadata
            .modified()?
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs())
    }
}

/// Finding fingerprint for tracking across scans
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FindingFingerprint {
    /// Unique identifier for this finding
    pub id: String,
}

impl FindingFingerprint {
    /// Generate fingerprint from finding attributes
    ///
    /// Uses a combination of:
    /// - Rule ID
    /// - File path
    /// - Line number
    /// - Column number (optional)
    /// - Code snippet hash (for robustness)
    pub fn new(
        rule_id: &str,
        file_path: &str,
        line: usize,
        column: usize,
        code_snippet: &str,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(rule_id.as_bytes());
        hasher.update(file_path.as_bytes());
        hasher.update(line.to_string().as_bytes());
        hasher.update(column.to_string().as_bytes());
        hasher.update(code_snippet.as_bytes());

        let id = format!("{:x}", hasher.finalize());

        Self { id }
    }

    /// Generate simple fingerprint without code snippet (less robust but faster)
    pub fn simple(rule_id: &str, file_path: &str, line: usize) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(rule_id.as_bytes());
        hasher.update(file_path.as_bytes());
        hasher.update(line.to_string().as_bytes());

        let id = format!("{:x}", hasher.finalize());

        Self { id }
    }

    /// Convert to short ID for display (first 12 characters)
    pub fn short_id(&self) -> String {
        self.id.chars().take(12).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_fingerprint_stability() {
        let content = b"console.log('hello');";
        let fp1 = FileFingerprint::from_content(content, content.len() as u64, 1000);
        let fp2 = FileFingerprint::from_content(content, content.len() as u64, 1000);

        assert_eq!(fp1, fp2);
        assert!(!fp1.has_changed(&fp2));
    }

    #[test]
    fn test_file_fingerprint_change_detection() {
        let content1 = b"console.log('hello');";
        let content2 = b"console.log('world');";

        let fp1 = FileFingerprint::from_content(content1, content1.len() as u64, 1000);
        let fp2 = FileFingerprint::from_content(content2, content2.len() as u64, 1000);

        assert!(fp1.has_changed(&fp2));
    }

    #[test]
    fn test_finding_fingerprint_stability() {
        let fp1 = FindingFingerprint::new(
            "sql-injection",
            "app.js",
            42,
            10,
            "db.query(userInput)",
        );

        let fp2 = FindingFingerprint::new(
            "sql-injection",
            "app.js",
            42,
            10,
            "db.query(userInput)",
        );

        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_finding_fingerprint_uniqueness() {
        let fp1 = FindingFingerprint::new(
            "sql-injection",
            "app.js",
            42,
            10,
            "db.query(userInput)",
        );

        let fp2 = FindingFingerprint::new(
            "sql-injection",
            "app.js",
            43, // Different line
            10,
            "db.query(userInput)",
        );

        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_short_id() {
        let fp = FindingFingerprint::new(
            "sql-injection",
            "app.js",
            42,
            10,
            "db.query(userInput)",
        );

        let short = fp.short_id();
        assert_eq!(short.len(), 12);
        assert!(fp.id.starts_with(&short));
    }
}
