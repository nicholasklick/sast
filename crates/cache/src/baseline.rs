//! Baseline mode for suppressing existing findings
//!
//! Baseline mode allows you to:
//! - Capture current state of all findings
//! - Suppress all baseline findings in future scans
//! - Only report new findings introduced after baseline
//! - Track when findings are fixed (removed from baseline)

use crate::fingerprint::FindingFingerprint;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use thiserror::Error;
use tracing::{debug, info};

/// Helper function to get current timestamp, returns 0 on error to avoid panics
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Error, Debug)]
pub enum BaselineError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Baseline not found: {0}")]
    BaselineNotFound(PathBuf),

    #[error("Invalid baseline format")]
    InvalidFormat,
}

/// Baseline configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineConfig {
    /// Path to baseline file (default: .gittera/baseline.json)
    pub baseline_file: PathBuf,

    /// Enable baseline mode
    pub enabled: bool,

    /// Track fixed findings (findings in baseline but not in current scan)
    pub track_fixed: bool,
}

impl Default for BaselineConfig {
    fn default() -> Self {
        Self {
            baseline_file: PathBuf::from(".gittera/baseline.json"),
            enabled: false,
            track_fixed: true,
        }
    }
}

/// A finding captured in the baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineFinding {
    /// Fingerprint for stable identification
    pub fingerprint: String,

    /// Rule ID
    pub rule_id: String,

    /// File path
    pub file_path: String,

    /// Line number
    pub line: usize,

    /// Column number
    pub column: usize,

    /// Code snippet
    pub snippet: String,

    /// Severity
    pub severity: String,

    /// Category
    pub category: String,

    /// Timestamp when added to baseline
    pub baseline_timestamp: u64,
}

impl BaselineFinding {
    /// Create from finding
    pub fn from_finding(finding: &gittera_query::Finding) -> Self {
        let fingerprint = FindingFingerprint::new(
            &finding.rule_id,
            &finding.file_path,
            finding.line,
            finding.column,
            &finding.code_snippet,
        );

        let now = current_timestamp();

        Self {
            fingerprint: fingerprint.id,
            rule_id: finding.rule_id.clone(),
            file_path: finding.file_path.clone(),
            line: finding.line,
            column: finding.column,
            snippet: finding.code_snippet.clone(),
            severity: finding.severity.clone(),
            category: finding.category.clone(),
            baseline_timestamp: now,
        }
    }
}

/// Baseline snapshot of findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    /// Baseline creation timestamp
    pub created_at: u64,

    /// Baseline description/comment
    pub description: Option<String>,

    /// All findings in baseline (keyed by fingerprint)
    pub findings: HashMap<String, BaselineFinding>,

    /// Version of the tool that created baseline
    pub tool_version: String,
}

impl Baseline {
    /// Create new baseline from findings
    pub fn new(findings: &[gittera_query::Finding], description: Option<String>) -> Self {
        let now = current_timestamp();

        let mut baseline_findings = HashMap::new();
        for finding in findings {
            let baseline_finding = BaselineFinding::from_finding(finding);
            baseline_findings.insert(baseline_finding.fingerprint.clone(), baseline_finding);
        }

        Self {
            created_at: now,
            description,
            findings: baseline_findings,
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Check if finding exists in baseline
    pub fn contains(&self, finding: &gittera_query::Finding) -> bool {
        let fingerprint = FindingFingerprint::new(
            &finding.rule_id,
            &finding.file_path,
            finding.line,
            finding.column,
            &finding.code_snippet,
        );

        self.findings.contains_key(&fingerprint.id)
    }

    /// Get baseline finding by fingerprint
    pub fn get(&self, fingerprint: &str) -> Option<&BaselineFinding> {
        self.findings.get(fingerprint)
    }

    /// Get number of findings in baseline
    pub fn count(&self) -> usize {
        self.findings.len()
    }

    /// Get statistics by severity
    pub fn stats_by_severity(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        for finding in self.findings.values() {
            *stats.entry(finding.severity.clone()).or_insert(0) += 1;
        }
        stats
    }

    /// Get statistics by category
    pub fn stats_by_category(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        for finding in self.findings.values() {
            *stats.entry(finding.category.clone()).or_insert(0) += 1;
        }
        stats
    }
}

/// Baseline manager
pub struct BaselineManager {
    config: BaselineConfig,
    baseline: Option<Baseline>,
}

impl BaselineManager {
    /// Create new baseline manager
    pub fn new(config: BaselineConfig) -> Result<Self, BaselineError> {
        let mut manager = Self {
            config,
            baseline: None,
        };

        // Load baseline if it exists and enabled
        if manager.config.enabled {
            if manager.config.baseline_file.exists() {
                manager.load()?;
            } else {
                debug!("Baseline file not found: {}", manager.config.baseline_file.display());
            }
        }

        Ok(manager)
    }

    /// Create new baseline from findings
    pub fn create_baseline(
        &mut self,
        findings: &[gittera_query::Finding],
        description: Option<String>,
    ) -> Result<(), BaselineError> {
        let baseline = Baseline::new(findings, description);
        info!("Created baseline with {} findings", baseline.count());

        self.baseline = Some(baseline);
        self.save()?;

        Ok(())
    }

    /// Load baseline from file
    pub fn load(&mut self) -> Result<(), BaselineError> {
        if !self.config.baseline_file.exists() {
            return Err(BaselineError::BaselineNotFound(
                self.config.baseline_file.clone(),
            ));
        }

        let content = std::fs::read_to_string(&self.config.baseline_file)?;
        let baseline: Baseline = serde_json::from_str(&content)?;

        info!(
            "Loaded baseline with {} findings from {}",
            baseline.count(),
            self.config.baseline_file.display()
        );

        self.baseline = Some(baseline);
        Ok(())
    }

    /// Save baseline to file
    pub fn save(&self) -> Result<(), BaselineError> {
        let baseline = self
            .baseline
            .as_ref()
            .ok_or(BaselineError::InvalidFormat)?;

        // Ensure directory exists
        if let Some(parent) = self.config.baseline_file.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string_pretty(baseline)?;
        std::fs::write(&self.config.baseline_file, json)?;

        info!(
            "Saved baseline to {}",
            self.config.baseline_file.display()
        );

        Ok(())
    }

    /// Check if finding is in baseline
    pub fn is_baseline(&self, finding: &gittera_query::Finding) -> bool {
        if !self.config.enabled {
            return false;
        }

        match &self.baseline {
            Some(baseline) => baseline.contains(finding),
            None => false,
        }
    }

    /// Filter findings to only new ones (not in baseline)
    pub fn filter_new_findings<'a>(
        &self,
        findings: &'a [gittera_query::Finding],
    ) -> Vec<&'a gittera_query::Finding> {
        if !self.config.enabled || self.baseline.is_none() {
            return findings.iter().collect();
        }

        findings
            .iter()
            .filter(|f| !self.is_baseline(f))
            .collect()
    }

    /// Find fixed findings (in baseline but not in current findings)
    pub fn find_fixed_findings(
        &self,
        current_findings: &[gittera_query::Finding],
    ) -> Vec<BaselineFinding> {
        if !self.config.enabled || !self.config.track_fixed {
            return Vec::new();
        }

        let baseline = match &self.baseline {
            Some(b) => b,
            None => return Vec::new(),
        };

        // Create set of current finding fingerprints
        let current_fps: HashSet<String> = current_findings
            .iter()
            .map(|f| {
                FindingFingerprint::new(
                    &f.rule_id,
                    &f.file_path,
                    f.line,
                    f.column,
                    &f.code_snippet,
                )
                .id
            })
            .collect();

        // Find baseline findings not in current set
        baseline
            .findings
            .iter()
            .filter(|(fp, _)| !current_fps.contains(*fp))
            .map(|(_, finding)| finding.clone())
            .collect()
    }

    /// Get baseline statistics
    pub fn stats(&self) -> Option<BaselineStats> {
        self.baseline.as_ref().map(|b| BaselineStats {
            total_findings: b.count(),
            created_at: b.created_at,
            by_severity: b.stats_by_severity(),
            by_category: b.stats_by_category(),
        })
    }

    /// Clear baseline
    pub fn clear(&mut self) -> Result<(), BaselineError> {
        self.baseline = None;

        if self.config.baseline_file.exists() {
            std::fs::remove_file(&self.config.baseline_file)?;
            info!("Cleared baseline");
        }

        Ok(())
    }

    /// Get baseline reference
    pub fn get_baseline(&self) -> Option<&Baseline> {
        self.baseline.as_ref()
    }
}

/// Baseline statistics
#[derive(Debug, Clone)]
pub struct BaselineStats {
    pub total_findings: usize,
    pub created_at: u64,
    pub by_severity: HashMap<String, usize>,
    pub by_category: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use gittera_query::Finding;

    fn create_test_finding(rule_id: &str, file: &str, line: usize) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            severity: "High".to_string(),
            category: "injection".to_string(),
            message: "Test finding".to_string(),
            file_path: file.to_string(),
            line,
            column: 10,
            code_snippet: format!("code at line {}", line),
            cwes: vec![],
            owasp: None,
        }
    }

    #[test]
    fn test_baseline_creation() {
        let findings = vec![
            create_test_finding("sql-injection", "app.js", 42),
            create_test_finding("xss", "app.js", 100),
        ];

        let baseline = Baseline::new(&findings, Some("Initial baseline".to_string()));

        assert_eq!(baseline.count(), 2);
        assert_eq!(baseline.description, Some("Initial baseline".to_string()));
    }

    #[test]
    fn test_baseline_contains() {
        let finding1 = create_test_finding("sql-injection", "app.js", 42);
        let finding2 = create_test_finding("xss", "app.js", 100);
        let finding3 = create_test_finding("sql-injection", "app.js", 50);

        let baseline = Baseline::new(&[finding1.clone(), finding2.clone()], None);

        assert!(baseline.contains(&finding1));
        assert!(baseline.contains(&finding2));
        assert!(!baseline.contains(&finding3));
    }

    #[test]
    fn test_filter_new_findings() {
        let baseline_findings = vec![
            create_test_finding("sql-injection", "app.js", 42),
            create_test_finding("xss", "app.js", 100),
        ];

        let mut config = BaselineConfig::default();
        config.enabled = true;

        let mut manager = BaselineManager::new(config).unwrap();
        manager
            .create_baseline(&baseline_findings, None)
            .unwrap();

        let current_findings = vec![
            create_test_finding("sql-injection", "app.js", 42), // In baseline
            create_test_finding("xss", "app.js", 100),          // In baseline
            create_test_finding("path-traversal", "app.js", 200), // New
        ];

        let new_findings = manager.filter_new_findings(&current_findings);

        assert_eq!(new_findings.len(), 1);
        assert_eq!(new_findings[0].rule_id, "path-traversal");
    }

    #[test]
    fn test_find_fixed_findings() {
        let baseline_findings = vec![
            create_test_finding("sql-injection", "app.js", 42),
            create_test_finding("xss", "app.js", 100),
            create_test_finding("path-traversal", "app.js", 200),
        ];

        let mut config = BaselineConfig::default();
        config.enabled = true;
        config.track_fixed = true;

        let mut manager = BaselineManager::new(config).unwrap();
        manager
            .create_baseline(&baseline_findings, None)
            .unwrap();

        // Current findings - xss was fixed
        let current_findings = vec![
            create_test_finding("sql-injection", "app.js", 42),
            create_test_finding("path-traversal", "app.js", 200),
        ];

        let fixed = manager.find_fixed_findings(&current_findings);

        assert_eq!(fixed.len(), 1);
        assert_eq!(fixed[0].rule_id, "xss");
    }

    #[test]
    fn test_baseline_stats() {
        let findings = vec![
            create_test_finding("sql-injection", "app.js", 42),
            create_test_finding("xss", "app.js", 100),
        ];

        let baseline = Baseline::new(&findings, None);
        let by_severity = baseline.stats_by_severity();

        assert_eq!(by_severity.get("High"), Some(&2));
    }
}
