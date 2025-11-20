//! Finding lifecycle tracking across scans
//!
//! Track how findings evolve over time:
//! - New findings introduced
//! - Existing findings that persist
//! - Fixed findings that were resolved
//! - Reopened findings that reappeared after being fixed

use crate::fingerprint::FindingFingerprint;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
pub enum LifecycleError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Invalid lifecycle data")]
    InvalidData,
}

/// State of a finding in its lifecycle
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingState {
    /// Newly discovered finding
    New,

    /// Finding exists from previous scan
    Existing,

    /// Finding was fixed (no longer appears)
    Fixed,

    /// Finding was fixed but reappeared
    Reopened,
}

impl FindingState {
    pub fn as_str(&self) -> &str {
        match self {
            Self::New => "new",
            Self::Existing => "existing",
            Self::Fixed => "fixed",
            Self::Reopened => "reopened",
        }
    }
}

/// Lifecycle information for a single finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingLifecycle {
    /// Fingerprint for stable identification
    pub fingerprint: String,

    /// Current state
    pub state: FindingState,

    /// Rule ID
    pub rule_id: String,

    /// File path
    pub file_path: String,

    /// Line number
    pub line: usize,

    /// Severity
    pub severity: String,

    /// Timestamp when first detected
    pub first_seen: u64,

    /// Timestamp when last seen
    pub last_seen: u64,

    /// Timestamp when fixed (if applicable)
    pub fixed_at: Option<u64>,

    /// Number of scans this finding appeared in
    pub occurrence_count: usize,
}

impl FindingLifecycle {
    /// Create new lifecycle entry from finding
    pub fn new(finding: &kodecd_query::Finding) -> Self {
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
            state: FindingState::New,
            rule_id: finding.rule_id.clone(),
            file_path: finding.file_path.clone(),
            line: finding.line,
            severity: finding.severity.clone(),
            first_seen: now,
            last_seen: now,
            fixed_at: None,
            occurrence_count: 1,
        }
    }

    /// Update lifecycle when finding appears in scan
    pub fn mark_seen(&mut self) {
        let now = current_timestamp();

        // If previously fixed, mark as reopened
        if self.state == FindingState::Fixed {
            self.state = FindingState::Reopened;
            debug!("Finding reopened: {} at {}:{}", self.rule_id, self.file_path, self.line);
        } else if self.state == FindingState::New {
            self.state = FindingState::Existing;
        }

        self.last_seen = now;
        self.occurrence_count += 1;
        self.fixed_at = None;
    }

    /// Mark finding as fixed
    pub fn mark_fixed(&mut self) {
        let now = current_timestamp();

        self.state = FindingState::Fixed;
        self.fixed_at = Some(now);
        debug!("Finding fixed: {} at {}:{}", self.rule_id, self.file_path, self.line);
    }

    /// Get age in seconds (time since first seen)
    pub fn age(&self) -> u64 {
        let now = current_timestamp();

        now - self.first_seen
    }

    /// Get time since last seen in seconds
    pub fn time_since_last_seen(&self) -> u64 {
        let now = current_timestamp();

        now - self.last_seen
    }
}

/// Configuration for lifecycle tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleConfig {
    /// Path to lifecycle database (default: .kodecd/lifecycle.json)
    pub lifecycle_file: PathBuf,

    /// Enable lifecycle tracking
    pub enabled: bool,

    /// Purge fixed findings after N days
    pub purge_fixed_after_days: Option<u64>,
}

impl Default for LifecycleConfig {
    fn default() -> Self {
        Self {
            lifecycle_file: PathBuf::from(".kodecd/lifecycle.json"),
            enabled: true,
            purge_fixed_after_days: Some(90), // 90 days
        }
    }
}

/// Lifecycle tracker for all findings
pub struct LifecycleTracker {
    config: LifecycleConfig,
    lifecycles: HashMap<String, FindingLifecycle>,
}

impl LifecycleTracker {
    /// Create new lifecycle tracker
    pub fn new(config: LifecycleConfig) -> Result<Self, LifecycleError> {
        let mut tracker = Self {
            config,
            lifecycles: HashMap::new(),
        };

        // Load existing lifecycle data
        if tracker.config.enabled && tracker.config.lifecycle_file.exists() {
            tracker.load()?;
        }

        Ok(tracker)
    }

    /// Load lifecycle data from file
    fn load(&mut self) -> Result<(), LifecycleError> {
        let content = std::fs::read_to_string(&self.config.lifecycle_file)?;
        self.lifecycles = serde_json::from_str(&content)?;

        info!(
            "Loaded lifecycle data for {} findings from {}",
            self.lifecycles.len(),
            self.config.lifecycle_file.display()
        );

        Ok(())
    }

    /// Save lifecycle data to file
    pub fn save(&self) -> Result<(), LifecycleError> {
        if !self.config.enabled {
            return Ok(());
        }

        // Ensure directory exists
        if let Some(parent) = self.config.lifecycle_file.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string_pretty(&self.lifecycles)?;
        std::fs::write(&self.config.lifecycle_file, json)?;

        info!(
            "Saved lifecycle data for {} findings to {}",
            self.lifecycles.len(),
            self.config.lifecycle_file.display()
        );

        Ok(())
    }

    /// Update lifecycle tracking with new scan results
    pub fn update(&mut self, current_findings: &[kodecd_query::Finding]) {
        if !self.config.enabled {
            return;
        }

        let _now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Track which fingerprints we see in this scan
        let mut seen_fps = std::collections::HashSet::new();

        // Process current findings
        for finding in current_findings {
            let fingerprint = FindingFingerprint::new(
                &finding.rule_id,
                &finding.file_path,
                finding.line,
                finding.column,
                &finding.code_snippet,
            );

            seen_fps.insert(fingerprint.id.clone());

            // Update or create lifecycle entry
            self.lifecycles
                .entry(fingerprint.id.clone())
                .and_modify(|lifecycle| lifecycle.mark_seen())
                .or_insert_with(|| FindingLifecycle::new(finding));
        }

        // Mark unseen findings as fixed
        for (fp, lifecycle) in self.lifecycles.iter_mut() {
            if !seen_fps.contains(fp) && lifecycle.state != FindingState::Fixed {
                lifecycle.mark_fixed();
            }
        }

        // Purge old fixed findings if configured
        if let Some(purge_days) = self.config.purge_fixed_after_days {
            let purge_threshold = purge_days * 24 * 60 * 60; // Convert to seconds
            self.lifecycles.retain(|_, lifecycle| {
                if lifecycle.state == FindingState::Fixed {
                    lifecycle.time_since_last_seen() < purge_threshold
                } else {
                    true
                }
            });
        }

        debug!("Updated lifecycle tracking for {} findings", current_findings.len());
    }

    /// Get lifecycle for a finding
    pub fn get(&self, finding: &kodecd_query::Finding) -> Option<&FindingLifecycle> {
        let fingerprint = FindingFingerprint::new(
            &finding.rule_id,
            &finding.file_path,
            finding.line,
            finding.column,
            &finding.code_snippet,
        );

        self.lifecycles.get(&fingerprint.id)
    }

    /// Get all lifecycles by state
    pub fn get_by_state(&self, state: FindingState) -> Vec<&FindingLifecycle> {
        self.lifecycles
            .values()
            .filter(|l| l.state == state)
            .collect()
    }

    /// Get lifecycle statistics
    pub fn stats(&self) -> LifecycleStats {
        let mut stats = LifecycleStats {
            total: self.lifecycles.len(),
            new: 0,
            existing: 0,
            fixed: 0,
            reopened: 0,
            by_severity: HashMap::new(),
        };

        for lifecycle in self.lifecycles.values() {
            match lifecycle.state {
                FindingState::New => stats.new += 1,
                FindingState::Existing => stats.existing += 1,
                FindingState::Fixed => stats.fixed += 1,
                FindingState::Reopened => stats.reopened += 1,
            }

            if lifecycle.state != FindingState::Fixed {
                *stats.by_severity.entry(lifecycle.severity.clone()).or_insert(0) += 1;
            }
        }

        stats
    }

    /// Get findings by age (oldest first)
    pub fn get_oldest(&self, limit: usize) -> Vec<&FindingLifecycle> {
        let mut lifecycles: Vec<&FindingLifecycle> = self
            .lifecycles
            .values()
            .filter(|l| l.state != FindingState::Fixed)
            .collect();

        lifecycles.sort_by_key(|l| l.first_seen);
        lifecycles.into_iter().take(limit).collect()
    }

    /// Clear all lifecycle data
    pub fn clear(&mut self) -> Result<(), LifecycleError> {
        self.lifecycles.clear();

        if self.config.lifecycle_file.exists() {
            std::fs::remove_file(&self.config.lifecycle_file)?;
            info!("Cleared lifecycle data");
        }

        Ok(())
    }

    /// Get total count
    pub fn count(&self) -> usize {
        self.lifecycles.len()
    }
}

/// Lifecycle statistics
#[derive(Debug, Clone)]
pub struct LifecycleStats {
    pub total: usize,
    pub new: usize,
    pub existing: usize,
    pub fixed: usize,
    pub reopened: usize,
    pub by_severity: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use kodecd_query::Finding;

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
        }
    }

    #[test]
    fn test_lifecycle_new_finding() {
        let finding = create_test_finding("sql-injection", "app.js", 42);
        let lifecycle = FindingLifecycle::new(&finding);

        assert_eq!(lifecycle.state, FindingState::New);
        assert_eq!(lifecycle.occurrence_count, 1);
        assert_eq!(lifecycle.fixed_at, None);
    }

    #[test]
    fn test_lifecycle_transitions() {
        let finding = create_test_finding("sql-injection", "app.js", 42);
        let mut lifecycle = FindingLifecycle::new(&finding);

        // New -> Existing
        lifecycle.mark_seen();
        assert_eq!(lifecycle.state, FindingState::Existing);
        assert_eq!(lifecycle.occurrence_count, 2);

        // Existing -> Fixed
        lifecycle.mark_fixed();
        assert_eq!(lifecycle.state, FindingState::Fixed);
        assert!(lifecycle.fixed_at.is_some());

        // Fixed -> Reopened
        lifecycle.mark_seen();
        assert_eq!(lifecycle.state, FindingState::Reopened);
        assert_eq!(lifecycle.fixed_at, None);
    }

    #[test]
    fn test_tracker_update() {
        let config = LifecycleConfig {
            lifecycle_file: PathBuf::from("/tmp/test_lifecycle.json"),
            enabled: true,
            purge_fixed_after_days: None,
        };

        let mut tracker = LifecycleTracker::new(config).unwrap();

        // First scan - 2 findings
        let scan1 = vec![
            create_test_finding("sql-injection", "app.js", 42),
            create_test_finding("xss", "app.js", 100),
        ];
        tracker.update(&scan1);

        let stats1 = tracker.stats();
        assert_eq!(stats1.new, 2);
        assert_eq!(stats1.existing, 0);

        // Second scan - same findings
        tracker.update(&scan1);

        let stats2 = tracker.stats();
        assert_eq!(stats2.new, 0);
        assert_eq!(stats2.existing, 2);

        // Third scan - one finding fixed, one new
        let scan2 = vec![
            create_test_finding("sql-injection", "app.js", 42), // Still exists
            create_test_finding("path-traversal", "app.js", 200), // New
        ];
        tracker.update(&scan2);

        let stats3 = tracker.stats();
        assert_eq!(stats3.existing, 1); // sql-injection
        assert_eq!(stats3.new, 1);      // path-traversal
        assert_eq!(stats3.fixed, 1);    // xss
    }

    #[test]
    fn test_get_by_state() {
        let config = LifecycleConfig::default();
        let mut tracker = LifecycleTracker::new(config).unwrap();

        let findings = vec![
            create_test_finding("sql-injection", "app.js", 42),
            create_test_finding("xss", "app.js", 100),
        ];
        tracker.update(&findings);

        let new_findings = tracker.get_by_state(FindingState::New);
        assert_eq!(new_findings.len(), 2);

        // Second scan
        tracker.update(&findings);

        let existing_findings = tracker.get_by_state(FindingState::Existing);
        assert_eq!(existing_findings.len(), 2);
    }

    #[test]
    fn test_reopened_finding() {
        let config = LifecycleConfig::default();
        let mut tracker = LifecycleTracker::new(config).unwrap();

        let finding = create_test_finding("sql-injection", "app.js", 42);

        // First scan
        tracker.update(&[finding.clone()]);

        // Second scan - finding gone (fixed)
        tracker.update(&[]);

        let stats = tracker.stats();
        assert_eq!(stats.fixed, 1);

        // Third scan - finding reappears (reopened)
        tracker.update(&[finding]);

        let stats = tracker.stats();
        assert_eq!(stats.reopened, 1);
        assert_eq!(stats.fixed, 0);
    }
}
