//! False positive suppression system
//!
//! Supports:
//! - Inline suppressions (// kodecd-ignore)
//! - File-based suppressions (.kodecd-ignore)
//! - Baseline mode (suppress all existing findings)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{debug, info};

#[derive(Error, Debug)]
pub enum SuppressionError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Invalid suppression format: {0}")]
    InvalidFormat(String),
}

/// Suppression configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionConfig {
    /// Path to suppression file (default: .kodecd-ignore)
    pub suppression_file: PathBuf,

    /// Enable inline suppressions
    pub enable_inline: bool,

    /// Enable file-based suppressions
    pub enable_file: bool,

    /// Enable baseline mode
    pub enable_baseline: bool,
}

impl Default for SuppressionConfig {
    fn default() -> Self {
        Self {
            suppression_file: PathBuf::from(".kodecd-ignore"),
            enable_inline: true,
            enable_file: true,
            enable_baseline: false,
        }
    }
}

/// Reason for suppression
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SuppressionReason {
    /// False positive
    FalsePositive,
    /// Accepted risk
    AcceptedRisk,
    /// Not applicable
    NotApplicable,
    /// Baseline (pre-existing finding)
    Baseline,
    /// Custom reason
    Custom(String),
}

impl SuppressionReason {
    pub fn as_str(&self) -> &str {
        match self {
            Self::FalsePositive => "false-positive",
            Self::AcceptedRisk => "accepted-risk",
            Self::NotApplicable => "not-applicable",
            Self::Baseline => "baseline",
            Self::Custom(s) => s,
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "false-positive" | "fp" => Self::FalsePositive,
            "accepted-risk" | "risk" => Self::AcceptedRisk,
            "not-applicable" | "na" => Self::NotApplicable,
            "baseline" => Self::Baseline,
            _ => Self::Custom(s.to_string()),
        }
    }
}

/// Scope of suppression
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SuppressionScope {
    /// Suppress on specific line
    Line { file: PathBuf, line: usize },

    /// Suppress specific rule in file
    FileRule { file: PathBuf, rule_id: String },

    /// Suppress all instances of a rule
    Rule { rule_id: String },

    /// Suppress entire file
    File { file: PathBuf },
}

/// A single suppression entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suppression {
    /// Suppression scope
    pub scope: SuppressionScope,

    /// Reason for suppression
    pub reason: SuppressionReason,

    /// Optional comment/explanation
    pub comment: Option<String>,

    /// Timestamp when suppression was added
    pub added_at: u64,

    /// Expiration timestamp (optional)
    pub expires_at: Option<u64>,
}

impl Suppression {
    /// Create new suppression
    pub fn new(scope: SuppressionScope, reason: SuppressionReason) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            scope,
            reason,
            comment: None,
            added_at: now,
            expires_at: None,
        }
    }

    /// Add comment/explanation
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Set expiration time (Unix timestamp)
    pub fn with_expiration(mut self, expires_at: u64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Check if suppression has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            now > expires_at
        } else {
            false
        }
    }

    /// Check if this suppression applies to a finding
    pub fn matches(&self, file: &Path, line: usize, rule_id: &str) -> bool {
        if self.is_expired() {
            return false;
        }

        match &self.scope {
            SuppressionScope::Line { file: f, line: l } => {
                f == file && *l == line
            }
            SuppressionScope::FileRule { file: f, rule_id: r } => {
                f == file && r == rule_id
            }
            SuppressionScope::Rule { rule_id: r } => {
                r == rule_id
            }
            SuppressionScope::File { file: f } => {
                f == file
            }
        }
    }
}

/// Suppression manager
pub struct SuppressionManager {
    config: SuppressionConfig,
    suppressions: Vec<Suppression>,
    inline_cache: HashMap<PathBuf, Vec<usize>>, // File -> suppressed lines
}

impl SuppressionManager {
    /// Create new suppression manager
    pub fn new(config: SuppressionConfig) -> Result<Self, SuppressionError> {
        let mut manager = Self {
            config,
            suppressions: Vec::new(),
            inline_cache: HashMap::new(),
        };

        // Load suppressions from file if it exists
        manager.load()?;

        Ok(manager)
    }

    /// Load suppressions from file
    pub fn load(&mut self) -> Result<(), SuppressionError> {
        if !self.config.enable_file {
            return Ok(());
        }

        if !self.config.suppression_file.exists() {
            debug!("Suppression file not found: {}", self.config.suppression_file.display());
            return Ok(());
        }

        let content = std::fs::read_to_string(&self.config.suppression_file)?;
        let loaded = self.parse_suppression_file(&content)?;

        info!("Loaded {} suppressions from {}",
              loaded,
              self.config.suppression_file.display());

        Ok(())
    }

    /// Parse suppression file
    fn parse_suppression_file(&mut self, content: &str) -> Result<usize, SuppressionError> {
        let mut count = 0;

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse suppression line
            // Format: <scope> [reason] [comment]
            // Examples:
            //   app.js:42                          # Suppress line 42
            //   app.js:sql-injection               # Suppress rule in file
            //   sql-injection                       # Suppress rule globally
            //   app.js                              # Suppress entire file

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            let scope_str = parts[0];
            let reason = if parts.len() > 1 {
                SuppressionReason::from_str(parts[1])
            } else {
                SuppressionReason::FalsePositive
            };

            let comment = if parts.len() > 2 {
                Some(parts[2..].join(" "))
            } else {
                None
            };

            // Parse scope
            let scope = if scope_str.contains(':') {
                let parts: Vec<&str> = scope_str.splitn(2, ':').collect();
                let file = PathBuf::from(parts[0]);
                let second_part = parts[1];

                // Check if second part is a number (line) or rule ID
                if let Ok(line) = second_part.parse::<usize>() {
                    SuppressionScope::Line { file, line }
                } else {
                    SuppressionScope::FileRule {
                        file,
                        rule_id: second_part.to_string()
                    }
                }
            } else if scope_str.contains('/') || scope_str.contains('.') {
                // Looks like a file path
                SuppressionScope::File { file: PathBuf::from(scope_str) }
            } else {
                // Assume it's a rule ID
                SuppressionScope::Rule { rule_id: scope_str.to_string() }
            };

            let mut suppression = Suppression::new(scope, reason);
            if let Some(c) = comment {
                suppression = suppression.with_comment(c);
            }

            self.suppressions.push(suppression);
            count += 1;
        }

        Ok(count)
    }

    /// Save suppressions to file
    pub fn save(&self) -> Result<(), SuppressionError> {
        if !self.config.enable_file {
            return Ok(());
        }

        let mut lines = vec![
            "# KodeCD Suppression File".to_string(),
            "# Format: <file>:<line> [reason] [comment]".to_string(),
            "#         <file>:<rule-id> [reason] [comment]".to_string(),
            "#         <rule-id> [reason] [comment]".to_string(),
            "#         <file> [reason] [comment]".to_string(),
            "".to_string(),
        ];

        for suppression in &self.suppressions {
            let scope_str = match &suppression.scope {
                SuppressionScope::Line { file, line } => {
                    format!("{}:{}", file.display(), line)
                }
                SuppressionScope::FileRule { file, rule_id } => {
                    format!("{}:{}", file.display(), rule_id)
                }
                SuppressionScope::Rule { rule_id } => {
                    rule_id.clone()
                }
                SuppressionScope::File { file } => {
                    file.display().to_string()
                }
            };

            let reason_str = suppression.reason.as_str();
            let comment_str = suppression.comment.as_deref().unwrap_or("");

            lines.push(format!("{} {} {}", scope_str, reason_str, comment_str).trim().to_string());
        }

        std::fs::write(&self.config.suppression_file, lines.join("\n"))?;
        info!("Saved {} suppressions to {}",
              self.suppressions.len(),
              self.config.suppression_file.display());

        Ok(())
    }

    /// Check if finding is suppressed
    pub fn is_suppressed(&mut self, file: &Path, line: usize, rule_id: &str) -> bool {
        // Check inline suppressions
        if self.config.enable_inline {
            if let Some(suppressed_lines) = self.inline_cache.get(file) {
                if suppressed_lines.contains(&line) {
                    return true;
                }
            } else {
                // Load inline suppressions for this file
                if let Ok(inline) = self.load_inline_suppressions(file) {
                    if inline.contains(&line) {
                        return true;
                    }
                }
            }
        }

        // Check file-based suppressions
        if self.config.enable_file {
            for suppression in &self.suppressions {
                if suppression.matches(file, line, rule_id) {
                    debug!("Finding suppressed: {}:{}:{}", file.display(), line, rule_id);
                    return true;
                }
            }
        }

        false
    }

    /// Load inline suppressions from file
    fn load_inline_suppressions(&mut self, file: &Path) -> Result<Vec<usize>, SuppressionError> {
        let content = std::fs::read_to_string(file)?;
        let mut suppressed_lines = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            // Check for kodecd-ignore comment
            if line.contains("kodecd-ignore") || line.contains("kodecd:ignore") {
                suppressed_lines.push(line_num + 1); // Next line
            }
        }

        // Cache for future use
        self.inline_cache.insert(file.to_path_buf(), suppressed_lines.clone());

        Ok(suppressed_lines)
    }

    /// Add new suppression
    pub fn add(&mut self, suppression: Suppression) {
        self.suppressions.push(suppression);
    }

    /// Get all suppressions
    pub fn get_all(&self) -> &[Suppression] {
        &self.suppressions
    }

    /// Clear all suppressions
    pub fn clear(&mut self) {
        self.suppressions.clear();
        self.inline_cache.clear();
    }

    /// Get statistics
    pub fn stats(&self) -> SuppressionStats {
        let mut by_scope = HashMap::new();
        let mut by_reason = HashMap::new();
        let mut expired = 0;

        for suppression in &self.suppressions {
            if suppression.is_expired() {
                expired += 1;
                continue;
            }

            let scope_type = match &suppression.scope {
                SuppressionScope::Line { .. } => "line",
                SuppressionScope::FileRule { .. } => "file-rule",
                SuppressionScope::Rule { .. } => "rule",
                SuppressionScope::File { .. } => "file",
            };

            *by_scope.entry(scope_type).or_insert(0) += 1;
            *by_reason.entry(suppression.reason.as_str().to_string()).or_insert(0) += 1;
        }

        SuppressionStats {
            total: self.suppressions.len(),
            expired,
            by_scope,
            by_reason,
        }
    }
}

/// Suppression statistics
#[derive(Debug)]
pub struct SuppressionStats {
    pub total: usize,
    pub expired: usize,
    pub by_scope: HashMap<&'static str, usize>,
    pub by_reason: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suppression_matching() {
        let suppression = Suppression::new(
            SuppressionScope::Line {
                file: PathBuf::from("app.js"),
                line: 42,
            },
            SuppressionReason::FalsePositive,
        );

        assert!(suppression.matches(Path::new("app.js"), 42, "sql-injection"));
        assert!(!suppression.matches(Path::new("app.js"), 43, "sql-injection"));
        assert!(!suppression.matches(Path::new("other.js"), 42, "sql-injection"));
    }

    #[test]
    fn test_rule_suppression() {
        let suppression = Suppression::new(
            SuppressionScope::Rule {
                rule_id: "sql-injection".to_string(),
            },
            SuppressionReason::AcceptedRisk,
        );

        assert!(suppression.matches(Path::new("app.js"), 42, "sql-injection"));
        assert!(suppression.matches(Path::new("other.js"), 100, "sql-injection"));
        assert!(!suppression.matches(Path::new("app.js"), 42, "xss"));
    }

    #[test]
    fn test_suppression_file_parsing() {
        let content = r#"
# Comment
app.js:42 false-positive Line 42 is safe
src/db.js:sql-injection accepted-risk Using parameterized queries
xss not-applicable Not a web app
test/fixtures/
"#;

        let config = SuppressionConfig::default();
        let mut manager = SuppressionManager {
            config,
            suppressions: Vec::new(),
            inline_cache: HashMap::new(),
        };

        let count = manager.parse_suppression_file(content).unwrap();
        assert_eq!(count, 4);
    }

    #[test]
    fn test_expiration() {
        let past = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() - 3600; // 1 hour ago

        let suppression = Suppression::new(
            SuppressionScope::Line {
                file: PathBuf::from("app.js"),
                line: 42,
            },
            SuppressionReason::FalsePositive,
        )
        .with_expiration(past);

        assert!(suppression.is_expired());
        assert!(!suppression.matches(Path::new("app.js"), 42, "sql-injection"));
    }
}
