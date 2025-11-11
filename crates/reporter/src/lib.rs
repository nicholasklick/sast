//! Result reporting in multiple formats (SARIF, JSON, text)

pub mod formats;
pub mod sarif;

pub use formats::{ReportFormat, Reporter};
pub use sarif::SarifReporter;

use kodecd_query::Finding;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ReportError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub summary: Summary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    pub total_files: usize,
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

impl Report {
    pub fn new(findings: Vec<Finding>) -> Self {
        let summary = Summary::from_findings(&findings);
        Self { findings, summary }
    }
}

impl Summary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;

        for finding in findings {
            match finding.severity.as_str() {
                "Critical" => critical += 1,
                "High" => high += 1,
                "Medium" => medium += 1,
                "Low" => low += 1,
                _ => {}
            }
        }

        Self {
            total_files: 0, // TODO: Track unique files
            total_findings: findings.len(),
            critical,
            high,
            medium,
            low,
        }
    }
}
