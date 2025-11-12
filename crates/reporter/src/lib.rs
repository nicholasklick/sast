//! Result reporting in multiple formats (SARIF, JSON, text)
//!
//! This crate provides flexible reporting of security findings in various formats
//! suitable for different tools and workflows.
//!
//! ## Features
//!
//! - **SARIF 2.1.0**: Static Analysis Results Interchange Format
//! - **JSON**: Machine-readable structured output
//! - **Text**: Human-readable console output
//! - **GitHub Integration**: Ready for GitHub Code Scanning
//! - **VS Code Integration**: Compatible with VS Code SARIF viewer
//!
//! ## Quick Start
//!
//! ### SARIF Output
//!
//! ```rust
//! use kodecd_reporter::{Reporter, ReportFormat};
//! use kodecd_query::Finding;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let findings = vec![
//!     Finding {
//!         file_path: "app.ts".to_string(),
//!         line: 42,
//!         column: 10,
//!         message: "SQL injection vulnerability".to_string(),
//!         severity: "Critical".to_string(),
//!         code_snippet: "database.execute(userInput)".to_string(),
//!         category: "injection".to_string(),
//!         rule_id: "sql-injection".to_string(),
//!     }
//! ];
//!
//! // Generate SARIF report
//! let reporter = Reporter::new(ReportFormat::Sarif);
//! let output = reporter.generate(&findings)?;
//! println!("{}", output);
//! # Ok(())
//! # }
//! ```
//!
//! ### JSON Output
//!
//! ```rust
//! use kodecd_reporter::{Reporter, ReportFormat, Report};
//! # use kodecd_query::Finding;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let findings = vec![];
//! // Create report with summary
//! let report = Report::new(findings);
//!
//! // Generate JSON
//! let reporter = Reporter::new(ReportFormat::Json);
//! let output = reporter.generate(&report.findings)?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Text Output
//!
//! ```rust
//! use kodecd_reporter::{Reporter, ReportFormat};
//! # use kodecd_query::Finding;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let findings = vec![];
//! // Human-readable output
//! let reporter = Reporter::new(ReportFormat::Text);
//! let output = reporter.generate(&findings)?;
//! println!("{}", output);
//! # Ok(())
//! # }
//! ```
//!
//! ## SARIF Format
//!
//! SARIF (Static Analysis Results Interchange Format) is an OASIS standard for
//! representing static analysis results. It's supported by:
//!
//! - **GitHub Code Scanning**: Upload SARIF files to GitHub Security tab
//! - **VS Code**: SARIF Viewer extension
//! - **Azure DevOps**: Security scanning integration
//! - **GitLab**: Security dashboard
//!
//! ### SARIF Structure
//!
//! ```json
//! {
//!   "version": "2.1.0",
//!   "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
//!   "runs": [{
//!     "tool": {
//!       "driver": {
//!         "name": "KodeCD SAST",
//!         "version": "0.1.0",
//!         "informationUri": "https://github.com/kodecd/sast",
//!         "rules": [...]
//!       }
//!     },
//!     "results": [...]
//!   }]
//! }
//! ```
//!
//! ## Integration Examples
//!
//! ### GitHub Actions
//!
//! ```yaml
//! - name: Run SAST
//!   run: kodecd-sast scan --format sarif src/ > results.sarif
//!
//! - name: Upload SARIF
//!   uses: github/codeql-action/upload-sarif@v2
//!   with:
//!     sarif_file: results.sarif
//! ```
//!
//! ### CI/CD Pipeline
//!
//! ```bash
//! # Run scan and generate JSON report
//! kodecd-sast scan --format json src/ > results.json
//!
//! # Parse results in build script
//! CRITICAL=$(jq '.summary.critical' results.json)
//! if [ "$CRITICAL" -gt 0 ]; then
//!   echo "Critical vulnerabilities found!"
//!   exit 1
//! fi
//! ```
//!
//! ## Report Summary
//!
//! The [`Summary`] struct provides aggregate statistics:
//!
//! ```rust
//! use kodecd_reporter::{Report, Summary};
//! # use kodecd_query::Finding;
//!
//! # let findings = vec![];
//! let report = Report::new(findings);
//! let summary = &report.summary;
//!
//! println!("Total findings: {}", summary.total_findings);
//! println!("Critical: {}", summary.critical);
//! println!("High: {}", summary.high);
//! println!("Medium: {}", summary.medium);
//! println!("Low: {}", summary.low);
//! ```
//!
//! ## Error Handling
//!
//! ```rust
//! use kodecd_reporter::{Reporter, ReportFormat, ReportError};
//! # use kodecd_query::Finding;
//!
//! # fn example() -> Result<(), ReportError> {
//! # let findings = vec![];
//! let reporter = Reporter::new(ReportFormat::Sarif);
//!
//! match reporter.generate(&findings) {
//!     Ok(output) => println!("{}", output),
//!     Err(ReportError::IoError(e)) => {
//!         eprintln!("I/O error: {}", e);
//!     }
//!     Err(ReportError::SerializationError(e)) => {
//!         eprintln!("Serialization error: {}", e);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Testing
//!
//! ```bash
//! cargo test -p kodecd-reporter
//! ```
//!
//! ## See Also
//!
//! - [SARIF Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
//! - [GitHub Code Scanning](https://docs.github.com/en/code-security/code-scanning)
//! - [VS Code SARIF Viewer](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer)

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
