//! SARIF format reporter

use crate::{Report, ReportError};
use serde_json::json;
use std::io::Write;

pub struct SarifReporter;

impl SarifReporter {
    pub fn write<W: Write>(report: &Report, writer: &mut W) -> Result<(), ReportError> {
        let sarif = json!({
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "KodeCD SAST",
                        "version": "0.1.0",
                        "informationUri": "https://kodecd.com",
                        "rules": []
                    }
                },
                "results": report.findings.iter().map(|finding| {
                    json!({
                        "ruleId": "security-check",
                        "level": Self::severity_to_level(&finding.severity),
                        "message": {
                            "text": finding.message
                        },
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": finding.file_path
                                },
                                "region": {
                                    "startLine": finding.line,
                                    "startColumn": finding.column
                                }
                            }
                        }]
                    })
                }).collect::<Vec<_>>()
            }]
        });

        serde_json::to_writer_pretty(writer, &sarif)?;
        Ok(())
    }

    fn severity_to_level(severity: &str) -> &'static str {
        match severity {
            "Critical" | "High" => "error",
            "Medium" => "warning",
            "Low" => "note",
            _ => "note",
        }
    }
}
