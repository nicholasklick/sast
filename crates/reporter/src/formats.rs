//! Report output formats

use crate::{Report, ReportError};
use colored::Colorize;
use std::io::Write;

#[derive(Debug, Clone, Copy)]
pub enum ReportFormat {
    Sarif,
    Json,
    Text,
}

pub struct Reporter;

impl Reporter {
    pub fn write_report<W: Write>(
        report: &Report,
        format: ReportFormat,
        writer: &mut W,
    ) -> Result<(), ReportError> {
        match format {
            ReportFormat::Sarif => {
                crate::sarif::SarifReporter::write(report, writer)?;
            }
            ReportFormat::Json => {
                serde_json::to_writer_pretty(writer, report)?;
            }
            ReportFormat::Text => {
                Self::write_text(report, writer)?;
            }
        }
        Ok(())
    }

    fn write_text<W: Write>(report: &Report, writer: &mut W) -> Result<(), ReportError> {
        writeln!(writer, "\n{}", "KodeCD SAST Analysis Results".bold())?;
        writeln!(writer, "{}", "=".repeat(50))?;
        writeln!(writer)?;

        writeln!(writer, "{}", "Summary:".bold())?;
        writeln!(writer, "  Total Findings: {}", report.summary.total_findings)?;
        writeln!(
            writer,
            "  Critical: {}",
            format!("{}", report.summary.critical).red()
        )?;
        writeln!(
            writer,
            "  High: {}",
            format!("{}", report.summary.high).red()
        )?;
        writeln!(
            writer,
            "  Medium: {}",
            format!("{}", report.summary.medium).yellow()
        )?;
        writeln!(
            writer,
            "  Low: {}",
            format!("{}", report.summary.low).green()
        )?;
        writeln!(writer)?;

        if !report.findings.is_empty() {
            writeln!(writer, "{}", "Findings:".bold())?;
            writeln!(writer, "{}", "-".repeat(50))?;

            for (i, finding) in report.findings.iter().enumerate() {
                writeln!(writer)?;
                writeln!(writer, "{}. {}", i + 1, finding.message.bold())?;
                writeln!(
                    writer,
                    "   Location: {}:{}:{}",
                    finding.file_path, finding.line, finding.column
                )?;
                writeln!(writer, "   Severity: {}", Self::colorize_severity(&finding.severity))?;
                writeln!(writer, "   Code: {}", finding.code_snippet.italic())?;
            }
        }

        writeln!(writer)?;
        Ok(())
    }

    fn colorize_severity(severity: &str) -> colored::ColoredString {
        match severity {
            "Critical" | "High" => severity.red(),
            "Medium" => severity.yellow(),
            "Low" => severity.green(),
            _ => severity.normal(),
        }
    }
}
