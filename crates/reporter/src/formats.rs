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
        writeln!(writer, "\n{}", "Gittera SAST Analysis Results".bold())?;
        writeln!(writer, "{}", "=".repeat(70))?;
        writeln!(writer)?;

        writeln!(writer, "{}", "Summary:".bold())?;
        writeln!(writer, "  Total Findings: {}", report.summary.total_findings)?;
        writeln!(
            writer,
            "  Critical: {}",
            format!("{}", report.summary.critical).red().bold()
        )?;
        writeln!(
            writer,
            "  High:     {}",
            format!("{}", report.summary.high).red()
        )?;
        writeln!(
            writer,
            "  Medium:   {}",
            format!("{}", report.summary.medium).yellow()
        )?;
        writeln!(
            writer,
            "  Low:      {}",
            format!("{}", report.summary.low).green()
        )?;
        writeln!(writer)?;

        if !report.findings.is_empty() {
            writeln!(writer, "{}", "Findings:".bold())?;
            writeln!(writer, "{}", "=".repeat(70))?;

            for (i, finding) in report.findings.iter().enumerate() {
                writeln!(writer)?;

                // Header with severity badge
                let severity_badge = format!("[{}]", finding.severity);
                let colored_badge = Self::colorize_severity(&severity_badge);
                writeln!(
                    writer,
                    "{}. {} {} ({})",
                    i + 1,
                    colored_badge,
                    finding.message.bold(),
                    finding.rule_id.italic()
                )?;

                // Location
                writeln!(
                    writer,
                    "   {}",
                    format!("Location: {}:{}:{}", finding.file_path, finding.line, finding.column).cyan()
                )?;

                // Category
                writeln!(
                    writer,
                    "   Category: {}",
                    finding.category
                )?;

                // Source code snippet
                writeln!(writer, "\n   Source Code:")?;
                Self::write_source_context(writer, finding)?;

                writeln!(writer, "\n   {}", "-".repeat(66))?;
            }
        }

        writeln!(writer)?;
        Ok(())
    }

    fn write_source_context<W: Write>(writer: &mut W, finding: &crate::Finding) -> Result<(), ReportError> {
        // Try to read the source file
        if let Ok(content) = std::fs::read_to_string(&finding.file_path) {
            let lines: Vec<&str> = content.lines().collect();
            let finding_line = finding.line;

            // Show 2 lines before and after for context
            let start = finding_line.saturating_sub(3).max(1);
            let end = (finding_line + 2).min(lines.len());

            for line_num in start..=end {
                if line_num > 0 && line_num <= lines.len() {
                    let line_content = lines[line_num - 1];

                    if line_num == finding_line {
                        // Highlight the vulnerable line
                        writeln!(
                            writer,
                            "   {} {}  {}",
                            format!("{:>4}", line_num).yellow().bold(),
                            "│".yellow().bold(),
                            line_content.red()
                        )?;
                        // Add an arrow pointing to the issue
                        writeln!(
                            writer,
                            "   {}  {} {}",
                            " ".repeat(4),
                            " ".repeat(finding.column),
                            "^".repeat(finding.code_snippet.len().min(10)).red().bold()
                        )?;
                    } else {
                        // Context lines
                        writeln!(
                            writer,
                            "   {} │  {}",
                            format!("{:>4}", line_num).dimmed(),
                            line_content.dimmed()
                        )?;
                    }
                }
            }
        } else {
            // Fallback to just showing the code snippet
            writeln!(writer, "   {}", finding.code_snippet.italic())?;
        }

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
