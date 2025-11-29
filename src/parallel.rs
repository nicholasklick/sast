//! Parallel analysis module for multi-file processing
//!
//! Handles parallel parsing, analysis, and query execution across multiple files

use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use gittera_analyzer::{CallGraphBuilder, CfgBuilder, InterproceduralTaintAnalysis, SymbolTableBuilder};
use gittera_parser::{LanguageConfig, Parser};
use gittera_query::{Query, QueryExecutor};
use gittera_query::Finding;
use rayon::prelude::*;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::{debug, error, info};

use crate::discovery::SourceFile;

/// Result of analyzing a single file
#[derive(Debug)]
pub struct FileAnalysisResult {
    pub file_path: PathBuf,
    pub findings: Vec<Finding>,
    pub success: bool,
    pub error: Option<String>,
}

/// Parallel analyzer for multi-file analysis
pub struct ParallelAnalyzer {
    show_progress: bool,
}

impl ParallelAnalyzer {
    pub fn new(show_progress: bool) -> Self {
        Self { show_progress }
    }

    /// Analyze multiple files in parallel
    pub fn analyze_files(
        &self,
        files: Vec<SourceFile>,
        queries: &[(String, Query)],
    ) -> Result<Vec<FileAnalysisResult>> {
        info!("Starting parallel analysis of {} files", files.len());

        let progress = if self.show_progress {
            let pb = ProgressBar::new(files.len() as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} {msg}")
                    .unwrap()
                    .progress_chars("=>-"),
            );
            Some(Arc::new(Mutex::new(pb)))
        } else {
            None
        };

        // Process files in parallel using rayon
        let results: Vec<FileAnalysisResult> = files
            .par_iter()
            .map(|source_file| {
                let result = self.analyze_single_file(source_file, queries);

                // Update progress
                if let Some(pb) = &progress {
                    if let Ok(pb) = pb.lock() {
                        pb.inc(1);
                        if result.success {
                            pb.set_message(format!("✓ {}", source_file.path.display()));
                        } else {
                            pb.set_message(format!("✗ {}", source_file.path.display()));
                        }
                    }
                }

                result
            })
            .collect();

        // Finish progress bar
        if let Some(pb) = progress {
            if let Ok(pb) = pb.lock() {
                pb.finish_with_message("Analysis complete");
            }
        }

        let successful = results.iter().filter(|r| r.success).count();
        let failed = results.len() - successful;

        info!(
            "Parallel analysis complete: {} succeeded, {} failed",
            successful, failed
        );

        Ok(results)
    }

    fn analyze_single_file(
        &self,
        source_file: &SourceFile,
        queries: &[(String, Query)],
    ) -> FileAnalysisResult {
        debug!("Analyzing: {}", source_file.path.display());

        // Parse the file
        let config = LanguageConfig::new(source_file.language);
        let parser = Parser::new(config, &source_file.path);

        let ast = match parser.parse_file() {
            Ok(ast) => ast,
            Err(e) => {
                error!("Parse error in {}: {}", source_file.path.display(), e);
                return FileAnalysisResult {
                    file_path: source_file.path.clone(),
                    findings: vec![],
                    success: false,
                    error: Some(format!("Parse error: {}", e)),
                };
            }
        };

        // Build analysis structures
        let symbol_table_builder = SymbolTableBuilder::new();
        let _symbol_table = symbol_table_builder.build(&ast);

        let call_graph_builder = CallGraphBuilder::new();
        let call_graph = call_graph_builder.build(&ast);

        let cfg_builder = CfgBuilder::new();
        let cfg = cfg_builder.build(&ast);

        // Run interprocedural taint analysis
        let mut interprocedural_analysis = InterproceduralTaintAnalysis::new()
            .with_default_sources()
            .with_default_sinks()
            .with_default_sanitizers();
        let taint_results = interprocedural_analysis.analyze(&ast, &call_graph);

        // Execute all queries
        let mut all_findings = Vec::new();

        for (name, query) in queries {
            let result = QueryExecutor::execute(query, &ast, &cfg, Some(&taint_results));

            for mut finding in result.findings {
                // Ensure file path is set correctly
                finding.file_path = source_file.path.to_string_lossy().to_string();
                finding.rule_id = name.to_string();
                all_findings.push(finding);
            }
        }

        debug!(
            "Found {} issues in {}",
            all_findings.len(),
            source_file.path.display()
        );

        FileAnalysisResult {
            file_path: source_file.path.clone(),
            findings: all_findings,
            success: true,
            error: None,
        }
    }

    /// Aggregate findings from multiple file results
    pub fn aggregate_findings(results: &[FileAnalysisResult]) -> Vec<Finding> {
        let mut all_findings: Vec<Finding> = results
            .iter()
            .flat_map(|r| r.findings.clone())
            .collect();

        // Sort by severity (Critical > High > Medium > Low), then by file path
        all_findings.sort_by(|a, b| {
            let severity_order = |s: &str| match s {
                "Critical" => 0,
                "High" => 1,
                "Medium" => 2,
                "Low" => 3,
                _ => 4,
            };

            severity_order(&a.severity)
                .cmp(&severity_order(&b.severity))
                .then_with(|| a.file_path.cmp(&b.file_path))
                .then_with(|| a.line.cmp(&b.line))
        });

        all_findings
    }

    /// Get statistics from analysis results
    pub fn get_statistics(results: &[FileAnalysisResult]) -> AnalysisStatistics {
        let total_files = results.len();
        let successful_files = results.iter().filter(|r| r.success).count();
        let failed_files = total_files - successful_files;
        let total_findings = results.iter().map(|r| r.findings.len()).sum();

        AnalysisStatistics {
            total_files,
            successful_files,
            failed_files,
            total_findings,
        }
    }
}

#[derive(Debug)]
pub struct AnalysisStatistics {
    pub total_files: usize,
    pub successful_files: usize,
    pub failed_files: usize,
    pub total_findings: usize,
}
