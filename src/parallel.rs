//! Parallel analysis module for multi-file processing
//!
//! Handles parallel parsing, analysis, and query execution across multiple files

use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use gittera_analyzer::{CallGraphBuilder, CfgBuilder, InterproceduralTaintAnalysis, SymbolTableBuilder};
use gittera_parser::{Language, LanguageConfig, Parser};
use gittera_query::{Query, QueryExecutor, QueryMetadata};
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

/// Convert Language enum to the string format used in query metadata
fn language_to_string(lang: Language) -> &'static str {
    match lang {
        Language::JavaScript => "javascript",
        Language::TypeScript => "typescript",
        Language::Python => "python",
        Language::Ruby => "ruby",
        Language::Php => "php",
        Language::Java => "java",
        Language::Kotlin => "kotlin",
        Language::Scala => "scala",
        Language::Go => "go",
        Language::Rust => "rust",
        Language::C => "c",
        Language::Cpp => "cpp",
        Language::CSharp => "csharp",
        Language::Swift => "swift",
        Language::Lua => "lua",
        Language::Perl => "perl",
        Language::Bash => "bash",
        Language::Dart => "dart",
    }
}

impl ParallelAnalyzer {
    pub fn new(show_progress: bool) -> Self {
        Self { show_progress }
    }

    /// Analyze multiple files in parallel (legacy - no language filtering)
    pub fn analyze_files(
        &self,
        files: Vec<SourceFile>,
        queries: &[(String, Query)],
    ) -> Result<Vec<FileAnalysisResult>> {
        // Convert to the new format with empty metadata (no language filtering)
        let queries_with_metadata: Vec<(String, Query, Option<QueryMetadata>)> = queries
            .iter()
            .map(|(id, q)| (id.clone(), q.clone(), None))
            .collect();
        self.analyze_files_with_metadata(files, &queries_with_metadata)
    }

    /// Analyze multiple files in parallel with language-aware query filtering
    pub fn analyze_files_with_metadata(
        &self,
        files: Vec<SourceFile>,
        queries: &[(String, Query, Option<QueryMetadata>)],
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
                let result = self.analyze_single_file_with_metadata(source_file, queries);

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

        // Run interprocedural taint analysis with language-specific configuration
        let mut interprocedural_analysis = InterproceduralTaintAnalysis::new()
            .for_language(source_file.language);
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

        // Also include findings from interprocedural taint analysis
        for vuln in &taint_results.vulnerabilities {
            let severity = match vuln.severity {
                gittera_analyzer::taint::Severity::Critical => "critical",
                gittera_analyzer::taint::Severity::High => "high",
                gittera_analyzer::taint::Severity::Medium => "medium",
                gittera_analyzer::taint::Severity::Low => "low",
            };

            let category = match vuln.sink.kind {
                gittera_analyzer::taint::TaintSinkKind::SqlQuery => "sql-injection",
                gittera_analyzer::taint::TaintSinkKind::CommandExecution => "command-injection",
                gittera_analyzer::taint::TaintSinkKind::FileWrite => "arbitrary-file-write",
                gittera_analyzer::taint::TaintSinkKind::CodeEval => "code-injection",
                gittera_analyzer::taint::TaintSinkKind::HtmlOutput => "xss",
                gittera_analyzer::taint::TaintSinkKind::LogOutput => "log-injection",
                gittera_analyzer::taint::TaintSinkKind::NetworkSend => "ssrf",
                gittera_analyzer::taint::TaintSinkKind::XPathQuery => "xpath-injection",
                gittera_analyzer::taint::TaintSinkKind::LdapQuery => "ldap-injection",
                gittera_analyzer::taint::TaintSinkKind::PathTraversal => "path-traversal",
                gittera_analyzer::taint::TaintSinkKind::Deserialization => "insecure-deserialization",
                gittera_analyzer::taint::TaintSinkKind::XmlParse => "xxe",
                gittera_analyzer::taint::TaintSinkKind::TrustBoundary => "trustboundary",
                gittera_analyzer::taint::TaintSinkKind::Redirect => "redirect",
            };

            let rule_id = format!("taint/{}", category);
            let finding = Finding {
                file_path: source_file.path.to_string_lossy().to_string(),
                line: vuln.line,
                column: vuln.column,
                message: format!("{} vulnerability - untrusted data flows to {}", category, vuln.sink.name),
                severity: severity.to_string(),
                code_snippet: vuln.sink.name.clone(),
                category: category.to_string(),
                rule_id,
                cwes: vec![],  // Will be derived by reporter
                owasp: None,   // Will be derived by reporter
                flow_path: None,
            };
            all_findings.push(finding);
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

    /// Analyze a single file with language-aware query filtering
    fn analyze_single_file_with_metadata(
        &self,
        source_file: &SourceFile,
        queries: &[(String, Query, Option<QueryMetadata>)],
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

        // Run interprocedural taint analysis with language-specific configuration
        let mut interprocedural_analysis = InterproceduralTaintAnalysis::new()
            .for_language(source_file.language);
        let taint_results = interprocedural_analysis.analyze(&ast, &call_graph);

        // Get the language string for filtering
        let file_lang = language_to_string(source_file.language);

        // Execute only queries that match this file's language
        let mut all_findings = Vec::new();

        for (name, query, metadata) in queries {
            // Filter by language if metadata is present
            let should_run = match metadata {
                Some(meta) => meta.supports_language(file_lang),
                None => true, // No metadata = run on all files (legacy behavior)
            };

            if should_run {
                let result = QueryExecutor::execute(query, &ast, &cfg, Some(&taint_results));

                for mut finding in result.findings {
                    // Ensure file path is set correctly
                    finding.file_path = source_file.path.to_string_lossy().to_string();
                    finding.rule_id = name.to_string();
                    all_findings.push(finding);
                }
            }
        }

        // Also include findings from interprocedural taint analysis
        for vuln in &taint_results.vulnerabilities {
            let severity = match vuln.severity {
                gittera_analyzer::taint::Severity::Critical => "critical",
                gittera_analyzer::taint::Severity::High => "high",
                gittera_analyzer::taint::Severity::Medium => "medium",
                gittera_analyzer::taint::Severity::Low => "low",
            };

            let category = match vuln.sink.kind {
                gittera_analyzer::taint::TaintSinkKind::SqlQuery => "sql-injection",
                gittera_analyzer::taint::TaintSinkKind::CommandExecution => "command-injection",
                gittera_analyzer::taint::TaintSinkKind::FileWrite => "arbitrary-file-write",
                gittera_analyzer::taint::TaintSinkKind::CodeEval => "code-injection",
                gittera_analyzer::taint::TaintSinkKind::HtmlOutput => "xss",
                gittera_analyzer::taint::TaintSinkKind::LogOutput => "log-injection",
                gittera_analyzer::taint::TaintSinkKind::NetworkSend => "ssrf",
                gittera_analyzer::taint::TaintSinkKind::XPathQuery => "xpath-injection",
                gittera_analyzer::taint::TaintSinkKind::LdapQuery => "ldap-injection",
                gittera_analyzer::taint::TaintSinkKind::PathTraversal => "path-traversal",
                gittera_analyzer::taint::TaintSinkKind::Deserialization => "insecure-deserialization",
                gittera_analyzer::taint::TaintSinkKind::XmlParse => "xxe",
                gittera_analyzer::taint::TaintSinkKind::TrustBoundary => "trustboundary",
                gittera_analyzer::taint::TaintSinkKind::Redirect => "redirect",
            };

            let rule_id = format!("taint/{}", category);
            let finding = Finding {
                file_path: source_file.path.to_string_lossy().to_string(),
                line: vuln.line,
                column: vuln.column,
                message: format!("{} vulnerability - untrusted data flows to {}", category, vuln.sink.name),
                severity: severity.to_string(),
                code_snippet: vuln.sink.name.clone(),
                category: category.to_string(),
                rule_id,
                cwes: vec![],  // Will be derived by reporter
                owasp: None,   // Will be derived by reporter
                flow_path: None,
            };
            all_findings.push(finding);
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
