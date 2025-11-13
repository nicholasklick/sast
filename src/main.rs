//! KodeCD SAST - High-performance static analysis security testing engine
//!
//! A CodeQL competitor written in Rust with custom query language (KQL)

mod discovery;
mod parallel;

use anyhow::Result;
use clap::{Parser as ClapParser, Subcommand};
use std::path::{Path, PathBuf};
use tracing::{info, Level};
use tracing_subscriber;

use discovery::FileDiscovery;
use parallel::ParallelAnalyzer;

use kodecd_analyzer::{CallGraphBuilder, CfgBuilder, InterproceduralTaintAnalysis, SymbolTableBuilder};
use kodecd_parser::{Language, LanguageConfig};
use kodecd_query::{QueryExecutor, QueryParser, ExtendedStandardLibrary, QuerySuite};
use kodecd_reporter::{Report, ReportFormat, Reporter};

#[derive(ClapParser)]
#[command(name = "kodecd")]
#[command(author = "KodeCD Team")]
#[command(version = "0.1.0")]
#[command(about = "High-performance SAST engine with custom query language", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze source code for security vulnerabilities
    Analyze {
        /// Path to source file or directory
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Output format (text, json, sarif)
        #[arg(short, long, default_value = "text")]
        format: String,

        /// Output file (defaults to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Language to analyze (auto-detect if not specified)
        #[arg(short, long)]
        language: Option<String>,

        /// Custom KQL query file
        #[arg(short, long)]
        query: Option<PathBuf>,
    },

    /// Run built-in security queries
    Scan {
        /// Path to source file or directory
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Output format (text, json, sarif)
        #[arg(short, long, default_value = "text")]
        format: String,

        /// Output file (defaults to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Query suite (default, extended, quality)
        #[arg(short = 's', long, default_value = "default")]
        suite: String,
    },

    /// Show available built-in queries
    ListQueries,

    /// Validate a KQL query
    ValidateQuery {
        /// Path to KQL query file
        #[arg(value_name = "QUERY")]
        query: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let level = if cli.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };

    tracing_subscriber::fmt().with_max_level(level).init();

    let exit_code = match cli.command {
        Commands::Analyze {
            path,
            format,
            output,
            language,
            query,
        } => {
            info!("Analyzing: {}", path.display());
            analyze_file(&path, &format, output.as_deref(), language, query)?
        }

        Commands::Scan { path, format, output, suite } => {
            info!("Scanning with built-in queries: {}", path.display());
            scan_with_builtin(&path, &format, output.as_deref(), &suite)?
        }

        Commands::ListQueries => {
            list_queries();
            0
        }

        Commands::ValidateQuery { query } => {
            info!("Validating query: {}", query.display());
            validate_query(&query)?;
            0
        }
    };

    std::process::exit(exit_code);
}

fn analyze_file(
    path: &PathBuf,
    format_str: &str,
    output: Option<&Path>,
    language: Option<String>,
    query_file: Option<PathBuf>,
) -> Result<i32> {
    // Detect or use specified language
    let lang = if let Some(lang_str) = language {
        match lang_str.to_lowercase().as_str() {
            "rust" => Language::Rust,
            "python" => Language::Python,
            "javascript" | "js" => Language::JavaScript,
            "typescript" | "ts" => Language::TypeScript,
            "java" => Language::Java,
            "go" => Language::Go,
            "swift" => Language::Swift,
            "php" => Language::Php,
            _ => {
                eprintln!("Unsupported language: {}", lang_str);
                std::process::exit(1);
            }
        }
    } else {
        Language::from_path(path)?
    };

    info!("Detected language: {}", lang.name());

    // Parse the source file
    let config = LanguageConfig::new(lang);
    let parser = kodecd_parser::Parser::new(config, path);
    let ast = parser.parse_file()?;

    info!("Parsed AST with {} nodes", ast.children.len());

    // Build symbol table
    let symbol_table_builder = SymbolTableBuilder::new();
    let symbol_table = symbol_table_builder.build(&ast);

    info!("Built symbol table with {} scopes", symbol_table.scope_count());

    // Build call graph
    let call_graph_builder = CallGraphBuilder::new();
    let call_graph = call_graph_builder.build(&ast);

    info!("Built call graph with {} functions, {} call sites",
          call_graph.node_count(), call_graph.edge_count());

    // Build control flow graph
    let cfg_builder = CfgBuilder::new();
    let cfg = cfg_builder.build(&ast);

    info!("Built CFG with {} nodes", cfg.graph.node_count());

    // Run interprocedural taint analysis
    let mut interprocedural_analysis = InterproceduralTaintAnalysis::new()
        .with_default_sources()
        .with_default_sinks()
        .with_default_sanitizers();
    let taint_results = interprocedural_analysis.analyze(&ast, &call_graph);

    info!("Interprocedural analysis found {} vulnerabilities", taint_results.vulnerabilities.len());

    // Parse or use default query
    let query = if let Some(query_path) = query_file {
        let query_source = std::fs::read_to_string(query_path)?;
        QueryParser::parse(&query_source)?
    } else {
        // Use a default SQL injection query from extended library
        let library = ExtendedStandardLibrary::new();
        if let Some((query, _)) = library.get("js/sql-injection") {
            query.clone()
        } else {
            anyhow::bail!("Default query not found");
        }
    };

    // Execute query
    let result = QueryExecutor::execute(&query, &ast, &cfg, Some(&taint_results));

    info!("Found {} potential issues", result.findings.len());

    // Generate report
    let has_findings = !result.findings.is_empty();
    let report = Report::new(result.findings);
    let format = parse_format(format_str);

    // Write output
    if let Some(output_path) = output {
        let mut file = std::fs::File::create(output_path)?;
        Reporter::write_report(&report, format, &mut file)?;
        info!("Report written to: {}", output_path.display());
    } else {
        let mut stdout = std::io::stdout();
        Reporter::write_report(&report, format, &mut stdout)?;
    }

    // Return exit code: 0 if no findings, 1 if findings found
    if has_findings {
        Ok(1)
    } else {
        Ok(0)
    }
}

fn scan_with_builtin(path: &PathBuf, format_str: &str, output: Option<&Path>, suite_str: &str) -> Result<i32> {
    // Parse query suite
    let suite = parse_suite(suite_str);

    // Check if path is a file or directory
    if path.is_file() {
        // Single file analysis (original behavior)
        scan_single_file(path, format_str, output, suite)
    } else if path.is_dir() {
        // Multi-file analysis (new behavior)
        scan_directory(path, format_str, output, suite)
    } else {
        anyhow::bail!("Path is neither a file nor directory: {}", path.display());
    }
}

fn scan_single_file(path: &PathBuf, format_str: &str, output: Option<&Path>, suite: QuerySuite) -> Result<i32> {
    let lang = Language::from_path(path)?;
    let config = LanguageConfig::new(lang);
    let parser = kodecd_parser::Parser::new(config, path);
    let ast = parser.parse_file()?;

    // Build symbol table
    let symbol_table_builder = SymbolTableBuilder::new();
    let symbol_table = symbol_table_builder.build(&ast);

    info!("Built symbol table with {} scopes", symbol_table.scope_count());

    // Build call graph
    let call_graph_builder = CallGraphBuilder::new();
    let call_graph = call_graph_builder.build(&ast);

    info!("Built call graph with {} functions, {} call sites",
          call_graph.node_count(), call_graph.edge_count());

    let cfg_builder = CfgBuilder::new();
    let cfg = cfg_builder.build(&ast);

    // Run interprocedural taint analysis
    let mut interprocedural_analysis = InterproceduralTaintAnalysis::new()
        .with_default_sources()
        .with_default_sinks()
        .with_default_sanitizers();
    let taint_results = interprocedural_analysis.analyze(&ast, &call_graph);

    info!("Interprocedural analysis found {} vulnerabilities", taint_results.vulnerabilities.len());

    // Run all built-in queries from the extended library
    let library = ExtendedStandardLibrary::new();
    let queries = library.get_suite(suite);
    let mut all_findings = Vec::new();

    info!("Running {} queries from {} suite", queries.len(), suite_name(suite));

    for (query_id, query, metadata) in queries {
        info!("Running query: {} - {}", query_id, metadata.name);
        let result = QueryExecutor::execute(&query, &ast, &cfg, Some(&taint_results));

        // Update findings with metadata
        for mut finding in result.findings {
            finding.rule_id = query_id.to_string();
            finding.category = metadata.category.as_str().to_string();
            finding.severity = metadata.severity.as_str().to_string();
            all_findings.push(finding);
        }
    }

    info!("Total findings: {}", all_findings.len());

    let has_findings = !all_findings.is_empty();
    let report = Report::new(all_findings);
    let format = parse_format(format_str);

    if let Some(output_path) = output {
        let mut file = std::fs::File::create(output_path)?;
        Reporter::write_report(&report, format, &mut file)?;
    } else {
        let mut stdout = std::io::stdout();
        Reporter::write_report(&report, format, &mut stdout)?;
    }

    // Return exit code: 0 if no findings, 1 if findings found
    if has_findings {
        Ok(1)
    } else {
        Ok(0)
    }
}

fn scan_directory(path: &PathBuf, format_str: &str, output: Option<&Path>, suite: QuerySuite) -> Result<i32> {
    info!("Starting multi-file analysis on directory: {}", path.display());

    // Discover all source files
    let discovery = FileDiscovery::with_default_config();
    let source_files = discovery.discover(path)?;

    if source_files.is_empty() {
        info!("No source files found in directory");
        return Ok(0);
    }

    info!("Found {} source files to analyze", source_files.len());

    // Get queries from extended library
    let library = ExtendedStandardLibrary::new();
    let suite_queries = library.get_suite(suite);

    info!("Using {} queries from {} suite", suite_queries.len(), suite_name(suite));

    // Prepare queries with categorization
    let queries: Vec<(String, kodecd_query::Query)> = suite_queries
        .into_iter()
        .map(|(id, query, _metadata)| (id.to_string(), query.clone()))
        .collect();

    // Run parallel analysis
    let analyzer = ParallelAnalyzer::new(true); // Enable progress bar
    let results = analyzer.analyze_files(source_files, &queries)?;

    // Get statistics
    let stats = ParallelAnalyzer::get_statistics(&results);
    info!(
        "Analysis complete: {}/{} files successful, {} total findings",
        stats.successful_files, stats.total_files, stats.total_findings
    );

    // Aggregate all findings
    let mut all_findings = ParallelAnalyzer::aggregate_findings(&results);

    // Apply categorization and severity
    for finding in &mut all_findings {
        finding.category = categorize_rule(&finding.rule_id);
        finding.severity = determine_severity(&finding.rule_id);
    }

    // Generate report
    let has_findings = !all_findings.is_empty();
    let report = Report::new(all_findings);
    let format = parse_format(format_str);

    if let Some(output_path) = output {
        let mut file = std::fs::File::create(output_path)?;
        Reporter::write_report(&report, format, &mut file)?;
        info!("Report written to: {}", output_path.display());
    } else {
        let mut stdout = std::io::stdout();
        Reporter::write_report(&report, format, &mut stdout)?;
    }

    // Return exit code: 0 if no findings, 1 if findings found
    if has_findings {
        Ok(1)
    } else {
        Ok(0)
    }
}

fn list_queries() {
    let library = ExtendedStandardLibrary::new();
    let all_queries = library.all_metadata();

    println!("\nKodeCD Extended Query Library");
    println!("{}", "=".repeat(70));
    println!("Total Queries: {}", all_queries.len());
    println!();

    // Group by category
    use std::collections::BTreeMap;
    let mut by_category: BTreeMap<String, Vec<_>> = BTreeMap::new();

    for metadata in all_queries {
        by_category
            .entry(metadata.category.as_str().to_string())
            .or_insert_with(Vec::new)
            .push(metadata);
    }

    for (category, queries) in by_category {
        println!("{}:", category);
        for metadata in queries {
            println!("  {} - {} [{}]",
                metadata.id,
                metadata.name,
                metadata.severity.as_str()
            );
        }
        println!();
    }

    println!("Query Suites:");
    println!("  default          - High precision, critical/high severity (~40 queries)");
    println!("  extended         - Broader coverage, includes medium severity (~70 queries)");
    println!("  quality          - Complete coverage including code quality (100+ queries)");
    println!();
    println!("Usage: kodecd-sast scan <path> --suite <suite>");
    println!();
}

fn validate_query(path: &PathBuf) -> Result<()> {
    let query_source = std::fs::read_to_string(path)?;
    let query = QueryParser::parse(&query_source)?;

    println!("✓ Query is valid");
    println!("  From: {:?}", query.from.entity);
    println!("  Where: {}", query.where_clause.is_some());
    println!("  Select: {} items", query.select.items.len());

    Ok(())
}

fn parse_format(format_str: &str) -> ReportFormat {
    match format_str.to_lowercase().as_str() {
        "sarif" => ReportFormat::Sarif,
        "json" => ReportFormat::Json,
        "text" => ReportFormat::Text,
        _ => ReportFormat::Text,
    }
}

fn parse_suite(suite_str: &str) -> QuerySuite {
    match suite_str.to_lowercase().as_str() {
        "default" => QuerySuite::Default,
        "extended" | "security-extended" => QuerySuite::SecurityExtended,
        "quality" | "security-and-quality" => QuerySuite::SecurityAndQuality,
        _ => {
            eprintln!("Unknown suite '{}', using 'default'", suite_str);
            QuerySuite::Default
        }
    }
}

fn suite_name(suite: QuerySuite) -> &'static str {
    match suite {
        QuerySuite::Default => "default",
        QuerySuite::SecurityExtended => "security-extended",
        QuerySuite::SecurityAndQuality => "security-and-quality",
    }
}

fn categorize_rule(rule_id: &str) -> String {
    match rule_id {
        "sql-injection" | "command-injection" | "ldap-injection" => "injection".to_string(),
        "xss" | "unsafe-redirect" | "server-side-template-injection" => "injection".to_string(),
        "path-traversal" => "path-traversal".to_string(),
        "hardcoded-secrets" => "secrets".to_string(),
        "insecure-deserialization" => "deserialization".to_string(),
        "xxe" => "xxe".to_string(),
        "ssrf" => "ssrf".to_string(),
        "weak-crypto" => "cryptography".to_string(),
        _ => "security".to_string(),
    }
}

fn determine_severity(rule_id: &str) -> String {
    match rule_id {
        "sql-injection" | "command-injection" | "insecure-deserialization" => "Critical".to_string(),
        "xss" | "xxe" | "ssrf" | "server-side-template-injection" => "High".to_string(),
        "path-traversal" | "ldap-injection" | "unsafe-redirect" => "High".to_string(),
        "hardcoded-secrets" | "weak-crypto" => "Medium".to_string(),
        _ => "Medium".to_string(),
    }
}
