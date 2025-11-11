//! KodeCD SAST - High-performance static analysis security testing engine
//!
//! A CodeQL competitor written in Rust with custom query language (KQL)

use anyhow::Result;
use clap::{Parser as ClapParser, Subcommand};
use std::path::{Path, PathBuf};
use tracing::{info, Level};
use tracing_subscriber;

use kodecd_analyzer::{CallGraphBuilder, CfgBuilder, InterproceduralTaintAnalysis, SymbolTableBuilder};
use kodecd_parser::{Language, LanguageConfig};
use kodecd_query::{QueryExecutor, QueryParser, StandardLibrary};
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

        Commands::Scan { path, format, output } => {
            info!("Scanning with built-in queries: {}", path.display());
            scan_with_builtin(&path, &format, output.as_deref())?
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
        // Use a default query
        StandardLibrary::sql_injection_query()
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

fn scan_with_builtin(path: &PathBuf, format_str: &str, output: Option<&Path>) -> Result<i32> {
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

    // Run all built-in queries
    let mut all_findings = Vec::new();

    for (name, query) in StandardLibrary::owasp_queries() {
        info!("Running query: {}", name);
        let result = QueryExecutor::execute(&query, &ast, &cfg, Some(&taint_results));

        // Update findings with proper rule_id and category
        for mut finding in result.findings {
            finding.rule_id = name.to_string();
            finding.category = categorize_rule(name);
            finding.severity = determine_severity(name);
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

fn list_queries() {
    println!("\nAvailable Built-in Queries:");
    println!("{}", "=".repeat(50));

    for (name, _) in StandardLibrary::owasp_queries() {
        println!("  - {}", name);
    }

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
