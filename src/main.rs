//! Gittera SAST - High-performance static analysis security testing engine
//!
//! A CodeQL competitor written in Rust with custom query language (GQL)

mod discovery;
mod parallel;

use anyhow::Result;
use clap::{Parser as ClapParser, Subcommand};
use std::path::{Path, PathBuf};
use tracing::{info, Level};
use tracing_subscriber;

use discovery::FileDiscovery;
use parallel::ParallelAnalyzer;

use gittera_analyzer::{CallGraphBuilder, CfgBuilder, InterproceduralTaintAnalysis, SymbolTableBuilder, taint_config::init_yaml_configs};
use gittera_parser::{Language, LanguageConfig};
use gittera_query::{QueryExecutor, QueryParser, ExtendedStandardLibrary, QuerySuite};
use gittera_reporter::{Report, ReportFormat, Reporter};

/// Derive CWE IDs and OWASP category from rule ID
fn derive_cwe_owasp(rule_id: &str) -> (Vec<u32>, Option<String>) {
    let rule_lower = rule_id.to_lowercase();

    // Map rule patterns to CWE IDs and OWASP categories
    if rule_lower.contains("sql") {
        (vec![89], Some("A03:2021 - Injection".to_string()))
    } else if rule_lower.contains("command") || rule_lower.contains("commandexecution") {
        (vec![78, 77], Some("A03:2021 - Injection".to_string()))
    } else if rule_lower.contains("xss") || rule_lower.contains("htmloutput") {
        (vec![79], Some("A03:2021 - Injection".to_string()))
    } else if rule_lower.contains("path") || rule_lower.contains("pathtraversal") {
        (vec![22], Some("A01:2021 - Broken Access Control".to_string()))
    } else if rule_lower.contains("ldap") {
        (vec![90], Some("A03:2021 - Injection".to_string()))
    } else if rule_lower.contains("xpath") {
        (vec![643], Some("A03:2021 - Injection".to_string()))
    } else if rule_lower.contains("deserialization") {
        (vec![502], Some("A08:2021 - Software and Data Integrity Failures".to_string()))
    } else if rule_lower.contains("xxe") || rule_lower.contains("xml") {
        (vec![611], Some("A05:2021 - Security Misconfiguration".to_string()))
    } else if rule_lower.contains("ssrf") {
        (vec![918], Some("A10:2021 - Server-Side Request Forgery".to_string()))
    } else if rule_lower.contains("redirect") {
        (vec![601], Some("A01:2021 - Broken Access Control".to_string()))
    } else if rule_lower.contains("code") || rule_lower.contains("codeeval") {
        (vec![94, 95], Some("A03:2021 - Injection".to_string()))
    } else if rule_lower.contains("crypto") || rule_lower.contains("hash") || rule_lower.contains("random") {
        (vec![327, 328, 330], Some("A02:2021 - Cryptographic Failures".to_string()))
    } else if rule_lower.contains("trust") || rule_lower.contains("session") {
        (vec![384], Some("A07:2021 - Identification and Authentication Failures".to_string()))
    } else if rule_lower.contains("cookie") {
        (vec![614], Some("A05:2021 - Security Misconfiguration".to_string()))
    } else if rule_lower.contains("log") {
        (vec![117], Some("A09:2021 - Security Logging and Monitoring Failures".to_string()))
    } else {
        (vec![], None)
    }
}

#[derive(ClapParser)]
#[command(name = "gittera")]
#[command(author = "Gittera Team")]
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

        /// Custom GQL query file
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

        /// Enable incremental analysis (only scan changed files)
        #[arg(long)]
        incremental: bool,

        /// Disable cache (force full scan)
        #[arg(long)]
        no_cache: bool,

        /// Create a new baseline from current findings
        #[arg(long)]
        baseline_create: bool,

        /// Use existing baseline (suppress baseline findings)
        #[arg(long)]
        baseline_use: bool,

        /// Show fixed findings (findings in baseline but now resolved)
        #[arg(long)]
        show_fixed: bool,

        /// Enable finding lifecycle tracking
        #[arg(long)]
        lifecycle: bool,
    },

    /// Show available built-in queries
    ListQueries,

    /// Validate a GQL query
    ValidateQuery {
        /// Path to GQL query file
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

    // Initialize YAML taint configs from models directory
    // This tries to load language-specific configs from models/<lang>/core.yaml
    // If no YAML config is found, hardcoded defaults are used
    let exe_path = std::env::current_exe().ok();
    let models_dir = exe_path
        .as_ref()
        .and_then(|p| p.parent())
        .map(|p| p.join("models"))
        .unwrap_or_else(|| PathBuf::from("models"));

    if models_dir.exists() {
        if let Err(e) = init_yaml_configs(&models_dir) {
            info!("Could not load YAML configs from {}: {} (using hardcoded configs)", models_dir.display(), e);
        } else {
            info!("Loaded YAML taint configs from {}", models_dir.display());
        }
    }

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

        Commands::Scan {
            path,
            format,
            output,
            suite,
            incremental,
            no_cache,
            baseline_create,
            baseline_use,
            show_fixed,
            lifecycle,
        } => {
            info!("Scanning with built-in queries: {}", path.display());
            scan_with_builtin(
                &path,
                &format,
                output.as_deref(),
                &suite,
                incremental,
                no_cache,
                baseline_create,
                baseline_use,
                show_fixed,
                lifecycle,
            )?
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
    let parser = gittera_parser::Parser::new(config, path);
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

    // Run interprocedural taint analysis with language-specific configuration
    let mut interprocedural_analysis = InterproceduralTaintAnalysis::new()
        .for_language(lang);
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

fn scan_with_builtin(
    path: &PathBuf,
    format_str: &str,
    output: Option<&Path>,
    suite_str: &str,
    incremental: bool,
    no_cache: bool,
    baseline_create: bool,
    baseline_use: bool,
    show_fixed: bool,
    lifecycle: bool,
) -> Result<i32> {
    // Parse query suite
    let suite = parse_suite(suite_str);

    // Check if path is a file or directory
    if path.is_file() {
        // Single file analysis (original behavior)
        scan_single_file(path, format_str, output, suite)
    } else if path.is_dir() {
        // Multi-file analysis (new behavior)
        scan_directory(
            path,
            format_str,
            output,
            suite,
            incremental,
            no_cache,
            baseline_create,
            baseline_use,
            show_fixed,
            lifecycle,
        )
    } else {
        anyhow::bail!("Path is neither a file nor directory: {}", path.display());
    }
}

fn scan_single_file(path: &PathBuf, format_str: &str, output: Option<&Path>, suite: QuerySuite) -> Result<i32> {
    let lang = Language::from_path(path)?;
    let config = LanguageConfig::new(lang);
    let parser = gittera_parser::Parser::new(config, path);
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

    // Run interprocedural taint analysis with language-specific configuration
    let mut interprocedural_analysis = InterproceduralTaintAnalysis::new()
        .for_language(lang);
    let taint_results = interprocedural_analysis.analyze(&ast, &call_graph);

    info!("Interprocedural analysis found {} vulnerabilities", taint_results.vulnerabilities.len());

    // Run all built-in queries from the extended library
    let library = ExtendedStandardLibrary::new();
    let queries = library.get_suite(suite);
    let mut all_findings = Vec::new();

    // Add interprocedural taint analysis findings
    for vuln in &taint_results.vulnerabilities {
        let rule_id = format!("taint/{:?}", vuln.sink.kind).to_lowercase();
        let (cwes, owasp) = derive_cwe_owasp(&rule_id);
        all_findings.push(gittera_query::Finding {
            file_path: vuln.file_path.clone(),
            line: vuln.line,
            column: vuln.column,
            message: vuln.message.clone(),
            severity: vuln.severity.as_str().to_string(),
            rule_id,
            category: "taint-analysis".to_string(),
            code_snippet: String::new(),
            cwes,
            owasp,
        });
    }

    // Get language string for filtering
    let lang_str = match lang {
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
    };

    // Filter queries by language
    let matching_queries: Vec<_> = queries
        .into_iter()
        .filter(|(_, _, metadata)| metadata.supports_language(lang_str))
        .collect();

    info!("Running {} queries from {} suite (filtered for {})",
          matching_queries.len(), suite_name(suite), lang_str);

    for (query_id, query, metadata) in matching_queries {
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

fn scan_directory(
    path: &PathBuf,
    format_str: &str,
    output: Option<&Path>,
    suite: QuerySuite,
    incremental: bool,
    no_cache: bool,
    baseline_create: bool,
    baseline_use: bool,
    show_fixed: bool,
    lifecycle_enabled: bool,
) -> Result<i32> {
    use gittera_cache::{
        Cache, CacheConfig, BaselineManager, BaselineConfig,
        SuppressionManager, SuppressionConfig, LifecycleTracker, LifecycleConfig,
    };

    info!("Starting multi-file analysis on directory: {}", path.display());

    // Initialize cache if incremental mode is enabled
    let use_cache = incremental && !no_cache;
    let mut cache = if use_cache {
        info!("Incremental mode enabled");
        let config = CacheConfig::default();
        Some(Cache::new(config)?)
    } else {
        None
    };

    // Initialize suppression manager
    let suppression_config = SuppressionConfig::default();
    let mut suppressions = SuppressionManager::new(suppression_config)?;
    if let Err(e) = suppressions.load() {
        info!("No suppression file found or failed to load: {}", e);
    } else {
        let stats = suppressions.stats();
        info!("Loaded {} suppressions", stats.total);
    }

    // Initialize baseline manager
    let baseline_config = BaselineConfig {
        enabled: baseline_use || baseline_create,
        ..Default::default()
    };
    let mut baseline_manager = BaselineManager::new(baseline_config)?;

    // Initialize lifecycle tracker
    let lifecycle_config = LifecycleConfig {
        enabled: lifecycle_enabled,
        ..Default::default()
    };
    let mut lifecycle_tracker = LifecycleTracker::new(lifecycle_config)?;

    // Discover all source files
    let discovery = FileDiscovery::with_default_config();
    let all_source_files = discovery.discover(path)?;

    if all_source_files.is_empty() {
        info!("No source files found in directory");
        return Ok(0);
    }

    // Determine which files to scan
    let source_files = if let Some(cache) = &mut cache {
        let changed_files = cache.get_changed_files(path)?;
        info!("Incremental analysis: {} changed out of {} total files",
              changed_files.len(), all_source_files.len());

        // Convert relative paths to SourceFile structs
        changed_files
            .into_iter()
            .map(|p| path.join(p))
            .filter(|p| p.exists())
            .filter_map(|p| {
                Language::from_path(&p).ok().map(|lang| discovery::SourceFile {
                    path: p,
                    language: lang,
                })
            })
            .collect()
    } else {
        all_source_files
    };

    if source_files.is_empty() {
        info!("No files to scan (all files unchanged)");

        // Still load baseline/lifecycle if needed
        if baseline_use && show_fixed {
            // Show fixed findings from baseline
            if let Some(stats) = baseline_manager.stats() {
                println!("\nBaseline Statistics:");
                println!("  Total findings in baseline: {}", stats.total_findings);
            }
        }

        return Ok(0);
    }

    info!("Scanning {} files", source_files.len());

    // Get queries from extended library
    let library = ExtendedStandardLibrary::new();
    let suite_queries = library.get_suite(suite);

    info!("Using {} queries from {} suite", suite_queries.len(), suite_name(suite));

    // Prepare queries with metadata for language-aware filtering
    let queries: Vec<(String, gittera_query::Query, Option<gittera_query::QueryMetadata>)> = suite_queries
        .into_iter()
        .map(|(id, query, metadata)| (id.to_string(), query.clone(), Some(metadata.clone())))
        .collect();

    // Run parallel analysis with language filtering
    let analyzer = ParallelAnalyzer::new(true); // Enable progress bar
    let results = analyzer.analyze_files_with_metadata(source_files.clone(), &queries)?;

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

    // Apply suppressions
    all_findings.retain(|finding| {
        !suppressions.is_suppressed(
            std::path::Path::new(&finding.file_path),
            finding.line,
            &finding.rule_id,
        )
    });

    info!("After suppressions: {} findings", all_findings.len());

    // Store results in cache
    if let Some(cache) = &mut cache {
        // Group findings by file
        use std::collections::HashMap;
        let mut findings_by_file: HashMap<String, Vec<gittera_query::Finding>> = HashMap::new();
        for finding in &all_findings {
            findings_by_file
                .entry(finding.file_path.clone())
                .or_insert_with(Vec::new)
                .push(finding.clone());
        }

        // Store each file's results
        for (file_path, findings) in findings_by_file {
            if let Err(e) = cache.store_results(&file_path, &findings) {
                info!("Failed to cache results for {}: {}", file_path, e);
            }
        }

        // Save cache
        cache.save()?;
        let cache_stats = cache.stats();
        info!("Cache updated: {} files, {} cached results",
              cache_stats.total_files, cache_stats.cached_results);
    }

    // Handle baseline operations
    if baseline_create {
        baseline_manager.create_baseline(&all_findings, Some("Baseline created from scan".to_string()))?;
        info!("Created baseline with {} findings", all_findings.len());
    }

    let findings_to_report = if baseline_use {
        let new_findings = baseline_manager.filter_new_findings(&all_findings);
        let new_count = new_findings.len();
        let suppressed_count = all_findings.len() - new_count;

        info!("Baseline filtering: {} new findings, {} baseline findings suppressed",
              new_count, suppressed_count);

        if show_fixed {
            let fixed = baseline_manager.find_fixed_findings(&all_findings);
            if !fixed.is_empty() {
                println!("\n🎉 Fixed Findings ({}):", fixed.len());
                for f in &fixed {
                    println!("  ✓ {} at {}:{} [{}]",
                            f.rule_id, f.file_path, f.line, f.severity);
                }
                println!();
            }
        }

        new_findings.into_iter().cloned().collect()
    } else {
        all_findings.clone()
    };

    // Update lifecycle tracking
    if lifecycle_enabled {
        lifecycle_tracker.update(&all_findings);
        lifecycle_tracker.save()?;

        let lc_stats = lifecycle_tracker.stats();
        info!("Lifecycle: {} new, {} existing, {} fixed, {} reopened",
              lc_stats.new, lc_stats.existing, lc_stats.fixed, lc_stats.reopened);

        println!("\nFinding Lifecycle:");
        println!("  🆕 New:      {}", lc_stats.new);
        println!("  📊 Existing: {}", lc_stats.existing);
        println!("  ✅ Fixed:    {}", lc_stats.fixed);
        println!("  🔄 Reopened: {}", lc_stats.reopened);
        println!();
    }

    // Generate report
    let has_findings = !findings_to_report.is_empty();
    let report = Report::new(findings_to_report);
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

    println!("\nGittera Extended Query Library");
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
    println!("Usage: gittera-sast scan <path> --suite <suite>");
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
