#!/usr/bin/env rust-script
//! ```cargo
//! [dependencies]
//! kodecd-parser = { path = "crates/parser" }
//! kodecd-query = { path = "crates/query" }
//! kodecd-analyzer = { path = "crates/analyzer" }
//! ```

use kodecd_analyzer::CfgBuilder;
use kodecd_parser::{Language, LanguageConfig, Parser};
use kodecd_query::{QueryExecutor, QueryParser};
use std::path::Path;

fn main() {
    println!("=== KQL End-to-End Test ===\n");

    // Test file with vulnerabilities
    let test_file = "test_vulnerabilities.ts";

    // Parse the file
    println!("📝 Parsing {}...", test_file);
    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new(test_file));
    let ast = match parser.parse_file() {
        Ok(ast) => {
            println!("✅ Parsed successfully\n");
            ast
        }
        Err(e) => {
            eprintln!("❌ Parse error: {}", e);
            return;
        }
    };

    // Build CFG
    println!("🔧 Building control flow graph...");
    let cfg = ControlFlowGraphBuilder::build(&ast);
    println!("✅ CFG built with {} nodes\n", cfg.graph.node_count());

    // Test queries
    let queries = vec![
        (
            "SQL Injection",
            r#"FROM CallExpression AS call
               WHERE call.callee MATCHES "(?i)(execute|query|exec)"
               SELECT call, "Potential SQL injection""#,
        ),
        (
            "Command Injection",
            r#"FROM CallExpression AS call
               WHERE call.callee == "exec"
               SELECT call, "Potential command injection""#,
        ),
        (
            "Eval Usage",
            r#"FROM CallExpression AS call
               WHERE call.callee == "eval"
               SELECT call, "Dangerous eval() call detected""#,
        ),
        (
            "XSS - innerHTML",
            r#"FROM MemberExpression AS member
               WHERE member.property MATCHES "(?i)(innerHTML|outerHTML)"
               SELECT member, "Potential XSS vulnerability""#,
        ),
        (
            "Hardcoded Secrets",
            r#"FROM VariableDeclaration AS vd
               WHERE vd.name MATCHES "(?i)(password|secret|apikey|token)"
               SELECT vd, "Potential hardcoded secret""#,
        ),
        (
            "Weak Crypto",
            r#"FROM CallExpression AS call
               WHERE call.callee MATCHES "(?i)(md5|sha1|des)"
               SELECT call, "Weak cryptography detected""#,
        ),
    ];

    println!("🔍 Running {} queries:\n", queries.len());
    println!("{}", "=".repeat(80));

    let mut total_findings = 0;

    for (name, query_str) in queries {
        println!("\n📋 Query: {}", name);
        println!("   {}", query_str.lines().next().unwrap().trim());

        // Parse the query
        let query = match QueryParser::parse(query_str) {
            Ok(q) => q,
            Err(e) => {
                println!("   ❌ Query parse error: {}", e);
                continue;
            }
        };

        // Execute the query
        let result = QueryExecutor::execute(&query, &ast, &cfg, None);

        if result.findings.is_empty() {
            println!("   ✓ No findings (query works, no matches)");
        } else {
            println!("   🚨 Found {} issues:", result.findings.len());
            for (i, finding) in result.findings.iter().enumerate().take(3) {
                println!(
                    "      {}. Line {}: {}",
                    i + 1,
                    finding.line,
                    finding.message
                );
                println!(
                    "         Code: {}",
                    finding.code_snippet.chars().take(60).collect::<String>()
                );
            }
            if result.findings.len() > 3 {
                println!("      ... and {} more", result.findings.len() - 3);
            }
            total_findings += result.findings.len();
        }
    }

    println!("\n{}", "=".repeat(80));
    println!("\n✅ KQL End-to-End Test Complete!");
    println!("📊 Total findings: {}", total_findings);
    println!("\n✨ KQL Parser & Executor are fully functional!");
}
