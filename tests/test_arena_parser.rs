#!/usr/bin/env rust-script
//! ```cargo
//! [dependencies]
//! gittera-parser = { path = "crates/parser" }
//! ```

use gittera_parser::{
    AstArena, Language, LanguageConfig, Parser, ParserArena,
};
use std::path::Path;

fn main() {
    let test_file = "test_vulnerabilities.ts";
    let source = std::fs::read_to_string(test_file).unwrap();

    println!("File: {} ({} bytes)", test_file, source.len());
    println!("Lines: {}", source.lines().count());
    println!("{}", "=".repeat(60));

    // Test arena parser
    println!("\n🚀 Arena AST Parser:");
    let arena = AstArena::new();
    let config = LanguageConfig::new(Language::TypeScript);
    let mut arena_parser = ParserArena::new(config, Path::new(test_file));

    match arena_parser.parse_file(&arena) {
        Ok(arena_ast) => {
            // Count arena nodes
            fn count_arena_nodes(node: &gittera_parser::ArenaAstNode) -> usize {
                1 + node.children.iter().map(|n| count_arena_nodes(n)).sum::<usize>()
            }

            let arena_node_count = count_arena_nodes(arena_ast);
            println!("  ✓ Parsed successfully!");
            println!("  Nodes: {}", arena_node_count);

            let stats = arena.memory_stats();
            println!("  {}", stats);

            println!("\n✅ Arena parser working correctly!");
        }
        Err(e) => {
            println!("  ✗ Parse error: {}", e);
        }
    }
}
