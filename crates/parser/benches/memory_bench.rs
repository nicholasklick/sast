use kodecd_parser::{
    AstArena, Language, LanguageConfig, Parser, ParserArena,
};
use std::path::Path;

fn main() {
    let test_file = "../../test_vulnerabilities.ts";
    let source = std::fs::read_to_string(test_file).unwrap();

    println!("File: {} ({} bytes)", test_file, source.len());
    println!("Lines: {}", source.lines().count());
    println!("{}", "=".repeat(60));

    // Test standard parser
    println!("\n📦 Standard AST Parser:");
    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new(test_file));
    let ast = parser.parse_file().unwrap();

    // Count nodes recursively
    fn count_nodes(node: &kodecd_parser::AstNode) -> usize {
        1 + node.children.iter().map(count_nodes).sum::<usize>()
    }

    let node_count = count_nodes(&ast);
    println!("  Nodes: {}", node_count);

    // Estimate memory (rough approximation)
    let estimated_memory = node_count * 200; // ~200 bytes per node with strings
    println!("  Estimated memory: {:.2} KB", estimated_memory as f64 / 1024.0);

    println!("{}", "=".repeat(60));

    // Test arena parser
    println!("\n🚀 Arena AST Parser:");
    let arena = AstArena::new();
    let config = LanguageConfig::new(Language::TypeScript);
    let mut arena_parser = ParserArena::new(config, Path::new(test_file));
    let arena_ast = arena_parser.parse_file(&arena).unwrap();

    // Count arena nodes
    fn count_arena_nodes(node: &kodecd_parser::ArenaAstNode) -> usize {
        1 + node.children.iter().map(|n| count_arena_nodes(n)).sum::<usize>()
    }

    let arena_node_count = count_arena_nodes(arena_ast);
    println!("  Nodes: {}", arena_node_count);

    let stats = arena.memory_stats();
    println!("  {}", stats);

    println!("{}", "=".repeat(60));

    // Calculate savings
    println!("\n💰 Savings:");
    let memory_saving = ((estimated_memory - stats.arena_allocated) as f64 / estimated_memory as f64) * 100.0;
    println!("  Memory reduction: {:.1}%", memory_saving);
    println!("  Allocated: {:.2} KB → {:.2} KB",
        estimated_memory as f64 / 1024.0,
        stats.arena_allocated as f64 / 1024.0
    );
}
