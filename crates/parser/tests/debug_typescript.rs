//! Debug test to see TypeScript-specific tree-sitter nodes

use kodecd_parser::{Language, LanguageConfig, Parser};
use std::path::Path;

fn print_ast(node: &kodecd_parser::ast::AstNode, indent: usize) {
    let indent_str = "  ".repeat(indent);
    println!("{}{:?}", indent_str, node.kind);
    for child in &node.children {
        print_ast(child, indent + 1);
    }
}

#[test]
fn debug_typescript_types() {
    let code = r#"
        function greet(name: string): string {
            return "Hello, " + name;
        }

        const value = obj as MyType;
        const checked = value satisfies number;
        const nonNull = value!;
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    println!("\n=== TYPESCRIPT TYPES ===");
    print_ast(&ast, 0);
}

#[test]
fn debug_typescript_generics() {
    let code = r#"
        function identity<T>(arg: T): T {
            return arg;
        }

        const result = identity<string>("hello");
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    println!("\n=== TYPESCRIPT GENERICS ===");
    print_ast(&ast, 0);
}
