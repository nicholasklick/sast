//! Property-based tests for the parser using proptest
//!
//! These tests verify that the parser behaves correctly on randomly generated inputs,
//! ensuring robustness and preventing panics.

use kodecd_parser::{Language, LanguageConfig, Parser};
use proptest::prelude::*;
use std::path::Path;

/// Property: Parser should never panic on any input
#[test]
fn test_parser_never_panics_on_random_input() {
    proptest!(|(code in any::<String>())| {
        let config = LanguageConfig::new(Language::TypeScript);
        let parser = Parser::new(config, Path::new("test.ts"));

        // Parser should handle any input without panicking
        let _ = parser.parse_source(&code);
    });
}

/// Property: Parser should handle empty strings
#[test]
fn test_parser_handles_empty_string() {
    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));

    let result = parser.parse_source("");
    assert!(result.is_ok());
}

/// Property: Parser should handle very long identifiers
#[test]
fn test_parser_handles_long_identifiers() {
    proptest!(|(length in 1usize..1000)| {
        let identifier = "a".repeat(length);
        let code = format!("const {} = 42;", identifier);

        let config = LanguageConfig::new(Language::TypeScript);
        let parser = Parser::new(config, Path::new("test.ts"));

        let _ = parser.parse_source(&code);
    });
}

/// Property: Parser should handle deeply nested structures
#[test]
fn test_parser_handles_nested_structures() {
    proptest!(|(depth in 1usize..20)| {
        // Generate deeply nested function calls
        let mut code = String::from("f");
        for _ in 0..depth {
            code = format!("{}()", code);
        }
        code.push(';');

        let config = LanguageConfig::new(Language::TypeScript);
        let parser = Parser::new(config, Path::new("test.ts"));

        let _ = parser.parse_source(&code);
    });
}

/// Property: Valid TypeScript should always parse successfully
#[test]
fn test_valid_typescript_always_parses() {
    let valid_snippets = vec![
        "const x = 42;",
        "function foo() { return 1; }",
        "class Bar { }",
        "let x: number = 5;",
        "const arr = [1, 2, 3];",
        "const obj = { a: 1, b: 2 };",
    ];

    for snippet in valid_snippets {
        let config = LanguageConfig::new(Language::TypeScript);
        let parser = Parser::new(config, Path::new("test.ts"));

        let result = parser.parse_source(snippet);
        assert!(result.is_ok(), "Failed to parse: {}", snippet);
    }
}

/// Property: Parser output should be deterministic
#[test]
fn test_parser_is_deterministic() {
    proptest!(|(code in "[a-z]{1,100}")| {
        let config = LanguageConfig::new(Language::TypeScript);
        let parser1 = Parser::new(config.clone(), Path::new("test.ts"));
        let parser2 = Parser::new(config, Path::new("test.ts"));

        let result1 = parser1.parse_source(&code);
        let result2 = parser2.parse_source(&code);

        // Both should succeed or both should fail
        assert_eq!(result1.is_ok(), result2.is_ok());
    });
}

/// Property: Unicode handling
#[test]
fn test_parser_handles_unicode() {
    proptest!(|(code in "[\\u{0}-\\u{10000}]{1,100}")| {
        let config = LanguageConfig::new(Language::TypeScript);
        let parser = Parser::new(config, Path::new("test.ts"));

        // Should not panic, even if parse fails
        let _ = parser.parse_source(&code);
    });
}

/// Property: Whitespace variations should not affect validity
#[test]
fn test_whitespace_invariance() {
    let whitespace_variants = vec![
        "const x = 42;",
        "const  x  =  42 ;",
        "const\tx\t=\t42;",
        "const\nx\n=\n42;",
    ];

    let config = LanguageConfig::new(Language::TypeScript);

    for variant in whitespace_variants {
        let parser = Parser::new(config.clone(), Path::new("test.ts"));
        let result = parser.parse_source(variant);
        assert!(result.is_ok(), "Failed on whitespace variant: {:?}", variant);
    }
}

/// Property: Comments should not break parsing
#[test]
fn test_comments_invariance() {
    proptest!(|(comment in "[a-zA-Z0-9 ]{1,50}")| {
        let code_with_comment = format!("// {}\nconst x = 42;", comment);

        let config = LanguageConfig::new(Language::TypeScript);
        let parser = Parser::new(config, Path::new("test.ts"));

        let result = parser.parse_source(&code_with_comment);
        // Should parse successfully
        prop_assert!(result.is_ok());
    });
}

/// Property: String literals should be handled correctly
#[test]
fn test_string_literals() {
    proptest!(|(content in "[a-zA-Z0-9 ]{0,50}")| {
        let code = format!("const x = \"{}\";", content.replace('\"', "\\\""));

        let config = LanguageConfig::new(Language::TypeScript);
        let parser = Parser::new(config, Path::new("test.ts"));

        let result = parser.parse_source(&code);
        prop_assert!(result.is_ok());
    });
}

/// Property: Number literals should be handled correctly
#[test]
fn test_number_literals() {
    proptest!(|(num in any::<i64>())| {
        let code = format!("const x = {};", num);

        let config = LanguageConfig::new(Language::TypeScript);
        let parser = Parser::new(config, Path::new("test.ts"));

        let result = parser.parse_source(&code);
        prop_assert!(result.is_ok());
    });
}

/// Property: Boolean literals should always parse
#[test]
fn test_boolean_literals() {
    for bool_val in &["true", "false"] {
        let code = format!("const x = {};", bool_val);

        let config = LanguageConfig::new(Language::TypeScript);
        let parser = Parser::new(config, Path::new("test.ts"));

        let result = parser.parse_source(&code);
        assert!(result.is_ok());
    }
}

/// Property: Array construction should handle various sizes
#[test]
fn test_array_construction() {
    proptest!(|(size in 0usize..50)| {
        let elements: Vec<String> = (0..size).map(|i| i.to_string()).collect();
        let code = format!("const x = [{}];", elements.join(", "));

        let config = LanguageConfig::new(Language::TypeScript);
        let parser = Parser::new(config, Path::new("test.ts"));

        let result = parser.parse_source(&code);
        prop_assert!(result.is_ok());
    });
}

/// Property: Object construction should handle various sizes
#[test]
fn test_object_construction() {
    proptest!(|(size in 0usize..20)| {
        let properties: Vec<String> = (0..size)
            .map(|i| format!("prop{}: {}", i, i))
            .collect();
        let code = format!("const x = {{ {} }};", properties.join(", "));

        let config = LanguageConfig::new(Language::TypeScript);
        let parser = Parser::new(config, Path::new("test.ts"));

        let result = parser.parse_source(&code);
        prop_assert!(result.is_ok());
    });
}

/// Property: Function parameters should handle various counts
#[test]
fn test_function_parameters() {
    proptest!(|(param_count in 0usize..10)| {
        let params: Vec<String> = (0..param_count)
            .map(|i| format!("param{}", i))
            .collect();
        let code = format!("function foo({}) {{ return 42; }}", params.join(", "));

        let config = LanguageConfig::new(Language::TypeScript);
        let parser = Parser::new(config, Path::new("test.ts"));

        let result = parser.parse_source(&code);
        prop_assert!(result.is_ok());
    });
}

/// Property: Binary operators should parse correctly
#[test]
fn test_binary_operators() {
    let operators = vec!["+", "-", "*", "/", "%", "==", "!=", "<", ">", "<=", ">=", "&&", "||"];

    proptest!(|(op_idx in 0..operators.len(), left in 1i32..100, right in 1i32..100)| {
        let op = operators[op_idx];
        let code = format!("const x = {} {} {};", left, op, right);

        let config = LanguageConfig::new(Language::TypeScript);
        let parser = Parser::new(config, Path::new("test.ts"));

        let result = parser.parse_source(&code);
        prop_assert!(result.is_ok());
    });
}

#[cfg(test)]
mod multi_language_tests {
    use super::*;

    /// Property: All supported languages should handle empty input
    #[test]
    fn test_all_languages_handle_empty() {
        let languages = vec![
            Language::TypeScript,
            Language::JavaScript,
            Language::Python,
            Language::Rust,
            Language::Java,
            Language::Go,
        ];

        for lang in languages {
            let config = LanguageConfig::new(lang);
            let parser = Parser::new(config, Path::new("test.txt"));

            let result = parser.parse_source("");
            assert!(result.is_ok(), "Failed for language: {:?}", lang);
        }
    }

    /// Property: All languages should handle basic variable declarations
    #[test]
    fn test_all_languages_handle_variables() {
        let test_cases = vec![
            (Language::TypeScript, "const x = 42;"),
            (Language::JavaScript, "const x = 42;"),
            (Language::Python, "x = 42"),
            (Language::Rust, "let x = 42;"),
            (Language::Java, "int x = 42;"),
            (Language::Go, "var x = 42"),
        ];

        for (lang, code) in test_cases {
            let config = LanguageConfig::new(lang);
            let parser = Parser::new(config, Path::new("test.txt"));

            let result = parser.parse_source(code);
            assert!(result.is_ok(), "Failed for language: {:?}", lang);
        }
    }
}
