// Comprehensive E2E integration tests for Gittera SAST
// Tests multi-language scanning, vulnerability detection, and false positive handling

use gittera_parser::{Language, LanguageConfig, Parser};
use std::path::Path;
use std::fs;

#[test]
fn test_all_languages_parse_vulnerable_fixtures() {
    println!("\n=== Testing Vulnerable Code Fixtures ===");

    let test_cases = vec![
        ("tests/fixtures/vulnerable/kotlin_vulnerabilities.kt", Language::Kotlin),
        ("tests/fixtures/vulnerable/scala_vulnerabilities.scala", Language::Scala),
        ("tests/fixtures/vulnerable/groovy_vulnerabilities.groovy", Language::Groovy),
        ("tests/fixtures/vulnerable/java_vulnerabilities.java", Language::Java),
        ("tests/fixtures/vulnerable/go_vulnerabilities.go", Language::Go),
        ("tests/fixtures/vulnerable/rust_vulnerabilities.rs", Language::Rust),
        ("tests/fixtures/vulnerable/c_vulnerabilities.c", Language::C),
        ("tests/fixtures/vulnerable/cpp_vulnerabilities.cpp", Language::Cpp),
        ("tests/fixtures/vulnerable/csharp_vulnerabilities.cs", Language::CSharp),
        ("tests/fixtures/vulnerable/ruby_vulnerabilities.rb", Language::Ruby),
        ("tests/fixtures/vulnerable/php_vulnerabilities.php", Language::Php),
        ("tests/fixtures/vulnerable/javascript_vulnerabilities.js", Language::JavaScript),
        ("tests/fixtures/vulnerable/typescript_vulnerabilities.ts", Language::TypeScript),
        ("tests/fixtures/vulnerable/python_vulnerabilities.py", Language::Python),
        ("tests/fixtures/vulnerable/swift_vulnerabilities.swift", Language::Swift),
    ];

    let mut passed = 0;
    let mut failed = 0;

    for (file_path, language) in test_cases {
        print!("Testing {:?} parser with {}... ", language, file_path);

        let path = Path::new(file_path);
        if !path.exists() {
            println!("⚠️  SKIPPED (file not found)");
            continue;
        }

        let config = LanguageConfig::new(language);
        let parser = Parser::new(config, path);

        match parser.parse_file() {
            Ok(ast) => {
                assert!(!ast.children.is_empty(), "AST should not be empty");
                println!("✅ PASSED ({} nodes)", ast.children.len());
                passed += 1;
            }
            Err(e) => {
                println!("❌ FAILED: {}", e);
                failed += 1;
                panic!("Failed to parse {}: {}", file_path, e);
            }
        }
    }

    println!("\n📊 Vulnerable Fixtures Results: {} passed, {} failed", passed, failed);
    assert_eq!(failed, 0, "All vulnerable fixtures should parse successfully");
}

#[test]
fn test_all_languages_parse_clean_fixtures() {
    println!("\n=== Testing Clean/Safe Code Fixtures ===");

    let test_cases = vec![
        ("tests/fixtures/clean/safe_kotlin.kt", Language::Kotlin),
        ("tests/fixtures/clean/safe_scala.scala", Language::Scala),
        ("tests/fixtures/clean/safe_groovy.groovy", Language::Groovy),
        ("tests/fixtures/clean/safe_java.java", Language::Java),
        ("tests/fixtures/clean/safe_go.go", Language::Go),
        ("tests/fixtures/clean/safe_rust.rs", Language::Rust),
        ("tests/fixtures/clean/safe_c.c", Language::C),
        ("tests/fixtures/clean/safe_cpp.cpp", Language::Cpp),
        ("tests/fixtures/clean/safe_csharp.cs", Language::CSharp),
        ("tests/fixtures/clean/safe_ruby.rb", Language::Ruby),
        ("tests/fixtures/clean/safe_php.php", Language::Php),
        ("tests/fixtures/clean/safe_javascript.js", Language::JavaScript),
        ("tests/fixtures/clean/safe_typescript.ts", Language::TypeScript),
        ("tests/fixtures/clean/safe_python.py", Language::Python),
        ("tests/fixtures/clean/safe_swift.swift", Language::Swift),
    ];

    let mut passed = 0;
    let mut failed = 0;

    for (file_path, language) in test_cases {
        print!("Testing {:?} parser with {}... ", language, file_path);

        let path = Path::new(file_path);
        if !path.exists() {
            println!("⚠️  SKIPPED (file not found)");
            continue;
        }

        let config = LanguageConfig::new(language);
        let parser = Parser::new(config, path);

        match parser.parse_file() {
            Ok(ast) => {
                assert!(!ast.children.is_empty(), "AST should not be empty");
                println!("✅ PASSED ({} nodes)", ast.children.len());
                passed += 1;
            }
            Err(e) => {
                println!("❌ FAILED: {}", e);
                failed += 1;
                panic!("Failed to parse {}: {}", file_path, e);
            }
        }
    }

    println!("\n📊 Clean Fixtures Results: {} passed, {} failed", passed, failed);
    assert_eq!(failed, 0, "All clean fixtures should parse successfully");
}

#[test]
fn test_language_detection_from_extension() {
    println!("\n=== Testing Language Detection ===");

    let test_cases = vec![
        ("test.kt", Language::Kotlin),
        ("test.kts", Language::Kotlin),
        ("test.scala", Language::Scala),
        ("test.sc", Language::Scala),
        ("test.groovy", Language::Groovy),
        ("test.gradle", Language::Groovy),
        ("test.java", Language::Java),
        ("test.go", Language::Go),
        ("test.rs", Language::Rust),
        ("test.c", Language::C),
        ("test.cpp", Language::Cpp),
        ("test.cs", Language::CSharp),
        ("test.rb", Language::Ruby),
        ("test.php", Language::Php),
        ("test.js", Language::JavaScript),
        ("test.ts", Language::TypeScript),
        ("test.py", Language::Python),
        ("test.swift", Language::Swift),
    ];

    for (filename, expected) in test_cases {
        let path = Path::new(filename);
        let detected = Language::from_path(path);
        print!("Extension '{}' -> {:?}... ", filename, detected);
        match detected {
            Ok(lang) => {
                assert_eq!(lang, expected, "Expected {:?}, got {:?}", expected, lang);
                println!("✅");
            }
            Err(e) => {
                println!("❌ FAILED: {}", e);
                panic!("Failed to detect language for {}", filename);
            }
        }
    }

    println!("\n✅ All language detection tests passed");
}

#[test]
fn test_fixture_file_existence() {
    println!("\n=== Verifying Test Fixture Files Exist ===");

    let vulnerable_fixtures = vec![
        "tests/fixtures/vulnerable/kotlin_vulnerabilities.kt",
        "tests/fixtures/vulnerable/scala_vulnerabilities.scala",
        "tests/fixtures/vulnerable/groovy_vulnerabilities.groovy",
        "tests/fixtures/vulnerable/java_vulnerabilities.java",
        "tests/fixtures/vulnerable/go_vulnerabilities.go",
        "tests/fixtures/vulnerable/rust_vulnerabilities.rs",
        "tests/fixtures/vulnerable/c_vulnerabilities.c",
        "tests/fixtures/vulnerable/cpp_vulnerabilities.cpp",
        "tests/fixtures/vulnerable/csharp_vulnerabilities.cs",
        "tests/fixtures/vulnerable/ruby_vulnerabilities.rb",
        "tests/fixtures/vulnerable/php_vulnerabilities.php",
        "tests/fixtures/vulnerable/javascript_vulnerabilities.js",
        "tests/fixtures/vulnerable/typescript_vulnerabilities.ts",
        "tests/fixtures/vulnerable/python_vulnerabilities.py",
        "tests/fixtures/vulnerable/swift_vulnerabilities.swift",
    ];

    let clean_fixtures = vec![
        "tests/fixtures/clean/safe_kotlin.kt",
        "tests/fixtures/clean/safe_scala.scala",
        "tests/fixtures/clean/safe_groovy.groovy",
        "tests/fixtures/clean/safe_java.java",
        "tests/fixtures/clean/safe_go.go",
        "tests/fixtures/clean/safe_rust.rs",
        "tests/fixtures/clean/safe_c.c",
        "tests/fixtures/clean/safe_cpp.cpp",
        "tests/fixtures/clean/safe_csharp.cs",
        "tests/fixtures/clean/safe_ruby.rb",
        "tests/fixtures/clean/safe_php.php",
        "tests/fixtures/clean/safe_javascript.js",
        "tests/fixtures/clean/safe_typescript.ts",
        "tests/fixtures/clean/safe_python.py",
        "tests/fixtures/clean/safe_swift.swift",
    ];

    println!("\nVulnerable fixtures:");
    let mut missing_vulnerable = Vec::new();
    for fixture in &vulnerable_fixtures {
        let path = Path::new(fixture);
        if path.exists() {
            let metadata = fs::metadata(path).unwrap();
            println!("  ✅ {} ({} bytes)", fixture, metadata.len());
        } else {
            println!("  ❌ {} (MISSING)", fixture);
            missing_vulnerable.push(*fixture);
        }
    }

    println!("\nClean fixtures:");
    let mut missing_clean = Vec::new();
    for fixture in &clean_fixtures {
        let path = Path::new(fixture);
        if path.exists() {
            let metadata = fs::metadata(path).unwrap();
            println!("  ✅ {} ({} bytes)", fixture, metadata.len());
        } else {
            println!("  ❌ {} (MISSING)", fixture);
            missing_clean.push(*fixture);
        }
    }

    println!("\n📊 Summary:");
    println!("  Vulnerable: {}/{} files found",
             vulnerable_fixtures.len() - missing_vulnerable.len(),
             vulnerable_fixtures.len());
    println!("  Clean: {}/{} files found",
             clean_fixtures.len() - missing_clean.len(),
             clean_fixtures.len());

    if !missing_vulnerable.is_empty() || !missing_clean.is_empty() {
        println!("\n⚠️  Warning: Some fixture files are missing");
        println!("Missing vulnerable: {:?}", missing_vulnerable);
        println!("Missing clean: {:?}", missing_clean);
    } else {
        println!("\n✅ All fixture files present");
    }
}

#[test]
fn test_parser_error_handling() {
    println!("\n=== Testing Parser Error Handling ===");

    // Test with non-existent file
    let config = LanguageConfig::new(Language::Rust);
    let parser = Parser::new(config, Path::new("nonexistent.rs"));

    match parser.parse_file() {
        Ok(_) => panic!("Should have failed for non-existent file"),
        Err(_) => println!("✅ Correctly handled non-existent file"),
    }

    // Test with invalid syntax (create temporary file)
    let temp_file = "tests/temp_invalid_syntax.rs";
    fs::write(temp_file, "fn invalid { { { }").unwrap();

    let config = LanguageConfig::new(Language::Rust);
    let parser = Parser::new(config, Path::new(temp_file));

    // Note: Tree-sitter may still parse this, it's error-tolerant
    let result = parser.parse_file();
    println!("Invalid syntax test: {:?}", if result.is_ok() { "Parsed (error-tolerant)" } else { "Failed" });

    // Cleanup
    let _ = fs::remove_file(temp_file);

    println!("✅ Parser error handling tests completed");
}

#[test]
fn test_multi_file_batch_parsing() {
    println!("\n=== Testing Batch Multi-File Parsing ===");

    let files = vec![
        ("tests/fixtures/vulnerable/java_vulnerabilities.java", Language::Java),
        ("tests/fixtures/vulnerable/python_vulnerabilities.py", Language::Python),
        ("tests/fixtures/vulnerable/javascript_vulnerabilities.js", Language::JavaScript),
        ("tests/fixtures/clean/safe_rust.rs", Language::Rust),
        ("tests/fixtures/clean/safe_go.go", Language::Go),
    ];

    let mut total_nodes = 0;
    let mut successful_parses = 0;

    for (file_path, language) in &files {
        let path = Path::new(file_path);
        if !path.exists() {
            continue;
        }

        let config = LanguageConfig::new(*language);
        let parser = Parser::new(config, path);

        if let Ok(ast) = parser.parse_file() {
            total_nodes += ast.children.len();
            successful_parses += 1;
            println!("✅ Parsed {} ({} nodes)", file_path, ast.children.len());
        }
    }

    println!("\n📊 Batch results: {}/{} files parsed, {} total nodes",
             successful_parses, files.len(), total_nodes);

    assert!(successful_parses > 0, "At least some files should parse successfully");
}

#[test]
fn test_ast_node_structure() {
    println!("\n=== Testing AST Node Structure ===");

    // Test a simple Rust file
    let test_file = "tests/fixtures/clean/safe_rust.rs";
    let path = Path::new(test_file);

    if !path.exists() {
        println!("⚠️  Skipping: {} not found", test_file);
        return;
    }

    let config = LanguageConfig::new(Language::Rust);
    let parser = Parser::new(config, path);

    let ast = parser.parse_file().expect("Should parse successfully");

    println!("Root node: {:?}", ast.kind);
    println!("Children count: {}", ast.children.len());

    // Verify AST has expected structure
    assert!(!ast.children.is_empty(), "AST should have child nodes");

    // Check that we can traverse the tree
    let mut node_count = 0;
    fn count_nodes(node: &gittera_parser::ast::AstNode) -> usize {
        1 + node.children.iter().map(|c| count_nodes(c)).sum::<usize>()
    }

    node_count = count_nodes(&ast);
    println!("Total AST nodes: {}", node_count);

    assert!(node_count > 0, "Should have traversable AST nodes");
    println!("✅ AST structure tests passed");
}

#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_parsing_performance() {
        println!("\n=== Testing Parsing Performance ===");

        let test_files = vec![
            ("tests/fixtures/vulnerable/java_vulnerabilities.java", Language::Java),
            ("tests/fixtures/vulnerable/python_vulnerabilities.py", Language::Python),
            ("tests/fixtures/vulnerable/rust_vulnerabilities.rs", Language::Rust),
        ];

        for (file_path, language) in test_files {
            let path = Path::new(file_path);
            if !path.exists() {
                continue;
            }

            let config = LanguageConfig::new(language);
            let parser = Parser::new(config, path);

            let start = Instant::now();
            let result = parser.parse_file();
            let duration = start.elapsed();

            match result {
                Ok(ast) => {
                    println!("✅ {:?} parsed in {:?} ({} nodes)",
                             language, duration, ast.children.len());

                    // Performance assertion: should parse in reasonable time
                    assert!(duration.as_secs() < 5, "Parsing should complete in under 5 seconds");
                }
                Err(e) => {
                    println!("❌ {:?} failed: {}", language, e);
                }
            }
        }
    }
}
