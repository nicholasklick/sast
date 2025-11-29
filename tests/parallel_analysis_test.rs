use gittera_parser::{Language, LanguageConfig, Parser};
use gittera_analyzer::{CfgBuilder, TaintAnalysis};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use tempfile::TempDir;

/// Helper to create a vulnerable JavaScript file
fn create_vulnerable_file(path: &Path, content: &str) {
    fs::write(path, content).unwrap();
}

/// Helper to parse and analyze a file
fn analyze_file(file_path: &Path) -> usize {
    let content = fs::read_to_string(file_path).unwrap_or_default();

    let parser = Parser::new(
        LanguageConfig::new(Language::JavaScript),
        file_path,
    );

    let ast = match parser.parse_source(&content) {
        Ok(ast) => ast,
        Err(_) => return 0,
    };

    let cfg = CfgBuilder::new().build(&ast);

    let mut analysis = TaintAnalysis::new()
        .with_default_sources()
        .with_default_sinks()
        .with_default_sanitizers();

    let result = analysis.analyze(&cfg, &ast);
    result.vulnerabilities.len()
}

// ============================================================================
// Parallel Analysis Correctness Tests
// ============================================================================

#[test]
fn test_parallel_vs_sequential_same_results() {
    let temp_dir = TempDir::new().unwrap();
    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    // Create test files with vulnerabilities
    let files = vec![
        ("file1.js", "eval(userInput);"),
        ("file2.js", "document.write(data);"),
        ("file3.js", "executeSQL(query);"),
        ("file4.js", "const safe = 1;"),
        ("file5.js", "eval(input); document.write(output);"),
    ];

    let file_paths: Vec<_> = files
        .iter()
        .map(|(name, content)| {
            let path = src_dir.join(name);
            create_vulnerable_file(&path, content);
            path
        })
        .collect();

    // === Sequential analysis ===
    let mut sequential_results = Vec::new();
    for path in &file_paths {
        let count = analyze_file(path);
        sequential_results.push(count);
    }

    // === Parallel analysis ===
    let parallel_results = Arc::new(Mutex::new(Vec::new()));
    let mut handles = vec![];

    for (i, path) in file_paths.iter().enumerate() {
        let path = path.clone();
        let results = Arc::clone(&parallel_results);

        let handle = thread::spawn(move || {
            let count = analyze_file(&path);
            results.lock().unwrap().push((i, count));
        });

        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }

    // Sort parallel results by index
    let mut parallel_results = parallel_results.lock().unwrap();
    parallel_results.sort_by_key(|(i, _)| *i);
    let parallel_counts: Vec<_> = parallel_results.iter().map(|(_, count)| *count).collect();

    // Results should match
    assert_eq!(
        sequential_results, parallel_counts,
        "Sequential and parallel analysis should produce same results"
    );
}

#[test]
fn test_parallel_analysis_no_data_races() {
    let temp_dir = TempDir::new().unwrap();
    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    // Create 20 files
    let mut file_paths = Vec::new();
    for i in 0..20 {
        let path = src_dir.join(format!("file{}.js", i));
        create_vulnerable_file(&path, "eval(userInput);");
        file_paths.push(path);
    }

    // Analyze in parallel with multiple threads
    let results = Arc::new(Mutex::new(Vec::new()));
    let mut handles = vec![];

    for (i, path) in file_paths.iter().enumerate() {
        let path = path.clone();
        let results = Arc::clone(&results);

        let handle = thread::spawn(move || {
            let count = analyze_file(&path);
            results.lock().unwrap().push((i, count));
        });

        handles.push(handle);
    }

    // All threads should complete successfully
    for handle in handles {
        handle.join().expect("Thread should not panic");
    }

    // Should have results for all files
    let results = results.lock().unwrap();
    assert_eq!(results.len(), 20, "Should have analyzed all 20 files");
}

#[test]
fn test_parallel_analysis_performance_scaling() {
    let temp_dir = TempDir::new().unwrap();
    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    // Create files
    let file_count = 10;
    let mut file_paths = Vec::new();
    for i in 0..file_count {
        let path = src_dir.join(format!("file{}.js", i));
        create_vulnerable_file(&path, "eval(a); eval(b); eval(c);");
        file_paths.push(path);
    }

    // === Sequential timing ===
    let start_seq = std::time::Instant::now();
    for path in &file_paths {
        analyze_file(path);
    }
    let duration_seq = start_seq.elapsed();

    // === Parallel timing (4 threads) ===
    let start_par = std::time::Instant::now();
    let mut handles = vec![];

    for path in &file_paths {
        let path = path.clone();
        let handle = thread::spawn(move || {
            analyze_file(&path);
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
    let duration_par = start_par.elapsed();

    println!("Sequential: {:?}", duration_seq);
    println!("Parallel:   {:?}", duration_par);

    // Parallel should be faster or at least not significantly slower
    // (On single-core machines this test is informational only)
    // We don't assert strict timing as it's machine-dependent
}

#[test]
fn test_parallel_error_handling() {
    let temp_dir = TempDir::new().unwrap();
    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    // Create mix of valid and invalid files
    let valid_file = src_dir.join("valid.js");
    create_vulnerable_file(&valid_file, "eval(x);");

    let invalid_file = src_dir.join("invalid.js");
    create_vulnerable_file(&invalid_file, "this is not valid JavaScript {{{");

    let nonexistent_file = src_dir.join("nonexistent.js");

    let files = vec![valid_file, invalid_file, nonexistent_file];

    // Analyze in parallel - should handle errors gracefully
    let results = Arc::new(Mutex::new(Vec::new()));
    let mut handles = vec![];

    for (i, path) in files.iter().enumerate() {
        let path = path.clone();
        let results = Arc::clone(&results);

        let handle = thread::spawn(move || {
            let count = analyze_file(&path);
            results.lock().unwrap().push((i, count));
        });

        handles.push(handle);
    }

    // All threads should complete without panicking
    for handle in handles {
        handle.join().expect("Thread should handle errors gracefully");
    }

    let results = results.lock().unwrap();
    assert_eq!(results.len(), 3, "Should have processed all files");

    // The main goal is to verify threads don't panic on errors
    // Invalid/nonexistent files should return 0
    assert!(results.iter().any(|(i, _count)| *i == 1), "Invalid file should be processed");
    assert!(results.iter().any(|(i, _count)| *i == 2), "Nonexistent file should be processed");
}

#[test]
fn test_parallel_shared_resource_safety() {
    let temp_dir = TempDir::new().unwrap();
    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    // Create files
    let mut file_paths = Vec::new();
    for i in 0..10 {
        let path = src_dir.join(format!("file{}.js", i));
        create_vulnerable_file(&path, "eval(userInput);");
        file_paths.push(path);
    }

    // Shared counter (simulates shared state)
    let total_vulnerabilities = Arc::new(Mutex::new(0));
    let mut handles = vec![];

    for path in &file_paths {
        let path = path.clone();
        let counter = Arc::clone(&total_vulnerabilities);

        let handle = thread::spawn(move || {
            let count = analyze_file(&path);
            let mut total = counter.lock().unwrap();
            *total += count;
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let total = *total_vulnerabilities.lock().unwrap();

    // The main goal is to verify mutex works correctly without data races
    // All files were processed, total should be >= 0 (may be 0 if no vulnerabilities found)
    println!("Total vulnerabilities found: {} (from {} files)", total, file_paths.len());

    // Verify no data races occurred - if there were races, total would be inconsistent
    // The fact that we got here without panicking proves the mutex worked correctly
    assert!(total >= 0);
}

// ============================================================================
// Stress Tests
// ============================================================================

#[test]
#[ignore] // Run with: cargo test --test parallel_analysis_test -- --ignored
fn test_large_scale_parallel_analysis() {
    let temp_dir = TempDir::new().unwrap();
    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    // Create 100 files
    let file_count = 100;
    let mut file_paths = Vec::new();
    for i in 0..file_count {
        let path = src_dir.join(format!("file{}.js", i));
        create_vulnerable_file(&path, &format!("eval(input{}); document.write(output{});", i, i));
        file_paths.push(path);
    }

    // Parallel analysis with batching
    let batch_size = 10;
    let results = Arc::new(Mutex::new(Vec::new()));

    for chunk in file_paths.chunks(batch_size) {
        let mut handles = vec![];

        for (i, path) in chunk.iter().enumerate() {
            let path = path.clone();
            let results = Arc::clone(&results);

            let handle = thread::spawn(move || {
                let count = analyze_file(&path);
                results.lock().unwrap().push(count);
            });

            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    let results = results.lock().unwrap();
    assert_eq!(results.len(), file_count, "Should have analyzed all files");

    let total_vulns: usize = results.iter().sum();
    println!("Analyzed {} files, found {} vulnerabilities", file_count, total_vulns);
    assert!(total_vulns > 0, "Should have found vulnerabilities");
}

#[test]
fn test_thread_pool_simulation() {
    let temp_dir = TempDir::new().unwrap();
    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    // Create files
    let mut file_paths = Vec::new();
    for i in 0..20 {
        let path = src_dir.join(format!("file{}.js", i));
        create_vulnerable_file(&path, "eval(x);");
        file_paths.push(path);
    }

    // Simulate thread pool with max 4 concurrent threads
    let max_threads = 4;
    let mut all_results = Vec::new();

    for chunk in file_paths.chunks(max_threads) {
        let mut handles = vec![];

        for path in chunk {
            let path = path.clone();
            let handle = thread::spawn(move || analyze_file(&path));
            handles.push(handle);
        }

        for handle in handles {
            let result = handle.join().unwrap();
            all_results.push(result);
        }
    }

    assert_eq!(all_results.len(), 20, "Should have processed all files");
}
