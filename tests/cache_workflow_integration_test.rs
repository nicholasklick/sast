use gittera_cache::{Cache, CacheConfig, Baseline, BaselineManager, BaselineConfig};
use gittera_query::Finding;
use gittera_parser::{Language, LanguageConfig, Parser};
use std::fs;
use std::path::Path;
use tempfile::TempDir;
use std::thread;
use std::time::Duration;

/// Helper to create a test finding
fn create_finding(
    file_path: &str,
    line: usize,
    rule_id: &str,
) -> Finding {
    Finding {
        file_path: file_path.to_string(),
        line,
        column: 5,
        message: format!("{} vulnerability", rule_id),
        severity: "High".to_string(),
        code_snippet: format!("code at {}:{}", file_path, line),
        category: "security".to_string(),
        rule_id: rule_id.to_string(),
        cwes: vec![],
        owasp: None,
    }
}

// ============================================================================
// Incremental Scan Workflow Tests
// ============================================================================

#[test]
fn test_full_incremental_workflow() {
    let temp_dir = TempDir::new().unwrap();
    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    let cache_dir = temp_dir.path().join(".gittera/cache");
    let config = CacheConfig {
        cache_dir: cache_dir.clone(),
        content_hashing: true,
        ttl_seconds: 0,
        max_size_mb: 100,
    };

    // === Step 1: Initial scan ===
    let file1 = src_dir.join("app.js");
    let file2 = src_dir.join("utils.js");

    fs::write(&file1, "const x = eval(userInput);").unwrap();
    fs::write(&file2, "const y = 1;").unwrap();

    let mut cache = Cache::new(config.clone()).unwrap();
    let changed_files = cache.get_changed_files(&src_dir).unwrap();

    // Both files should be new
    assert_eq!(changed_files.len(), 2, "Initial scan should detect both files");
    cache.save().unwrap();

    // === Step 2: Rescan without changes ===
    let mut cache2 = Cache::new(config.clone()).unwrap();
    let changed_files2 = cache2.get_changed_files(&src_dir).unwrap();

    assert_eq!(changed_files2.len(), 0, "No changes should mean no files to scan");

    // === Step 3: Modify one file ===
    thread::sleep(Duration::from_millis(10));
    fs::write(&file1, "const x = eval(userInput); // modified").unwrap();

    let mut cache3 = Cache::new(config.clone()).unwrap();
    let changed_files3 = cache3.get_changed_files(&src_dir).unwrap();

    assert_eq!(changed_files3.len(), 1, "Only modified file should be detected");
    assert!(changed_files3.iter().any(|p| p.to_str().unwrap().contains("app.js")));

    // === Step 4: Add new file ===
    let file3 = src_dir.join("new.js");
    fs::write(&file3, "const z = 2;").unwrap();

    let mut cache4 = Cache::new(config.clone()).unwrap();
    let changed_files4 = cache4.get_changed_files(&src_dir).unwrap();

    // Should detect both the previously modified file and the new file
    // (if we haven't saved cache3, file1 is still marked as changed)
    assert!(changed_files4.len() >= 1, "New file should be detected");
    assert!(changed_files4.iter().any(|p| p.to_str().unwrap().contains("new.js")));
}

#[test]
fn test_incremental_with_deletions() {
    let temp_dir = TempDir::new().unwrap();
    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    let config = CacheConfig {
        cache_dir: temp_dir.path().join(".gittera/cache"),
        content_hashing: true,
        ttl_seconds: 0,
        max_size_mb: 100,
    };

    // Create and scan files
    let file1 = src_dir.join("temp.js");
    fs::write(&file1, "const x = 1;").unwrap();

    let mut cache = Cache::new(config.clone()).unwrap();
    cache.get_changed_files(&src_dir).unwrap();
    cache.save().unwrap();

    // Delete file
    fs::remove_file(&file1).unwrap();

    // Rescan - deleted file won't be in results
    let mut cache2 = Cache::new(config).unwrap();
    let changed = cache2.get_changed_files(&src_dir).unwrap();

    // Deleted files are simply not present, not marked as "changed"
    assert_eq!(changed.len(), 0);
}

#[test]
fn test_cache_persistence_across_restarts() {
    let temp_dir = TempDir::new().unwrap();
    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    let cache_dir = temp_dir.path().join(".gittera/cache");
    let config = CacheConfig {
        cache_dir: cache_dir.clone(),
        content_hashing: true,
        ttl_seconds: 0,
        max_size_mb: 100,
    };

    // Create files
    fs::write(src_dir.join("file1.js"), "const a = 1;").unwrap();
    fs::write(src_dir.join("file2.js"), "const b = 2;").unwrap();

    // First instance - scan and save
    {
        let mut cache = Cache::new(config.clone()).unwrap();
        let changed = cache.get_changed_files(&src_dir).unwrap();
        assert_eq!(changed.len(), 2);
        cache.save().unwrap();
    }

    // Second instance - should load previous state
    {
        let mut cache = Cache::new(config.clone()).unwrap();
        let changed = cache.get_changed_files(&src_dir).unwrap();
        assert_eq!(changed.len(), 0, "Cache should persist across instances");
    }

    // Verify cache files exist
    assert!(cache_dir.join("file_index.json").exists());
    assert!(cache_dir.join("results.json").exists());
}

// ============================================================================
// Baseline Workflow Tests
// ============================================================================

#[test]
fn test_baseline_workflow_end_to_end() {
    let temp_dir = TempDir::new().unwrap();
    let baseline_file = temp_dir.path().join(".gittera/baseline.json");
    fs::create_dir_all(baseline_file.parent().unwrap()).unwrap();

    // === Step 1: Initial scan with findings ===
    let initial_findings = vec![
        create_finding("app.js", 10, "sql-injection"),
        create_finding("app.js", 20, "xss"),
    ];

    // Create baseline
    let config = BaselineConfig {
        baseline_file: baseline_file.clone(),
        enabled: true,
        track_fixed: true,
    };

    let mut manager = BaselineManager::new(config.clone()).unwrap();
    manager.create_baseline(&initial_findings, Some("Initial scan".to_string())).unwrap();
    manager.save().unwrap();

    assert!(baseline_file.exists(), "Baseline file should be created");

    // === Step 2: Rescan with same findings ===
    let mut manager2 = BaselineManager::new(config.clone()).unwrap();
    manager2.load().unwrap();

    let same_scan = vec![
        create_finding("app.js", 10, "sql-injection"),
        create_finding("app.js", 20, "xss"),
    ];

    let new_findings = manager2.filter_new_findings(&same_scan);
    assert_eq!(new_findings.len(), 0, "Same findings should be filtered out");

    // === Step 3: New vulnerability introduced ===
    let scan_with_new_vuln = vec![
        create_finding("app.js", 10, "sql-injection"), // Baseline
        create_finding("app.js", 20, "xss"),           // Baseline
        create_finding("app.js", 30, "command-injection"), // NEW
    ];

    let new_findings2 = manager2.filter_new_findings(&scan_with_new_vuln);
    assert_eq!(new_findings2.len(), 1, "Only new vulnerability should be reported");
    assert_eq!(new_findings2[0].rule_id, "command-injection");
    assert_eq!(new_findings2[0].line, 30);

    // === Step 4: Vulnerability fixed ===
    let scan_after_fix = vec![
        create_finding("app.js", 10, "sql-injection"), // Still there
        // XSS at line 20 was fixed
        create_finding("app.js", 30, "command-injection"), // Still there
    ];

    let fixed = manager2.find_fixed_findings(&scan_after_fix);
    assert_eq!(fixed.len(), 1, "Should detect fixed vulnerability");
    assert_eq!(fixed[0].rule_id, "xss");
}

#[test]
fn test_baseline_empty_then_populate() {
    let temp_dir = TempDir::new().unwrap();
    let baseline_file = temp_dir.path().join("baseline.json");

    let config = BaselineConfig {
        baseline_file: baseline_file.clone(),
        enabled: true,
        track_fixed: true,
    };

    // Create empty baseline
    let mut manager = BaselineManager::new(config.clone()).unwrap();
    manager.create_baseline(&[], Some("Empty initial state".to_string())).unwrap();
    manager.save().unwrap();

    // All findings should be "new" with empty baseline
    let findings = vec![
        create_finding("test.js", 10, "sql-injection"),
        create_finding("test.js", 20, "xss"),
    ];

    let new_findings = manager.filter_new_findings(&findings);
    assert_eq!(new_findings.len(), 2, "All findings are new with empty baseline");
}

// ============================================================================
// Combined Cache + Baseline Workflow Tests
// ============================================================================

#[test]
fn test_combined_incremental_and_baseline() {
    let temp_dir = TempDir::new().unwrap();
    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    // Setup cache
    let cache_config = CacheConfig {
        cache_dir: temp_dir.path().join(".gittera/cache"),
        content_hashing: true,
        ttl_seconds: 0,
        max_size_mb: 100,
    };

    // Setup baseline
    let baseline_config = BaselineConfig {
        baseline_file: temp_dir.path().join(".gittera/baseline.json"),
        enabled: true,
        track_fixed: true,
    };

    // Create files
    let file1 = src_dir.join("app.js");
    let file2 = src_dir.join("utils.js");
    fs::write(&file1, "eval(userInput);").unwrap();
    fs::write(&file2, "const safe = 1;").unwrap();

    // === Initial scan ===
    let mut cache = Cache::new(cache_config.clone()).unwrap();
    let changed_files = cache.get_changed_files(&src_dir).unwrap();
    assert_eq!(changed_files.len(), 2);

    // Simulate finding vulnerabilities in changed files
    let findings = vec![
        create_finding("app.js", 1, "code-injection"),
    ];

    // Create baseline
    let mut baseline = BaselineManager::new(baseline_config.clone()).unwrap();
    baseline.create_baseline(&findings, None).unwrap();
    baseline.save().unwrap();

    cache.save().unwrap();

    // === Second scan - no changes ===
    let mut cache2 = Cache::new(cache_config.clone()).unwrap();
    let changed_files2 = cache2.get_changed_files(&src_dir).unwrap();
    assert_eq!(changed_files2.len(), 0, "No file changes");

    // Baseline should filter out existing finding
    let mut baseline2 = BaselineManager::new(baseline_config.clone()).unwrap();
    baseline2.load().unwrap();
    let new_findings = baseline2.filter_new_findings(&findings);
    assert_eq!(new_findings.len(), 0, "Baseline filters existing finding");

    // === Third scan - modify file ===
    thread::sleep(Duration::from_millis(10));
    fs::write(&file1, "eval(userInput); document.write(data);").unwrap();

    let mut cache3 = Cache::new(cache_config).unwrap();
    let changed_files3 = cache3.get_changed_files(&src_dir).unwrap();
    assert_eq!(changed_files3.len(), 1, "Modified file detected");

    // New vulnerability in modified file
    let new_scan = vec![
        create_finding("app.js", 1, "code-injection"), // Baseline
        create_finding("app.js", 1, "xss"),            // NEW (different rule)
    ];

    let new_findings2 = baseline2.filter_new_findings(&new_scan);
    assert_eq!(new_findings2.len(), 1, "Only new XSS should be reported");
    assert_eq!(new_findings2[0].rule_id, "xss");
}

#[test]
fn test_baseline_with_multiple_files() {
    let temp_dir = TempDir::new().unwrap();
    let baseline_file = temp_dir.path().join("baseline.json");

    let config = BaselineConfig {
        baseline_file,
        enabled: true,
        track_fixed: true,
    };

    // Create baseline with findings across multiple files
    let baseline_findings = vec![
        create_finding("file1.js", 10, "sql-injection"),
        create_finding("file1.js", 20, "xss"),
        create_finding("file2.js", 15, "command-injection"),
        create_finding("file3.js", 5, "path-traversal"),
    ];

    let mut manager = BaselineManager::new(config).unwrap();
    manager.create_baseline(&baseline_findings, None).unwrap();

    // New scan with some baseline + some new
    let new_scan = vec![
        create_finding("file1.js", 10, "sql-injection"),    // Baseline
        create_finding("file1.js", 25, "xss"),              // NEW (different line)
        create_finding("file2.js", 15, "command-injection"), // Baseline
        create_finding("file4.js", 8, "xxe"),               // NEW (new file)
    ];

    let new_findings = manager.filter_new_findings(&new_scan);

    // Should report 2 new findings
    assert_eq!(new_findings.len(), 2);
    assert!(new_findings.iter().any(|f| f.rule_id == "xss" && f.line == 25));
    assert!(new_findings.iter().any(|f| f.rule_id == "xxe"));

    // Fixed findings (file3.js path-traversal and file1.js xss at line 20)
    let fixed = manager.find_fixed_findings(&new_scan);
    assert_eq!(fixed.len(), 2);
    assert!(fixed.iter().any(|f| f.rule_id == "path-traversal"));
    assert!(fixed.iter().any(|f| f.rule_id == "xss" && f.line == 20));
}
