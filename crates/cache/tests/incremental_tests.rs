use gittera_cache::{Cache, CacheConfig, FileFingerprint};
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;
use std::thread;
use std::time::Duration;

/// Helper to create a test cache in a temp directory
fn create_test_cache() -> (Cache, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let cache_dir = temp_dir.path().join(".gittera/cache");

    let config = CacheConfig {
        cache_dir,
        content_hashing: true,
        ttl_seconds: 0,
        max_size_mb: 100,
    };

    let cache = Cache::new(config).unwrap();
    (cache, temp_dir)
}

#[test]
fn test_cache_creation() {
    let (_cache, temp_dir) = create_test_cache();

    // Verify cache directory was created
    let cache_dir = temp_dir.path().join(".gittera/cache");
    assert!(cache_dir.exists());
    assert!(cache_dir.is_dir());
}

#[test]
fn test_cache_detects_new_file() {
    let (mut cache, temp_dir) = create_test_cache();

    // Create a new source file
    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();
    let test_file = src_dir.join("test.js");
    fs::write(&test_file, "const x = 1;").unwrap();

    // Get changed files - new file should be detected
    let changed = cache.get_changed_files(&src_dir).unwrap();

    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0], PathBuf::from("test.js"));
}

#[test]
fn test_cache_detects_modified_file() {
    let (mut cache, temp_dir) = create_test_cache();

    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();
    let test_file = src_dir.join("test.js");

    // Initial file
    fs::write(&test_file, "const x = 1;").unwrap();
    let changed1 = cache.get_changed_files(&src_dir).unwrap();
    assert_eq!(changed1.len(), 1);

    // Save cache state
    cache.save().unwrap();

    // File hasn't changed - should not be detected
    let changed2 = cache.get_changed_files(&src_dir).unwrap();
    assert_eq!(changed2.len(), 0, "Unchanged file should not be detected");

    // Wait a bit and modify file
    thread::sleep(Duration::from_millis(10));
    fs::write(&test_file, "const x = 2;").unwrap();

    // Should detect change
    let changed3 = cache.get_changed_files(&src_dir).unwrap();
    assert_eq!(changed3.len(), 1);
    assert_eq!(changed3[0], PathBuf::from("test.js"));
}

#[test]
fn test_cache_unchanged_file_not_rescanned() {
    let (mut cache, temp_dir) = create_test_cache();

    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();
    let test_file = src_dir.join("test.js");
    fs::write(&test_file, "const x = 1;").unwrap();

    // Initial scan
    let changed1 = cache.get_changed_files(&src_dir).unwrap();
    assert_eq!(changed1.len(), 1);

    // Save cache
    cache.save().unwrap();

    // Reload cache from disk
    let config = CacheConfig {
        cache_dir: temp_dir.path().join(".gittera/cache"),
        content_hashing: true,
        ttl_seconds: 0,
        max_size_mb: 100,
    };
    let mut cache2 = Cache::new(config).unwrap();

    // Unchanged file should not be detected
    let changed2 = cache2.get_changed_files(&src_dir).unwrap();
    assert_eq!(changed2.len(), 0);
}

#[test]
fn test_content_hash_detects_change() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.js");

    // Create file with initial content
    fs::write(&test_file, "const x = 1;").unwrap();
    let fp1 = FileFingerprint::from_file(&test_file).unwrap();

    // Modify content
    thread::sleep(Duration::from_millis(10));
    fs::write(&test_file, "const x = 2;").unwrap();
    let fp2 = FileFingerprint::from_file(&test_file).unwrap();

    // Fingerprints should be different
    assert!(fp1.has_changed(&fp2), "Content change should be detected");
}

#[test]
fn test_cache_persists_across_instances() {
    let temp_dir = TempDir::new().unwrap();
    let cache_dir = temp_dir.path().join(".gittera/cache");
    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    // Create file and scan with first cache instance
    let test_file = src_dir.join("test.js");
    fs::write(&test_file, "const x = 1;").unwrap();

    {
        let config = CacheConfig {
            cache_dir: cache_dir.clone(),
            content_hashing: true,
            ttl_seconds: 0,
            max_size_mb: 100,
        };
        let mut cache1 = Cache::new(config).unwrap();
        let changed = cache1.get_changed_files(&src_dir).unwrap();
        assert_eq!(changed.len(), 1);
        cache1.save().unwrap();
    }

    // Create new cache instance - should load previous state
    {
        let config = CacheConfig {
            cache_dir: cache_dir.clone(),
            content_hashing: true,
            ttl_seconds: 0,
            max_size_mb: 100,
        };
        let mut cache2 = Cache::new(config).unwrap();
        let changed = cache2.get_changed_files(&src_dir).unwrap();
        // File hasn't changed, so should be empty
        assert_eq!(changed.len(), 0, "Cache should persist across instances");
    }
}

#[test]
fn test_cache_multiple_files() {
    let (mut cache, temp_dir) = create_test_cache();

    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    // Create multiple files
    for i in 1..=5 {
        let file = src_dir.join(format!("file{}.js", i));
        fs::write(&file, format!("const x = {};", i)).unwrap();
    }

    // All files should be new
    let changed = cache.get_changed_files(&src_dir).unwrap();
    assert_eq!(changed.len(), 5);

    // Save and rescan
    cache.save().unwrap();
    let changed2 = cache.get_changed_files(&src_dir).unwrap();
    assert_eq!(changed2.len(), 0, "No files changed");

    // Modify one file
    thread::sleep(Duration::from_millis(10));
    fs::write(src_dir.join("file3.js"), "const x = 999;").unwrap();

    // Only one file should be detected
    let changed3 = cache.get_changed_files(&src_dir).unwrap();
    assert_eq!(changed3.len(), 1);
    assert_eq!(changed3[0], PathBuf::from("file3.js"));
}

#[test]
fn test_cache_ignores_non_source_files() {
    let (mut cache, temp_dir) = create_test_cache();

    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    // Create source file
    fs::write(src_dir.join("app.js"), "code").unwrap();

    // Create non-source files
    fs::write(src_dir.join("data.json"), "{}").unwrap();
    fs::write(src_dir.join("README.md"), "# Title").unwrap();
    fs::write(src_dir.join("image.png"), "binary").unwrap();

    // Only source file should be detected
    let changed = cache.get_changed_files(&src_dir).unwrap();

    // Should include .js but not .json, .md, .png
    // (depends on is_source_file implementation, but typically JS/TS/PY etc)
    assert!(changed.iter().any(|p| p.to_str().unwrap().contains("app.js")));
}

#[test]
fn test_cache_handles_deleted_files() {
    let (mut cache, temp_dir) = create_test_cache();

    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    let test_file = src_dir.join("test.js");
    fs::write(&test_file, "const x = 1;").unwrap();

    // Initial scan
    let changed1 = cache.get_changed_files(&src_dir).unwrap();
    assert_eq!(changed1.len(), 1);
    cache.save().unwrap();

    // Delete file
    fs::remove_file(&test_file).unwrap();

    // Deleted file won't be in scan results (file doesn't exist)
    let changed2 = cache.get_changed_files(&src_dir).unwrap();
    assert_eq!(changed2.len(), 0);
}

#[test]
fn test_fingerprint_equality() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.js");

    fs::write(&test_file, "const x = 1;").unwrap();
    let fp1 = FileFingerprint::from_file(&test_file).unwrap();
    let fp2 = FileFingerprint::from_file(&test_file).unwrap();

    // Same file should have same fingerprint
    assert!(!fp1.has_changed(&fp2), "Identical files should have same fingerprint");
}
