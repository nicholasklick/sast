use gittera_cache::{Baseline, BaselineManager, BaselineConfig};
use gittera_query::Finding;
use tempfile::TempDir;
use std::fs;

/// Helper to create a test finding
fn create_finding(
    file_path: &str,
    line: usize,
    column: usize,
    rule_id: &str,
    message: &str,
    severity: &str,
) -> Finding {
    Finding {
        file_path: file_path.to_string(),
        line,
        column,
        message: message.to_string(),
        severity: severity.to_string(),
        code_snippet: format!("code at {}:{}", file_path, line),
        category: "test".to_string(),
        rule_id: rule_id.to_string(),
        cwes: vec![],
        owasp: None,
    }
}

#[test]
fn test_baseline_creation() {
    let findings = vec![
        create_finding("test.js", 10, 5, "sql-injection", "SQL injection", "High"),
        create_finding("test.js", 20, 8, "xss", "XSS vulnerability", "High"),
    ];

    let baseline = Baseline::new(&findings, Some("Initial baseline".to_string()));

    assert_eq!(baseline.findings.len(), 2);
    assert!(baseline.description.is_some());
    assert_eq!(baseline.description.unwrap(), "Initial baseline");
    assert!(baseline.created_at > 0);
}

#[test]
fn test_baseline_save_and_load() {
    let temp_dir = TempDir::new().unwrap();
    let baseline_file = temp_dir.path().join("baseline.json");

    let findings = vec![
        create_finding("test.js", 10, 5, "sql-injection", "SQL injection", "High"),
        create_finding("app.js", 42, 3, "xss", "XSS vulnerability", "High"),
    ];

    let config = BaselineConfig {
        baseline_file: baseline_file.clone(),
        enabled: true,
        track_fixed: true,
    };

    // Create and save baseline
    let mut manager = BaselineManager::new(config).unwrap();
    manager.create_baseline(&findings, Some("Test baseline".to_string())).unwrap();
    manager.save().unwrap();

    assert!(baseline_file.exists());

    // Load baseline
    let mut manager2 = BaselineManager::new(BaselineConfig {
        baseline_file: baseline_file.clone(),
        enabled: true,
        track_fixed: true,
    }).unwrap();
    manager2.load().unwrap();

    let baseline = manager2.get_baseline().unwrap();
    assert_eq!(baseline.findings.len(), 2);
    assert_eq!(baseline.description, Some("Test baseline".to_string()));
}

#[test]
fn test_baseline_filters_existing_findings() {
    let temp_dir = TempDir::new().unwrap();
    let baseline_file = temp_dir.path().join("baseline.json");

    let baseline_findings = vec![
        create_finding("test.js", 10, 5, "sql-injection", "SQL injection", "High"),
    ];

    let config = BaselineConfig {
        baseline_file: baseline_file.clone(),
        enabled: true,
        track_fixed: true,
    };

    let mut manager = BaselineManager::new(config).unwrap();
    manager.create_baseline(&baseline_findings, None).unwrap();

    let current_findings = vec![
        create_finding("test.js", 10, 5, "sql-injection", "SQL injection", "High"), // Exists in baseline
        create_finding("test.js", 20, 8, "xss", "XSS vulnerability", "High"),       // New
    ];

    let new_findings = manager.filter_new_findings(&current_findings);

    // Should only include the XSS finding (new)
    assert_eq!(new_findings.len(), 1);
    assert_eq!(new_findings[0].line, 20);
    assert_eq!(new_findings[0].rule_id, "xss");
}

#[test]
fn test_baseline_fingerprint_stability() {
    let finding1 = create_finding("test.js", 10, 5, "sql-injection", "SQL injection", "High");
    let finding2 = create_finding("test.js", 10, 5, "sql-injection", "SQL injection", "High");

    let baseline1 = Baseline::new(&[finding1], None);
    let baseline2 = Baseline::new(&[finding2], None);

    // Same finding should have same fingerprint
    let fp1 = baseline1.findings.values().next().unwrap().fingerprint.clone();
    let fp2 = baseline2.findings.values().next().unwrap().fingerprint.clone();

    assert_eq!(fp1, fp2, "Identical findings should have same fingerprint");
}

#[test]
fn test_baseline_detects_fixed_findings() {
    let temp_dir = TempDir::new().unwrap();
    let baseline_file = temp_dir.path().join("baseline.json");

    let baseline_findings = vec![
        create_finding("test.js", 10, 5, "sql-injection", "SQL injection", "High"),
        create_finding("test.js", 20, 8, "xss", "XSS vulnerability", "High"),
    ];

    let config = BaselineConfig {
        baseline_file: baseline_file.clone(),
        enabled: true,
        track_fixed: true,
    };

    let mut manager = BaselineManager::new(config).unwrap();
    manager.create_baseline(&baseline_findings, None).unwrap();

    let current_findings = vec![
        create_finding("test.js", 10, 5, "sql-injection", "SQL injection", "High"), // Still there
        // XSS finding is missing - it was fixed
    ];

    let fixed = manager.find_fixed_findings(&current_findings);

    // Should detect that XSS was fixed
    assert_eq!(fixed.len(), 1);
    assert_eq!(fixed[0].rule_id, "xss");
}

#[test]
fn test_baseline_all_findings_in_baseline() {
    let temp_dir = TempDir::new().unwrap();
    let baseline_file = temp_dir.path().join("baseline.json");

    let findings = vec![
        create_finding("test.js", 10, 5, "sql-injection", "SQL injection", "High"),
        create_finding("test.js", 20, 8, "xss", "XSS", "High"),
    ];

    let config = BaselineConfig {
        baseline_file: baseline_file.clone(),
        enabled: true,
        track_fixed: true,
    };

    let mut manager = BaselineManager::new(config).unwrap();
    manager.create_baseline(&findings, None).unwrap();

    // Same findings - should all be filtered
    let new_findings = manager.filter_new_findings(&findings);

    assert_eq!(new_findings.len(), 0, "All findings in baseline should be filtered");
}

#[test]
fn test_baseline_manager_workflow() {
    let temp_dir = TempDir::new().unwrap();
    let baseline_file = temp_dir.path().join("baseline.json");

    let config = BaselineConfig {
        baseline_file: baseline_file.clone(),
        enabled: true,
        track_fixed: true,
    };

    let mut manager = BaselineManager::new(config).unwrap();

    // Create initial findings
    let initial_findings = vec![
        create_finding("test.js", 10, 5, "sql-injection", "SQL injection", "High"),
        create_finding("test.js", 20, 8, "xss", "XSS", "High"),
    ];

    // Create baseline
    manager.create_baseline(&initial_findings, None).unwrap();
    manager.save().unwrap();
    assert!(baseline_file.exists());

    // Load baseline
    manager.load().unwrap();
    assert!(manager.get_baseline().is_some());

    // New scan with one new finding and one existing
    let new_scan_findings = vec![
        create_finding("test.js", 10, 5, "sql-injection", "SQL injection", "High"), // Baseline
        create_finding("app.js", 30, 1, "command-injection", "Command injection", "Critical"), // New
    ];

    let filtered = manager.filter_new_findings(&new_scan_findings);

    // Should only include the command injection (new)
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].rule_id, "command-injection");
}

#[test]
fn test_baseline_empty_findings() {
    let temp_dir = TempDir::new().unwrap();
    let baseline_file = temp_dir.path().join("baseline.json");

    let config = BaselineConfig {
        baseline_file: baseline_file.clone(),
        enabled: true,
        track_fixed: true,
    };

    let mut manager = BaselineManager::new(config).unwrap();
    manager.create_baseline(&[], Some("Empty baseline".to_string())).unwrap();

    let baseline = manager.get_baseline().unwrap();
    assert_eq!(baseline.findings.len(), 0);

    let current = vec![
        create_finding("test.js", 10, 5, "sql-injection", "SQL injection", "High"),
    ];

    let new_findings = manager.filter_new_findings(&current);

    // All findings are new when baseline is empty
    assert_eq!(new_findings.len(), 1);
}

#[test]
fn test_baseline_different_locations_different_fingerprints() {
    let temp_dir = TempDir::new().unwrap();
    let baseline_file = temp_dir.path().join("baseline.json");

    let finding1 = create_finding("test.js", 10, 5, "sql-injection", "SQL injection", "High");
    let finding2 = create_finding("test.js", 20, 5, "sql-injection", "SQL injection", "High");

    let config = BaselineConfig {
        baseline_file: baseline_file.clone(),
        enabled: true,
        track_fixed: true,
    };

    let mut manager = BaselineManager::new(config).unwrap();
    let baseline_findings = vec![finding1.clone()];
    manager.create_baseline(&baseline_findings, None).unwrap();

    // Different line number should create new finding
    let current_findings = vec![finding2];
    let new_findings = manager.filter_new_findings(&current_findings);
    assert_eq!(new_findings.len(), 1, "Different line should be detected as new");
}
