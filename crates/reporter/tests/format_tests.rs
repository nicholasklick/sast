use gittera_reporter::{Report, Reporter, ReportFormat};
use gittera_query::Finding;
use serde_json::Value;

/// Helper function to create a test finding
fn create_finding(
    file_path: &str,
    line: usize,
    message: &str,
    severity: &str,
    rule_id: &str,
) -> Finding {
    Finding {
        file_path: file_path.to_string(),
        line,
        column: 5,
        message: message.to_string(),
        severity: severity.to_string(),
        code_snippet: format!("// Code at {}:{}", file_path, line),
        category: "test".to_string(),
        rule_id: rule_id.to_string(),
        cwes: vec![],
        owasp: None,
    }
}

// ============================================================================
// JSON Format Tests
// ============================================================================

#[test]
fn test_json_output_basic_structure() {
    let findings = vec![create_finding(
        "test.js",
        10,
        "Test vulnerability",
        "High",
        "test-rule",
    )];

    let report = Report::new(findings);
    let mut output = Vec::new();

    Reporter::write_report(&report, ReportFormat::Json, &mut output)
        .expect("Failed to generate JSON");

    let json: Value = serde_json::from_slice(&output).expect("Invalid JSON");

    // Verify basic structure
    assert!(json["summary"].is_object());
    assert!(json["findings"].is_array());
}

#[test]
fn test_json_summary_statistics() {
    let findings = vec![
        create_finding("test1.js", 10, "Critical vuln", "Critical", "crit-1"),
        create_finding("test2.js", 20, "Critical vuln 2", "Critical", "crit-2"),
        create_finding("test3.js", 30, "High vuln", "High", "high-1"),
        create_finding("test4.js", 40, "Medium vuln", "Medium", "med-1"),
        create_finding("test5.js", 50, "Low vuln", "Low", "low-1"),
    ];

    let report = Report::new(findings);
    let mut output = Vec::new();

    Reporter::write_report(&report, ReportFormat::Json, &mut output)
        .expect("Failed to generate JSON");

    let json: Value = serde_json::from_slice(&output).expect("Invalid JSON");
    let summary = &json["summary"];

    assert_eq!(summary["total_findings"], 5);
    assert_eq!(summary["critical"], 2);
    assert_eq!(summary["high"], 1);
    assert_eq!(summary["medium"], 1);
    assert_eq!(summary["low"], 1);
}

#[test]
fn test_json_findings_array() {
    let findings = vec![
        create_finding("test.js", 10, "SQL injection", "High", "sql-injection"),
        create_finding("test.js", 20, "XSS vulnerability", "High", "xss"),
    ];

    let report = Report::new(findings);
    let mut output = Vec::new();

    Reporter::write_report(&report, ReportFormat::Json, &mut output)
        .expect("Failed to generate JSON");

    let json: Value = serde_json::from_slice(&output).expect("Invalid JSON");
    let findings_array = json["findings"].as_array().unwrap();

    assert_eq!(findings_array.len(), 2);

    // Verify first finding
    let finding1 = &findings_array[0];
    assert_eq!(finding1["file_path"], "test.js");
    assert_eq!(finding1["line"], 10);
    assert_eq!(finding1["severity"], "High");
    assert_eq!(finding1["rule_id"], "sql-injection");
    assert!(finding1["message"].as_str().unwrap().contains("SQL injection"));
}

#[test]
fn test_json_empty_findings() {
    let report = Report::new(vec![]);
    let mut output = Vec::new();

    Reporter::write_report(&report, ReportFormat::Json, &mut output)
        .expect("Failed to generate JSON");

    let json: Value = serde_json::from_slice(&output).expect("Invalid JSON");

    assert_eq!(json["summary"]["total_findings"], 0);
    assert_eq!(json["summary"]["critical"], 0);
    assert_eq!(json["summary"]["high"], 0);
    assert_eq!(json["summary"]["medium"], 0);
    assert_eq!(json["summary"]["low"], 0);
    assert_eq!(json["findings"].as_array().unwrap().len(), 0);
}

#[test]
fn test_json_preserves_all_finding_fields() {
    let mut finding = create_finding(
        "src/app.js",
        42,
        "Detailed vulnerability description",
        "Critical",
        "test-vuln-1",
    );
    finding.code_snippet = "const x = eval(userInput);".to_string();
    finding.column = 15;
    finding.category = "injection".to_string();

    let report = Report::new(vec![finding]);
    let mut output = Vec::new();

    Reporter::write_report(&report, ReportFormat::Json, &mut output)
        .expect("Failed to generate JSON");

    let json: Value = serde_json::from_slice(&output).expect("Invalid JSON");
    let finding_json = &json["findings"][0];

    // Verify all fields are preserved
    assert_eq!(finding_json["file_path"], "src/app.js");
    assert_eq!(finding_json["line"], 42);
    assert_eq!(finding_json["column"], 15);
    assert_eq!(finding_json["severity"], "Critical");
    assert_eq!(finding_json["rule_id"], "test-vuln-1");
    assert_eq!(finding_json["category"], "injection");
    assert!(finding_json["message"]
        .as_str()
        .unwrap()
        .contains("Detailed vulnerability"));
    assert_eq!(finding_json["code_snippet"], "const x = eval(userInput);");
}

// ============================================================================
// Text Format Tests
// ============================================================================

#[test]
fn test_text_output_basic_format() {
    let findings = vec![create_finding(
        "test.js",
        10,
        "SQL injection vulnerability",
        "High",
        "sql-injection",
    )];

    let report = Report::new(findings);
    let mut output = Vec::new();

    Reporter::write_report(&report, ReportFormat::Text, &mut output)
        .expect("Failed to generate text");

    let text = String::from_utf8(output).expect("Invalid UTF-8");

    // Verify text contains key information
    assert!(text.contains("test.js"));
    assert!(text.contains("10")); // Line number
    assert!(text.contains("SQL injection"));
    assert!(text.contains("High"));
}

#[test]
fn test_text_output_summary() {
    let findings = vec![
        create_finding("test1.js", 10, "Critical issue", "Critical", "crit-1"),
        create_finding("test2.js", 20, "High issue", "High", "high-1"),
        create_finding("test3.js", 30, "Medium issue", "Medium", "med-1"),
    ];

    let report = Report::new(findings);
    let mut output = Vec::new();

    Reporter::write_report(&report, ReportFormat::Text, &mut output)
        .expect("Failed to generate text");

    let text = String::from_utf8(output).expect("Invalid UTF-8");

    // Verify summary section
    assert!(text.contains("Summary") || text.contains("SUMMARY"));
    assert!(text.contains("Total") || text.contains("total"));
    assert!(text.contains("3")); // Total findings

    // Verify severity counts
    assert!(text.contains("Critical") || text.contains("critical"));
    assert!(text.contains("High") || text.contains("high"));
    assert!(text.contains("Medium") || text.contains("medium"));
}

#[test]
fn test_text_output_multiple_findings() {
    let findings = vec![
        create_finding("app.js", 15, "SQL injection", "High", "sql-1"),
        create_finding("render.js", 42, "XSS vulnerability", "High", "xss-1"),
        create_finding("crypto.js", 7, "Weak encryption", "Medium", "crypto-1"),
    ];

    let report = Report::new(findings);
    let mut output = Vec::new();

    Reporter::write_report(&report, ReportFormat::Text, &mut output)
        .expect("Failed to generate text");

    let text = String::from_utf8(output).expect("Invalid UTF-8");

    // All findings should be present
    assert!(text.contains("app.js"));
    assert!(text.contains("render.js"));
    assert!(text.contains("crypto.js"));

    assert!(text.contains("SQL injection"));
    assert!(text.contains("XSS vulnerability"));
    assert!(text.contains("Weak encryption"));
}

#[test]
fn test_text_output_empty_findings() {
    let report = Report::new(vec![]);
    let mut output = Vec::new();

    Reporter::write_report(&report, ReportFormat::Text, &mut output)
        .expect("Failed to generate text");

    let text = String::from_utf8(output).expect("Invalid UTF-8");

    // Should indicate no findings
    assert!(
        text.contains("Total Findings: 0") ||
        text.contains("No findings") ||
        text.contains("0 vulnerabilities")
    );
}

#[test]
fn test_text_output_human_readable() {
    let finding = create_finding(
        "src/vulnerable.js",
        123,
        "Path traversal vulnerability: User input flows to fs.readFile without validation",
        "High",
        "path-traversal",
    );

    let report = Report::new(vec![finding]);
    let mut output = Vec::new();

    Reporter::write_report(&report, ReportFormat::Text, &mut output)
        .expect("Failed to generate text");

    let text = String::from_utf8(output).expect("Invalid UTF-8");

    // Verify human-readable format
    // Should have file:line format
    assert!(text.contains("vulnerable.js") && text.contains("123"));

    // Should show severity prominently
    assert!(text.contains("High"));

    // Should include message
    assert!(text.contains("Path traversal"));
}
