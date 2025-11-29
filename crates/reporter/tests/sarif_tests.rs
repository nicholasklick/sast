use gittera_reporter::{Report, Reporter, ReportFormat};
use gittera_query::Finding;
use serde_json::Value;

/// Helper function to create a test finding
fn create_finding(
    file_path: &str,
    line: usize,
    column: usize,
    message: &str,
    severity: &str,
    category: &str,
    rule_id: &str,
) -> Finding {
    Finding {
        file_path: file_path.to_string(),
        line,
        column,
        message: message.to_string(),
        severity: severity.to_string(),
        code_snippet: format!("// Code at {}:{}", file_path, line),
        category: category.to_string(),
        rule_id: rule_id.to_string(),
    }
}

/// Helper to create SQL injection finding
fn create_sql_injection_vuln() -> Finding {
    create_finding(
        "src/database.js",
        42,
        10,
        "SQL injection vulnerability: User input flows to database.execute() without sanitization",
        "High",
        "injection",
        "sql-injection",
    )
}

/// Helper to create XSS finding
fn create_xss_vuln() -> Finding {
    create_finding(
        "src/render.js",
        15,
        5,
        "Cross-site scripting (XSS) vulnerability: User input flows to document.write() without escaping",
        "High",
        "injection",
        "xss",
    )
}

/// Helper to create command injection finding
fn create_command_injection_vuln() -> Finding {
    create_finding(
        "src/exec.js",
        28,
        8,
        "Command injection vulnerability: User input flows to child_process.exec() without validation",
        "Critical",
        "injection",
        "command-injection",
    )
}

/// Helper to create finding with specific severity
fn create_vuln_with_severity(severity: &str) -> Finding {
    create_finding(
        "test.js",
        10,
        5,
        &format!("Test vulnerability with {} severity", severity),
        severity,
        "test",
        "test-rule",
    )
}

/// Parse SARIF JSON output
fn parse_sarif(output: &[u8]) -> Value {
    serde_json::from_slice(output).expect("Failed to parse SARIF JSON")
}

#[test]
fn test_sarif_basic_structure() {
    let report = Report::new(vec![]);
    let mut output = Vec::new();

    Reporter::write_report(&report, ReportFormat::Sarif, &mut output)
        .expect("Failed to generate SARIF");

    let sarif = parse_sarif(&output);

    // Verify SARIF 2.1.0 structure
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(
        sarif["$schema"],
        "https://json.schemastore.org/sarif-2.1.0.json"
    );
    assert!(sarif["runs"].is_array());
    assert_eq!(sarif["runs"].as_array().unwrap().len(), 1);
}

#[test]
fn test_sarif_tool_metadata() {
    let report = Report::new(vec![]);
    let mut output = Vec::new();

    Reporter::write_report(&report, ReportFormat::Sarif, &mut output)
        .expect("Failed to generate SARIF");

    let sarif = parse_sarif(&output);
    let tool = &sarif["runs"][0]["tool"]["driver"];

    assert_eq!(tool["name"], "Gittera SAST");
    assert!(tool["informationUri"].as_str().is_some());
    assert!(tool["version"].as_str().is_some());
    assert_eq!(tool["organization"], "Gittera");

    // Verify descriptions
    assert!(tool["shortDescription"]["text"].as_str().is_some());
    assert!(tool["fullDescription"]["text"].as_str().is_some());
}

#[test]
fn test_sarif_single_finding() {
    let vuln = create_sql_injection_vuln();
    let report = Report::new(vec![vuln]);
    let mut output = Vec::new();

    Reporter::write_report(&report, ReportFormat::Sarif, &mut output)
        .expect("Failed to generate SARIF");

    let sarif = parse_sarif(&output);
    let results = sarif["runs"][0]["results"].as_array().unwrap();

    assert_eq!(results.len(), 1);
    let result = &results[0];

    // Verify rule ID
    assert_eq!(result["ruleId"], "sql-injection");

    // Verify message
    assert!(result["message"]["text"]
        .as_str()
        .unwrap()
        .contains("SQL injection"));

    // Verify location
    let location = &result["locations"][0]["physicalLocation"];
    assert_eq!(
        location["artifactLocation"]["uri"],
        "src/database.js"
    );
    assert_eq!(location["region"]["startLine"], 42);
    assert_eq!(location["region"]["startColumn"], 10);
}

#[test]
fn test_sarif_multiple_findings() {
    let vulns = vec![
        create_sql_injection_vuln(),
        create_xss_vuln(),
        create_command_injection_vuln(),
    ];

    let report = Report::new(vulns);
    let mut output = Vec::new();

    Reporter::write_report(&report, ReportFormat::Sarif, &mut output)
        .expect("Failed to generate SARIF");

    let sarif = parse_sarif(&output);
    let results = sarif["runs"][0]["results"].as_array().unwrap();

    assert_eq!(results.len(), 3);

    // Verify different rule IDs
    let rule_ids: Vec<&str> = results
        .iter()
        .map(|r| r["ruleId"].as_str().unwrap())
        .collect();

    assert!(rule_ids.contains(&"sql-injection"));
    assert!(rule_ids.contains(&"xss"));
    assert!(rule_ids.contains(&"command-injection"));
}

#[test]
fn test_sarif_severity_mapping() {
    let findings = vec![
        create_vuln_with_severity("Critical"),
        create_vuln_with_severity("High"),
        create_vuln_with_severity("Medium"),
        create_vuln_with_severity("Low"),
    ];

    let report = Report::new(findings);
    let mut output = Vec::new();

    Reporter::write_report(&report, ReportFormat::Sarif, &mut output)
        .expect("Failed to generate SARIF");

    let sarif = parse_sarif(&output);
    let results = sarif["runs"][0]["results"].as_array().unwrap();

    assert_eq!(results.len(), 4);

    // Verify severity level mapping
    assert_eq!(results[0]["level"], "error"); // Critical -> error
    assert_eq!(results[1]["level"], "error"); // High -> error
    assert_eq!(results[2]["level"], "warning"); // Medium -> warning
    assert_eq!(results[3]["level"], "note"); // Low -> note
}

#[test]
fn test_sarif_rules_section() {
    let findings = vec![
        create_sql_injection_vuln(),
        create_xss_vuln(),
        // Duplicate SQL injection - should only appear once in rules
        create_finding(
            "other.js",
            99,
            1,
            "Another SQL injection",
            "High",
            "injection",
            "sql-injection",
        ),
    ];

    let report = Report::new(findings);
    let mut output = Vec::new();

    Reporter::write_report(&report, ReportFormat::Sarif, &mut output)
        .expect("Failed to generate SARIF");

    let sarif = parse_sarif(&output);
    let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();

    // Should have 2 unique rules (sql-injection and xss)
    assert_eq!(rules.len(), 2);

    // Verify rule structure
    for rule in rules {
        assert!(rule["id"].as_str().is_some());
        assert!(rule["name"].as_str().is_some());
        assert!(rule["shortDescription"]["text"].as_str().is_some());
        assert!(rule["fullDescription"]["text"].as_str().is_some());
        assert!(rule["help"]["text"].as_str().is_some());
        assert!(rule["helpUri"].as_str().is_some());
    }
}

#[test]
fn test_sarif_taxonomies_present() {
    let report = Report::new(vec![create_sql_injection_vuln()]);
    let mut output = Vec::new();

    Reporter::write_report(&report, ReportFormat::Sarif, &mut output)
        .expect("Failed to generate SARIF");

    let sarif = parse_sarif(&output);
    let taxonomies = &sarif["runs"][0]["tool"]["driver"]["taxa"];

    assert!(taxonomies.is_array());
    let taxonomies_array = taxonomies.as_array().unwrap();

    // Should have taxonomies (OWASP, CWE, etc.)
    assert!(!taxonomies_array.is_empty());

    // Verify taxonomy structure (these are top-level taxonomies)
    for taxonomy in taxonomies_array {
        assert!(taxonomy["name"].as_str().is_some());
        assert!(taxonomy["guid"].as_str().is_some());
        assert!(taxonomy["organization"].as_str().is_some());
    }

    // Verify OWASP Top 10 taxonomy specifically
    let owasp = taxonomies_array
        .iter()
        .find(|t| t["name"].as_str() == Some("OWASP Top 10 2021"));
    assert!(owasp.is_some());

    // Verify it has taxa (actual categories)
    let owasp_taxa = &owasp.unwrap()["taxa"];
    assert!(owasp_taxa.is_array());
    assert!(owasp_taxa.as_array().unwrap().len() == 10); // OWASP Top 10
}

#[test]
fn test_sarif_summary_statistics() {
    let findings = vec![
        create_vuln_with_severity("Critical"),
        create_vuln_with_severity("Critical"),
        create_vuln_with_severity("High"),
        create_vuln_with_severity("Medium"),
        create_vuln_with_severity("Low"),
    ];

    let report = Report::new(findings);
    let mut output = Vec::new();

    Reporter::write_report(&report, ReportFormat::Sarif, &mut output)
        .expect("Failed to generate SARIF");

    let sarif = parse_sarif(&output);
    let summary = &sarif["runs"][0]["properties"]["summary"];

    assert_eq!(summary["totalFindings"], 5);
    assert_eq!(summary["critical"], 2);
    assert_eq!(summary["high"], 1);
    assert_eq!(summary["medium"], 1);
    assert_eq!(summary["low"], 1);
}

#[test]
fn test_sarif_schema_validation() {
    let report = Report::new(vec![create_sql_injection_vuln()]);
    let mut output = Vec::new();

    Reporter::write_report(&report, ReportFormat::Sarif, &mut output)
        .expect("Failed to generate SARIF");

    let sarif = parse_sarif(&output);

    // Verify required top-level fields
    assert!(sarif["version"].is_string());
    assert!(sarif["$schema"].is_string());
    assert!(sarif["runs"].is_array());

    // Verify run structure
    let run = &sarif["runs"][0];
    assert!(run["tool"].is_object());
    assert!(run["results"].is_array());

    // Verify tool structure
    let tool = &run["tool"]["driver"];
    assert!(tool["name"].is_string());
    assert!(tool["version"].is_string());
    assert!(tool["informationUri"].is_string());
    assert!(tool["rules"].is_array());
}

#[test]
fn test_sarif_empty_findings() {
    let report = Report::new(vec![]);
    let mut output = Vec::new();

    Reporter::write_report(&report, ReportFormat::Sarif, &mut output)
        .expect("Failed to generate SARIF");

    let sarif = parse_sarif(&output);

    // Should still be valid SARIF
    assert_eq!(sarif["version"], "2.1.0");

    let results = sarif["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 0);

    let summary = &sarif["runs"][0]["properties"]["summary"];
    assert_eq!(summary["totalFindings"], 0);
    assert_eq!(summary["critical"], 0);
    assert_eq!(summary["high"], 0);
    assert_eq!(summary["medium"], 0);
    assert_eq!(summary["low"], 0);
}

#[test]
fn test_sarif_code_snippet_inclusion() {
    let mut finding = create_sql_injection_vuln();
    finding.code_snippet = "const query = 'SELECT * FROM users WHERE id=' + userId;".to_string();

    let report = Report::new(vec![finding]);
    let mut output = Vec::new();

    Reporter::write_report(&report, ReportFormat::Sarif, &mut output)
        .expect("Failed to generate SARIF");

    let sarif = parse_sarif(&output);
    let result = &sarif["runs"][0]["results"][0];
    let snippet = &result["locations"][0]["physicalLocation"]["region"]["snippet"];

    assert!(snippet["text"].as_str().is_some());
    assert!(snippet["text"]
        .as_str()
        .unwrap()
        .contains("SELECT * FROM users"));
}

#[test]
fn test_sarif_category_classification() {
    let findings = vec![
        create_finding("test.js", 1, 1, "Injection", "High", "injection", "sql-1"),
        create_finding("test.js", 2, 1, "Crypto", "Medium", "crypto", "weak-crypto"),
        create_finding("test.js", 3, 1, "Secret", "Critical", "secrets", "hardcoded-secret"),
    ];

    let report = Report::new(findings);
    let mut output = Vec::new();

    Reporter::write_report(&report, ReportFormat::Sarif, &mut output)
        .expect("Failed to generate SARIF");

    let sarif = parse_sarif(&output);
    let results = sarif["runs"][0]["results"].as_array().unwrap();

    // Verify all findings are present
    assert_eq!(results.len(), 3);

    // Verify categories are preserved in rule properties
    let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();
    assert_eq!(rules.len(), 3);
}

#[test]
fn test_sarif_properties_metadata() {
    let report = Report::new(vec![]);
    let mut output = Vec::new();

    Reporter::write_report(&report, ReportFormat::Sarif, &mut output)
        .expect("Failed to generate SARIF");

    let sarif = parse_sarif(&output);
    let properties = &sarif["runs"][0]["tool"]["driver"]["properties"];

    // Verify metadata properties
    assert!(properties["totalRules"].is_number());
    assert!(properties["supportedLanguages"].is_array());
    assert!(properties["owaspCoverage"].is_string());
    assert!(properties["cweCoverage"].is_string());

    // Verify supported languages
    let languages = properties["supportedLanguages"].as_array().unwrap();
    assert!(languages.len() >= 10); // Should support at least 10 languages
}
