# SARIF Output Format

Gittera SAST implements full SARIF 2.1.0 (Static Analysis Results Interchange Format) support for security findings, enabling seamless integration with GitHub Code Scanning, VS Code, Azure DevOps, and other SARIF-compatible tools.

## Overview

SARIF (Static Analysis Results Interchange Format) is an OASIS standard for representing static analysis tool outputs in a structured, machine-readable JSON format. Version 2.1.0 is the current industry standard.

**Specification**: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

## Features

### ✅ Full SARIF 2.1.0 Compliance

- **Schema Validation**: Adheres to official SARIF 2.1.0 JSON schema
- **Tool Metadata**: Complete driver information with version and organization
- **Rule Definitions**: Comprehensive rule descriptors with help URIs
- **Taxonomies**: OWASP Top 10 2021 and CWE classifications
- **Locations**: Precise file paths, line/column numbers, code snippets
- **Messages**: Rich text and Markdown formatted descriptions
- **Fingerprints**: Stable identifiers for finding deduplication
- **Severity Levels**: Maps to SARIF levels (error, warning, note)
- **Rank Scoring**: 0.0-100.0 ranking for prioritization

### ✅ GitHub Code Scanning Compatible

Upload SARIF files directly to GitHub Security tab:
- Automatic vulnerability detection
- Pull request annotations
- Security dashboard integration
- Trend analysis over time

### ✅ VS Code SARIF Viewer Compatible

View findings in Visual Studio Code:
- In-editor annotations
- Problem panel integration
- Click-to-navigate to vulnerabilities
- Rich hover information

### ✅ CI/CD Integration Ready

Works with all major CI/CD platforms:
- GitHub Actions
- GitLab CI/CD
- Azure Pipelines
- Jenkins
- CircleCI
- Travis CI

## Usage

### Generate SARIF Output

```bash
# Scan a single file
gittera-sast scan --format sarif app.js > results.sarif

# Scan a directory
gittera-sast scan --format sarif src/ > results.sarif

# Save to file
gittera-sast scan --format sarif --output report.sarif src/
```

### GitHub Actions Integration

Upload SARIF to GitHub Code Scanning:

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run Gittera SAST
        run: |
          cargo install gittera-sast
          gittera-sast scan --format sarif src/ > results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
          category: gittera-sast
```

### VS Code SARIF Viewer

1. Install the [SARIF Viewer extension](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer)
2. Open the SARIF file in VS Code
3. Click "Show Results" in the explorer
4. Navigate to vulnerabilities from the Problems panel

### Azure DevOps Integration

```yaml
- task: Bash@3
  displayName: 'Run Security Scan'
  inputs:
    targetType: 'inline'
    script: |
      gittera-sast scan --format sarif $(Build.SourcesDirectory) > results.sarif

- task: PublishBuildArtifacts@1
  inputs:
    PathtoPublish: 'results.sarif'
    ArtifactName: 'CodeAnalysisLogs'
```

## SARIF Structure

### Basic Structure

```json
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [{
    "tool": { ... },
    "results": [ ... ],
    "taxonomies": [ ... ]
  }]
}
```

### Tool Information

```json
"tool": {
  "driver": {
    "name": "Gittera SAST",
    "version": "0.1.0",
    "semanticVersion": "0.1.0",
    "informationUri": "https://github.com/gittera/sast",
    "organization": "Gittera",
    "shortDescription": {
      "text": "Static Application Security Testing (SAST) tool with OWASP Top 10 coverage"
    },
    "fullDescription": {
      "text": "Gittera SAST is a multi-language static analysis security testing tool with comprehensive OWASP Top 10 2021 coverage, CWE mappings, and interprocedural taint analysis."
    },
    "rules": [ ... ],
    "taxa": [ ... ],
    "properties": {
      "totalRules": 1225,
      "supportedLanguages": ["JavaScript", "TypeScript", "Python", "Java", "Go", "Rust", "PHP", "Ruby", "C#", "Swift"],
      "owaspCoverage": "OWASP Top 10 2021 (100%)",
      "cweCoverage": "39 unique CWE IDs"
    }
  }
}
```

### Rule Definitions

Each unique rule detected in the scan is included with full metadata:

```json
{
  "id": "js/sql-injection",
  "name": "Sql Injection",
  "shortDescription": {
    "text": "SQL injection vulnerability detected"
  },
  "fullDescription": {
    "text": "Unvalidated user input is used in a SQL query, allowing attackers to execute arbitrary SQL commands"
  },
  "help": {
    "text": "For more information about Sql Injection, see the documentation.",
    "markdown": "# Sql Injection\n\nUnvalidated user input is used in a SQL query...\n\n## Category\ninjection\n\n## Severity\nCritical\n\n[Learn more](https://github.com/gittera/sast/js-sql-injection)"
  },
  "helpUri": "https://github.com/gittera/sast/js-sql-injection",
  "properties": {
    "category": "injection",
    "severity": "Critical",
    "tags": ["security", "injection", "severity/critical", "owasp/A03:2021"]
  },
  "defaultConfiguration": {
    "level": "error",
    "rank": 100.0
  },
  "relationships": [{
    "target": {
      "id": "A03:2021",
      "toolComponent": {
        "name": "OWASP Top 10 2021",
        "guid": "00000000-0000-0000-0000-000000000001"
      }
    },
    "kinds": ["superset"]
  }]
}
```

### Results (Findings)

Each security finding includes detailed location and context information:

```json
{
  "ruleId": "js/sql-injection",
  "ruleIndex": 0,
  "level": "error",
  "kind": "fail",
  "message": {
    "text": "Unvalidated user input is used in a SQL query",
    "markdown": "**injection**\n\nUnvalidated user input is used in a SQL query"
  },
  "locations": [{
    "physicalLocation": {
      "artifactLocation": {
        "uri": "src/app.js",
        "uriBaseId": "%SRCROOT%"
      },
      "region": {
        "startLine": 42,
        "startColumn": 15,
        "snippet": {
          "text": "db.query(`SELECT * FROM users WHERE id = ${userId}`)"
        }
      }
    }
  }],
  "partialFingerprints": {
    "primaryLocationLineHash": "a1b2c3d4e5f6"
  },
  "properties": {
    "severity": "Critical",
    "category": "injection"
  },
  "rank": 100.0
}
```

### Taxonomies

Gittera SAST includes two standard taxonomies:

#### OWASP Top 10 2021

```json
{
  "name": "OWASP Top 10 2021",
  "guid": "00000000-0000-0000-0000-000000000001",
  "organization": "OWASP",
  "shortDescription": {
    "text": "OWASP Top 10 Web Application Security Risks - 2021"
  },
  "downloadUri": "https://owasp.org/Top10/",
  "informationUri": "https://owasp.org/Top10/",
  "isComprehensive": true,
  "releaseDateUtc": "2021-09-24",
  "taxa": [
    {
      "id": "A01:2021",
      "name": "Broken Access Control",
      "shortDescription": {
        "text": "Broken Access Control"
      },
      "helpUri": "https://owasp.org/Top10/A01"
    },
    // ... A02 through A10
  ]
}
```

#### CWE (Common Weakness Enumeration)

```json
{
  "name": "CWE",
  "guid": "00000000-0000-0000-0000-000000000002",
  "organization": "MITRE",
  "shortDescription": {
    "text": "Common Weakness Enumeration"
  },
  "downloadUri": "https://cwe.mitre.org/data/downloads.html",
  "informationUri": "https://cwe.mitre.org/",
  "isComprehensive": false,
  "releaseDateUtc": "2024-01-01"
}
```

## Severity Mapping

Gittera severity levels map to SARIF as follows:

| Gittera Severity | SARIF Level | Rank  | Description |
|-----------------|-------------|-------|-------------|
| Critical        | error       | 100.0 | Severe security vulnerabilities requiring immediate attention |
| High            | error       | 80.0  | Serious security issues that should be fixed soon |
| Medium          | warning     | 50.0  | Moderate security concerns |
| Low             | note        | 20.0  | Minor security improvements |
| Info            | note        | 10.0  | Informational findings |

## Integration Examples

### GitLab CI/CD

```yaml
sast:
  stage: test
  script:
    - gittera-sast scan --format sarif src/ > gl-sast-report.sarif
  artifacts:
    reports:
      sast: gl-sast-report.sarif
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'gittera-sast scan --format sarif src/ > results.sarif'
                archiveArtifacts artifacts: 'results.sarif'

                // Optionally publish to a SARIF viewer
                publishHTML([
                    reportDir: '.',
                    reportFiles: 'results.sarif',
                    reportName: 'Security Scan Results'
                ])
            }
        }
    }
}
```

### CircleCI

```yaml
version: 2.1
jobs:
  security-scan:
    docker:
      - image: rust:latest
    steps:
      - checkout
      - run:
          name: Install Gittera SAST
          command: cargo install gittera-sast
      - run:
          name: Run security scan
          command: gittera-sast scan --format sarif src/ > results.sarif
      - store_artifacts:
          path: results.sarif
          destination: security-reports
```

## Advanced Features

### Fingerprinting

Each finding includes a stable fingerprint for tracking across scans:

```json
"partialFingerprints": {
  "primaryLocationLineHash": "a1b2c3d4e5f6"
}
```

This enables:
- Deduplication of findings across multiple scans
- Tracking of specific vulnerabilities over time
- Baseline comparison between scan runs

### Rich Metadata

Results include comprehensive metadata:

```json
"properties": {
  "severity": "Critical",
  "category": "injection",
  "tags": [
    "security",
    "injection",
    "severity/critical",
    "owasp/A03:2021"
  ]
}
```

### Code Snippets

Vulnerable code context is included directly in the SARIF:

```json
"region": {
  "startLine": 42,
  "startColumn": 15,
  "snippet": {
    "text": "db.query(`SELECT * FROM users WHERE id = ${userId}`)"
  }
}
```

### Relationships

Rules are linked to taxonomy classifications:

```json
"relationships": [{
  "target": {
    "id": "A03:2021",
    "index": 0,
    "toolComponent": {
      "name": "OWASP Top 10 2021",
      "guid": "00000000-0000-0000-0000-000000000001"
    }
  },
  "kinds": ["superset"]
}]
```

## Validation

Validate SARIF output against the official schema:

```bash
# Using JSON Schema validator
npm install -g ajv-cli
ajv validate -s https://json.schemastore.org/sarif-2.1.0.json -d results.sarif
```

## Best Practices

1. **Regular Scans**: Run SARIF scans on every commit/PR
2. **Baseline Management**: Use fingerprints to track new vs. existing findings
3. **GitHub Integration**: Upload to GitHub Code Scanning for visibility
4. **CI/CD Gates**: Fail builds on critical/high severity findings
5. **Trend Analysis**: Track finding counts over time
6. **Review Process**: Establish triage workflow for new findings

## Troubleshooting

### SARIF file not uploading to GitHub

Ensure:
- File is valid SARIF 2.1.0 format
- `uriBaseId` is set correctly (`%SRCROOT%`)
- File paths are relative to repository root
- GitHub Actions has proper permissions

### VS Code not showing results

Check:
- SARIF Viewer extension is installed
- File is opened in VS Code (not just viewed)
- Click "Show Results" in the SARIF explorer panel

### Missing rule information

Verify:
- Rules array in tool.driver is populated
- Each result has a valid ruleId
- Rule definitions include all required fields

## References

- [SARIF Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [SARIF Tutorials](https://github.com/microsoft/sarif-tutorials)
- [GitHub Code Scanning SARIF Support](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning)
- [VS Code SARIF Viewer](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer)
- [SARIF Validator](https://sarifweb.azurewebsites.net/Validation)

## See Also

- [CWE Mapping Documentation](CWE_MAPPING.md)
- [OWASP Rule Library](OWASP_RULE_LIBRARY.md)
- [Competitive Analysis](COMPETITIVE_ANALYSIS.md)
