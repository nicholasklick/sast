#!/usr/bin/env python3
"""
Unified OWASP Benchmark Scoring Script

Supports both Java and Python OWASP benchmarks.
Provides consistent precision/recall metrics and regression detection.

Usage:
    python3 scripts/benchmark_score.py --language java --results results.json
    python3 scripts/benchmark_score.py --language python --results results.json
    python3 scripts/benchmark_score.py --language all  # Run both benchmarks
"""

import argparse
import csv
import json
import os
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class BenchmarkConfig:
    """Configuration for a specific benchmark."""
    language: str
    source_path: str
    expected_results: str
    file_extension: str
    # Mapping from our rule IDs/CWEs to OWASP categories
    category_mapping: dict


# OWASP Category mappings
JAVA_CATEGORIES = {
    "cmdi": {"cwe": 78, "name": "Command Injection"},
    "crypto": {"cwe": 327, "name": "Weak Encryption"},
    "hash": {"cwe": 328, "name": "Weak Hash"},
    "ldapi": {"cwe": 90, "name": "LDAP Injection"},
    "pathtraver": {"cwe": 22, "name": "Path Traversal"},
    "securecookie": {"cwe": 614, "name": "Insecure Cookie"},
    "sqli": {"cwe": 89, "name": "SQL Injection"},
    "trustbound": {"cwe": 501, "name": "Trust Boundary Violation"},
    "weakrand": {"cwe": 330, "name": "Weak Randomness"},
    "xpathi": {"cwe": 643, "name": "XPath Injection"},
    "xss": {"cwe": 79, "name": "Cross-Site Scripting"},
}

PYTHON_CATEGORIES = {
    "cmdi": {"cwe": 78, "name": "Command Injection"},
    "codeinj": {"cwe": 94, "name": "Code Injection"},
    "crypto": {"cwe": 327, "name": "Weak Encryption"},
    "deserialization": {"cwe": 502, "name": "Insecure Deserialization"},
    "hash": {"cwe": 328, "name": "Weak Hash"},
    "ldapi": {"cwe": 90, "name": "LDAP Injection"},
    "nosqli": {"cwe": 943, "name": "NoSQL Injection"},
    "pathtraver": {"cwe": 22, "name": "Path Traversal"},
    "redirect": {"cwe": 601, "name": "Open Redirect"},
    "securecookie": {"cwe": 614, "name": "Insecure Cookie"},
    "sqli": {"cwe": 89, "name": "SQL Injection"},
    "trustbound": {"cwe": 501, "name": "Trust Boundary Violation"},
    "weakrand": {"cwe": 330, "name": "Weak Randomness"},
    "xpathi": {"cwe": 643, "name": "XPath Injection"},
    "xss": {"cwe": 79, "name": "Cross-Site Scripting"},
    "xxe": {"cwe": 611, "name": "XXE"},
}

# Rule ID to OWASP category mapping
RULE_TO_CATEGORY = {
    # SQL Injection
    "js/sql-injection": "sqli",
    "js/sql-injection-extended": "sqli",
    "java/sql-injection": "sqli",
    "taint/sql-injection": "sqli",

    # Command Injection
    "js/command-injection": "cmdi",
    "js/command-injection-extended": "cmdi",
    "java/command-injection": "cmdi",
    "taint/command-injection": "cmdi",

    # XSS
    "js/dom-xss": "xss",
    "js/reflected-xss": "xss",
    "js/stored-xss": "xss",
    "js/unsafe-innerhtml": "xss",
    "js/document-write-xss": "xss",
    "java/reflected-xss": "xss",
    "taint/xss": "xss",
    "taint/htmloutput": "xss",

    # Path Traversal
    "js/path-traversal": "pathtraver",
    "js/arbitrary-file-write": "pathtraver",
    "java/path-traversal": "pathtraver",
    "taint/path-traversal": "pathtraver",
    "taint/pathtraversal": "pathtraver",
    "taint/arbitrary-file-write": "pathtraver",

    # Weak Hash
    "js/weak-hash": "hash",
    "java/weak-hash-variable": "hash",

    # Weak Cipher/Crypto
    "js/weak-cipher": "crypto",
    "js/ecb-mode": "crypto",
    "js/insufficient-key-size": "crypto",

    # LDAP Injection
    "js/ldap-injection": "ldapi",
    "java/ldap-injection": "ldapi",
    "taint/ldap-injection": "ldapi",

    # XPath Injection
    "js/xpath-injection": "xpathi",
    "java/xpath-injection": "xpathi",
    "taint/xpath-injection": "xpathi",

    # Trust Boundary Violation
    "taint/trustboundary": "trustbound",
    "taint/trust-boundary": "trustbound",
    "java/trust-boundary": "trustbound",

    # Insecure Cookie
    "js/insecure-session-cookie": "securecookie",
    "java/insecure-cookie": "securecookie",

    # Weak Random
    "js/insecure-random": "weakrand",
    "js/predictable-seed": "weakrand",
    "java/weak-random": "weakrand",
    "python/weak-random": "weakrand",

    # Trust Boundary
    "js/session-fixation": "trustbound",

    # Code Injection
    "js/code-injection": "codeinj",
    "taint/code-injection": "codeinj",
    "taint/codeeval": "codeinj",

    # Template Injection (maps to cmdi)
    "js/template-injection": "cmdi",

    # SSRF - not in standard OWASP benchmark categories
    "js/ssrf": None,

    # Deserialization
    "js/insecure-deserialization": "deserialization",

    # Open Redirect
    "js/open-redirect": "redirect",

    # XXE
    "js/xxe": "xxe",
    "taint/xxe": "xxe",
    "taint/xmlparse": "xxe",
}

# CWE to OWASP category mapping (fallback)
CWE_TO_CATEGORY = {
    78: "cmdi",
    79: "xss",
    89: "sqli",
    90: "ldapi",
    22: "pathtraver",
    327: "crypto",
    328: "hash",
    330: "weakrand",
    501: "trustbound",
    614: "securecookie",
    643: "xpathi",
    611: "xxe",
    943: "nosqli",
}


BENCHMARKS = {
    "java": BenchmarkConfig(
        language="java",
        source_path="../owasp/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode",
        expected_results="../owasp/BenchmarkJava/expectedresults-1.2.csv",
        file_extension=".java",
        category_mapping=JAVA_CATEGORIES,
    ),
    "python": BenchmarkConfig(
        language="python",
        source_path="../owasp/BenchmarkPython/testcode",
        expected_results="../owasp/BenchmarkPython/expectedresults-0.1.csv",
        file_extension=".py",
        category_mapping=PYTHON_CATEGORIES,
    ),
    "javascript": BenchmarkConfig(
        language="javascript",
        source_path="../owasp/BenchmarkJS/testcode",
        expected_results="../owasp/BenchmarkJS/expectedresults-0.1.csv",
        file_extension=".js",
        category_mapping=PYTHON_CATEGORIES,  # Same categories
    ),
    "typescript": BenchmarkConfig(
        language="typescript",
        source_path="../owasp/BenchmarkTypeScript/testcode",
        expected_results="../owasp/BenchmarkTypeScript/expectedresults-0.1.csv",
        file_extension=".js",  # TypeScript benchmark uses .js files
        category_mapping=PYTHON_CATEGORIES,
    ),
    "golang": BenchmarkConfig(
        language="golang",
        source_path="../owasp/BenchmarkGolang/internal/testcases",
        expected_results="../owasp/BenchmarkGolang/expectedresults-0.1.csv",
        file_extension=".go",
        category_mapping=PYTHON_CATEGORIES,
    ),
    "rust": BenchmarkConfig(
        language="rust",
        source_path="../owasp/BenchmarkRust/src/testcases",
        expected_results="../owasp/BenchmarkRust/expectedresults-0.1.csv",
        file_extension=".rs",
        category_mapping=PYTHON_CATEGORIES,
    ),
    "ruby": BenchmarkConfig(
        language="ruby",
        source_path="../owasp/BenchmarkRuby/testcode",
        expected_results="../owasp/BenchmarkRuby/expectedresults-0.1.csv",
        file_extension=".rb",
        category_mapping=PYTHON_CATEGORIES,
    ),
}


def get_rule_category(rule_id: str, cwe: Optional[int] = None) -> Optional[str]:
    """Map a rule ID or CWE to an OWASP benchmark category."""
    # First try direct rule mapping
    if rule_id in RULE_TO_CATEGORY:
        return RULE_TO_CATEGORY[rule_id]

    # Then try CWE mapping
    if cwe and cwe in CWE_TO_CATEGORY:
        return CWE_TO_CATEGORY[cwe]

    return None


def load_expected_results(csv_path: str) -> dict:
    """Load expected results from OWASP CSV file."""
    results = {}
    with open(csv_path, "r") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            test_name = row[0]
            category = row[1]
            is_vulnerable = row[2].lower() == "true"
            cwe = int(row[3]) if len(row) > 3 else None
            results[test_name] = {
                "category": category,
                "vulnerable": is_vulnerable,
                "cwe": cwe,
            }
    return results


def load_scan_results(results_path: str) -> list:
    """Load scan results from JSON output."""
    with open(results_path, "r") as f:
        data = json.load(f)
        # Handle both direct array and {"findings": [...]} format
        if isinstance(data, dict) and "findings" in data:
            return data["findings"]
        elif isinstance(data, list):
            return data
        else:
            return []


def extract_test_name(file_path: str, extension: str) -> Optional[str]:
    """Extract BenchmarkTestXXXXX from file path."""
    import re
    pattern = r"(BenchmarkTest\d+)" + re.escape(extension)
    match = re.search(pattern, file_path)
    if match:
        return match.group(1)
    return None


# Cache for Go line-to-test mappings
_go_line_mappings: dict = {}


def build_line_mapping(source_file: str) -> dict:
    """Build a mapping from line numbers to test names for single-file benchmarks."""
    import re
    if source_file in _go_line_mappings:
        return _go_line_mappings[source_file]

    mapping = {}
    current_test = None

    try:
        with open(source_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                # Look for test name patterns:
                # Go: "BenchmarkTest00001" or RegisteredTests with BenchmarkTest00001
                # Rust: "pub mod benchmarktest00001" or "//! BenchmarkTest00001"
                match = re.search(r'[Bb]enchmark[Tt]est(\d+)', line, re.IGNORECASE)
                if match:
                    current_test = f"BenchmarkTest{match.group(1)}"
                if current_test:
                    mapping[line_num] = current_test
    except Exception:
        pass

    _go_line_mappings[source_file] = mapping
    return mapping


def extract_test_name_with_line(file_path: str, line: int, extension: str, language: str) -> Optional[str]:
    """Extract test name, using line number for single-file benchmarks (Go, Rust)."""
    import re
    import os

    # First try file path extraction
    pattern = r"(BenchmarkTest\d+)" + re.escape(extension)
    match = re.search(pattern, file_path)
    if match:
        return match.group(1)

    # For Go/Rust with multi-test files, use line-based mapping
    # Go: generated.go contains all tests
    # Rust: hash.rs, cmdi.rs, etc. contain multiple tests per file
    if language == "golang" and "generated.go" in file_path:
        mapping = build_line_mapping(file_path)
        test_name = None
        for ln in sorted(mapping.keys()):
            if ln <= line:
                test_name = mapping[ln]
            else:
                break
        return test_name

    if language == "rust" and file_path.endswith(".rs"):
        mapping = build_line_mapping(file_path)
        test_name = None
        for ln in sorted(mapping.keys()):
            if ln <= line:
                test_name = mapping[ln]
            else:
                break
        return test_name

    return None


def run_scan(config: BenchmarkConfig, sast_binary: str = "./target/release/gittera-sast") -> list:
    """Run the SAST scanner on benchmark code."""
    cmd = [sast_binary, "scan", config.source_path, "--format", "json"]

    # Set larger stack size for Rust (large files can overflow default stack)
    env = os.environ.copy()
    if config.language == "rust":
        env["RUST_MIN_STACK"] = "16777216"  # 16MB stack

    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, env=env)

    if result.returncode != 0 and result.returncode != 1:
        print(f"Warning: Scanner returned non-zero exit code: {result.returncode}")
        print(f"Stderr: {result.stderr}")

    # Parse JSON output - filter out log lines that appear before JSON
    stdout = result.stdout
    # Look for the actual JSON object (starts with {"findings" or just {)
    # Skip ANSI escape codes which contain [ characters
    import re
    # Remove ANSI escape codes
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    clean_stdout = ansi_escape.sub('', stdout)

    # Find the start of JSON object
    json_start = clean_stdout.find('{"findings"')
    if json_start == -1:
        json_start = clean_stdout.find('{')

    if json_start == -1:
        print(f"Error: No JSON found in output")
        print(f"Stdout: {clean_stdout[:500]}")
        return []

    json_str = clean_stdout[json_start:]

    try:
        data = json.loads(json_str)
        # Handle both direct array and {"findings": [...]} format
        if isinstance(data, dict) and "findings" in data:
            return data["findings"]
        elif isinstance(data, list):
            return data
        else:
            return []
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON output: {e}")
        print(f"JSON string (first 500 chars): {json_str[:500]}")
        return []


def calculate_metrics(
    expected: dict,
    flagged_tests: dict,  # test_name -> list of (rule_id, category)
    category_filter: Optional[str] = None,
) -> dict:
    """Calculate precision, recall, and F1 score with category matching."""

    tp = 0  # True positives: vulnerable test correctly flagged with matching category
    fp = 0  # False positives: non-vulnerable test flagged, OR wrong category
    fn = 0  # False negatives: vulnerable test not flagged
    tn = 0  # True negatives: non-vulnerable test not flagged

    tp_tests = []
    fp_tests = []
    fn_tests = []

    for test_name, info in expected.items():
        test_category = info["category"]
        is_vulnerable = info["vulnerable"]

        # Skip if filtering by category
        if category_filter and test_category != category_filter:
            continue

        # Get all rules that flagged this test
        flags = flagged_tests.get(test_name, [])

        # Check if any flag matches the test's category
        correctly_flagged = any(cat == test_category for _, cat in flags)
        flagged_at_all = len(flags) > 0

        if is_vulnerable:
            if correctly_flagged:
                tp += 1
                tp_tests.append(test_name)
            else:
                fn += 1
                fn_tests.append(test_name)
        else:
            # For false positive tests, ANY flag is a false positive
            if flagged_at_all:
                fp += 1
                fp_tests.append(test_name)
            else:
                tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tp_tests": tp_tests,
        "fp_tests": fp_tests,
        "fn_tests": fn_tests,
    }


def score_benchmark(
    config: BenchmarkConfig,
    results: list,
    verbose: bool = False,
) -> dict:
    """Score benchmark results against expected outcomes."""

    expected = load_expected_results(config.expected_results)

    # Map findings to test names with their categories
    flagged_tests = defaultdict(list)

    for finding in results:
        file_path = finding.get("file_path", finding.get("file", finding.get("path", "")))
        line = finding.get("line", 0)
        test_name = extract_test_name_with_line(file_path, line, config.file_extension, config.language)

        if not test_name:
            continue

        rule_id = finding.get("rule_id", finding.get("check", ""))
        cwe = finding.get("cwe")

        # Try to extract CWE from finding
        if not cwe:
            cwes = finding.get("cwes", [])
            if cwes:
                cwe = cwes[0]

        # Map rule to category
        category = get_rule_category(rule_id, cwe)

        if category:
            flagged_tests[test_name].append((rule_id, category))

    # Calculate overall metrics
    overall = calculate_metrics(expected, flagged_tests)

    # Calculate per-category metrics
    categories = {}
    for cat in config.category_mapping.keys():
        cat_metrics = calculate_metrics(expected, flagged_tests, category_filter=cat)
        if cat_metrics["tp"] + cat_metrics["fp"] + cat_metrics["fn"] > 0:
            categories[cat] = cat_metrics

    return {
        "language": config.language,
        "overall": overall,
        "categories": categories,
        "total_findings": len(results),
        "unique_tests_flagged": len(flagged_tests),
        "total_tests": len(expected),
    }


def print_results(results: dict, verbose: bool = False):
    """Print formatted benchmark results."""
    lang = results["language"].upper()
    overall = results["overall"]

    print(f"\n{'='*60}")
    print(f"  {lang} OWASP Benchmark Results")
    print(f"{'='*60}")

    print(f"\nOverall Metrics:")
    print(f"  Precision: {overall['precision']*100:.1f}%")
    print(f"  Recall:    {overall['recall']*100:.1f}%")
    print(f"  F1 Score:  {overall['f1']*100:.1f}%")
    print(f"\n  True Positives:  {overall['tp']}")
    print(f"  False Positives: {overall['fp']}")
    print(f"  False Negatives: {overall['fn']}")
    print(f"  True Negatives:  {overall['tn']}")
    print(f"\n  Total Findings:     {results['total_findings']}")
    print(f"  Unique Tests Hit:   {results['unique_tests_flagged']}")
    print(f"  Total Test Cases:   {results['total_tests']}")

    print(f"\nPer-Category Results:")
    print(f"  {'Category':<15} {'Prec':>8} {'Recall':>8} {'F1':>8} {'TP':>5} {'FP':>5} {'FN':>5}")
    print(f"  {'-'*55}")

    for cat, metrics in sorted(results["categories"].items()):
        print(f"  {cat:<15} {metrics['precision']*100:>7.1f}% {metrics['recall']*100:>7.1f}% {metrics['f1']*100:>7.1f}% {metrics['tp']:>5} {metrics['fp']:>5} {metrics['fn']:>5}")

    if verbose and overall["fp_tests"]:
        print(f"\nFalse Positive Tests (first 20):")
        for test in overall["fp_tests"][:20]:
            print(f"  - {test}")

    if verbose and overall["fn_tests"]:
        print(f"\nFalse Negative Tests (first 20):")
        for test in overall["fn_tests"][:20]:
            print(f"  - {test}")


def check_regression(current: dict, baseline_file: Optional[str] = None) -> bool:
    """Check for precision regression against baseline."""
    if not baseline_file or not os.path.exists(baseline_file):
        return True

    with open(baseline_file, "r") as f:
        baseline = json.load(f)

    lang = current["language"]
    if lang not in baseline:
        print(f"No baseline for {lang}, skipping regression check")
        return True

    baseline_precision = baseline[lang]["precision"]
    current_precision = current["overall"]["precision"]

    # Allow 1% tolerance for floating point issues
    if current_precision < baseline_precision - 0.01:
        print(f"\nREGRESSION DETECTED for {lang}!")
        print(f"  Baseline precision: {baseline_precision*100:.1f}%")
        print(f"  Current precision:  {current_precision*100:.1f}%")
        print(f"  Regression: {(baseline_precision - current_precision)*100:.1f}%")
        return False

    return True


def save_baseline(results: dict, baseline_file: str):
    """Save current results as baseline."""
    baseline = {}
    if os.path.exists(baseline_file):
        with open(baseline_file, "r") as f:
            baseline = json.load(f)

    baseline[results["language"]] = {
        "precision": results["overall"]["precision"],
        "recall": results["overall"]["recall"],
        "f1": results["overall"]["f1"],
        "tp": results["overall"]["tp"],
        "fp": results["overall"]["fp"],
        "fn": results["overall"]["fn"],
    }

    with open(baseline_file, "w") as f:
        json.dump(baseline, f, indent=2)

    print(f"Saved baseline to {baseline_file}")


def main():
    parser = argparse.ArgumentParser(description="OWASP Benchmark Scoring")
    parser.add_argument("--language", "-l",
                       choices=["java", "python", "javascript", "typescript", "golang", "rust", "ruby", "all"],
                       default="all", help="Language benchmark to run")
    parser.add_argument("--results", "-r", help="Pre-existing results JSON file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed output")
    parser.add_argument("--baseline", "-b", default="scripts/benchmark_baseline.json",
                       help="Baseline file for regression checking")
    parser.add_argument("--save-baseline", action="store_true",
                       help="Save current results as new baseline")
    parser.add_argument("--check-regression", action="store_true",
                       help="Check for precision regression")
    parser.add_argument("--json-output", "-o", help="Output results as JSON to file")
    parser.add_argument("--sast-binary", default="./target/release/gittera-sast",
                       help="Path to SAST binary")

    args = parser.parse_args()

    languages = list(BENCHMARKS.keys()) if args.language == "all" else [args.language]
    all_results = {}
    regression_found = False

    for lang in languages:
        config = BENCHMARKS[lang]

        # Check if source path exists
        if not os.path.exists(config.source_path):
            print(f"Warning: {lang} benchmark not found at {config.source_path}, skipping")
            continue

        print(f"\n{'='*60}")
        print(f"  Scoring {lang.upper()} Benchmark")
        print(f"{'='*60}")

        # Get results
        if args.results:
            results = load_scan_results(args.results)
        else:
            results = run_scan(config, args.sast_binary)

        # Score
        scored = score_benchmark(config, results, verbose=args.verbose)
        all_results[lang] = scored

        # Print results
        print_results(scored, verbose=args.verbose)

        # Check regression
        if args.check_regression:
            if not check_regression(scored, args.baseline):
                regression_found = True

        # Save baseline
        if args.save_baseline:
            save_baseline(scored, args.baseline)

    # Output JSON if requested
    if args.json_output:
        with open(args.json_output, "w") as f:
            json.dump(all_results, f, indent=2, default=str)
        print(f"\nResults saved to {args.json_output}")

    # Exit with error if regression detected
    if regression_found:
        sys.exit(1)

    return 0


if __name__ == "__main__":
    sys.exit(main())
