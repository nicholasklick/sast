#!/usr/bin/env python3
"""
Score Semgrep results against OWASP Benchmark expected results.

Usage:
    semgrep --config=auto path/to/benchmark --json | python3 semgrep_to_benchmark.py expected.csv
"""

import csv
import json
import re
import sys
from collections import defaultdict

# Semgrep rule patterns to OWASP categories
SEMGREP_RULE_TO_CATEGORY = {
    # SQL Injection
    "sql": "sqli",
    "sqli": "sqli",

    # Command Injection
    "command-injection": "cmdi",
    "os-command": "cmdi",
    "exec": "cmdi",

    # XSS
    "xss": "xss",
    "cross-site-scripting": "xss",
    "reflected-xss": "xss",

    # Path Traversal
    "path-traversal": "pathtraver",
    "directory-traversal": "pathtraver",
    "file-inclusion": "pathtraver",

    # Weak Hash
    "md5": "hash",
    "sha1": "hash",
    "weak-hash": "hash",
    "weak-message-digest": "hash",

    # Weak Crypto
    "weak-crypto": "crypto",
    "des": "crypto",
    "ecb-mode": "crypto",
    "weak-cipher": "crypto",

    # LDAP Injection
    "ldap": "ldapi",

    # XPath Injection
    "xpath": "xpathi",

    # Trust Boundary
    "trust-boundary": "trustbound",
    "session": "trustbound",

    # Insecure Cookie
    "cookie": "securecookie",
    "httponly": "securecookie",
    "secure-cookie": "securecookie",

    # Weak Random
    "random": "weakrand",
    "math-random": "weakrand",
    "weak-random": "weakrand",
    "predictable": "weakrand",
}

# CWE to category mapping
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
}


def get_category_from_semgrep(result: dict) -> str | None:
    """Extract OWASP category from a Semgrep result."""
    check_id = result.get("check_id", "").lower()

    # Try rule ID patterns
    for pattern, category in SEMGREP_RULE_TO_CATEGORY.items():
        if pattern in check_id:
            return category

    # Try CWE from metadata
    metadata = result.get("extra", {}).get("metadata", {})
    cwes = metadata.get("cwe", [])
    if isinstance(cwes, str):
        cwes = [cwes]

    for cwe in cwes:
        # Extract CWE number from strings like "CWE-89: SQL Injection"
        match = re.search(r"CWE-?(\d+)", str(cwe))
        if match:
            cwe_num = int(match.group(1))
            if cwe_num in CWE_TO_CATEGORY:
                return CWE_TO_CATEGORY[cwe_num]

    return None


def extract_test_name(file_path: str) -> str | None:
    """Extract BenchmarkTestXXXXX from file path."""
    match = re.search(r"(BenchmarkTest\d+)", file_path)
    return match.group(1) if match else None


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
            results[test_name] = {
                "category": category,
                "vulnerable": is_vulnerable,
            }
    return results


def main():
    if len(sys.argv) < 2:
        print("Usage: semgrep ... --json | python3 semgrep_to_benchmark.py expected.csv", file=sys.stderr)
        sys.exit(1)

    csv_path = sys.argv[1]

    # Load expected results
    expected = load_expected_results(csv_path)

    # Load Semgrep JSON from stdin
    semgrep_data = json.load(sys.stdin)
    results = semgrep_data.get("results", [])

    # Map findings to test names with categories
    flagged_tests = defaultdict(list)

    for result in results:
        file_path = result.get("path", "")
        test_name = extract_test_name(file_path)

        if not test_name:
            continue

        category = get_category_from_semgrep(result)
        if category:
            flagged_tests[test_name].append((result.get("check_id", ""), category))

    # Calculate metrics
    tp = fp = fn = tn = 0
    tp_tests = []
    fp_tests = []
    fn_tests = []

    for test_name, info in expected.items():
        test_category = info["category"]
        is_vulnerable = info["vulnerable"]

        flags = flagged_tests.get(test_name, [])
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
            if flagged_at_all:
                fp += 1
                fp_tests.append(test_name)
            else:
                tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    # Calculate per-category metrics
    categories = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0})

    for test_name, info in expected.items():
        cat = info["category"]
        is_vulnerable = info["vulnerable"]
        flags = flagged_tests.get(test_name, [])
        correctly_flagged = any(c == cat for _, c in flags)
        flagged_at_all = len(flags) > 0

        if is_vulnerable:
            if correctly_flagged:
                categories[cat]["tp"] += 1
            else:
                categories[cat]["fn"] += 1
        else:
            if flagged_at_all:
                categories[cat]["fp"] += 1
            else:
                categories[cat]["tn"] += 1

    # Print results
    print(f"\n{'='*60}")
    print(f"  SEMGREP OWASP Benchmark Results")
    print(f"{'='*60}")

    print(f"\nOverall Metrics:")
    print(f"  Precision: {precision*100:.1f}%")
    print(f"  Recall:    {recall*100:.1f}%")
    print(f"  F1 Score:  {f1*100:.1f}%")
    print(f"\n  True Positives:  {tp}")
    print(f"  False Positives: {fp}")
    print(f"  False Negatives: {fn}")
    print(f"  True Negatives:  {tn}")
    print(f"\n  Total Semgrep Findings: {len(results)}")
    print(f"  Unique Tests Hit:       {len(flagged_tests)}")
    print(f"  Total Test Cases:       {len(expected)}")

    print(f"\nPer-Category Results:")
    print(f"  {'Category':<15} {'Prec':>8} {'Recall':>8} {'F1':>8} {'TP':>5} {'FP':>5} {'FN':>5}")
    print(f"  {'-'*55}")

    for cat in sorted(categories.keys()):
        m = categories[cat]
        p = m["tp"] / (m["tp"] + m["fp"]) if (m["tp"] + m["fp"]) > 0 else 0
        r = m["tp"] / (m["tp"] + m["fn"]) if (m["tp"] + m["fn"]) > 0 else 0
        f = 2 * p * r / (p + r) if (p + r) > 0 else 0
        print(f"  {cat:<15} {p*100:>7.1f}% {r*100:>7.1f}% {f*100:>7.1f}% {m['tp']:>5} {m['fp']:>5} {m['fn']:>5}")


if __name__ == "__main__":
    main()
