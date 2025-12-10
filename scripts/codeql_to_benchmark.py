#!/usr/bin/env python3
"""
Score CodeQL SARIF results against OWASP Benchmark expected results.

Usage:
    python3 codeql_to_benchmark.py results.sarif expected.csv
"""

import csv
import json
import re
import sys
from collections import defaultdict

# CWE to OWASP category mapping
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


def extract_cwe(rule_id: str, tags: list) -> int | None:
    """Extract CWE number from rule ID or tags."""
    # Try rule ID first (e.g., java/sql-injection has CWE in tags)
    for tag in tags:
        if tag.startswith("external/cwe/cwe-"):
            try:
                return int(tag.split("cwe-")[1])
            except:
                pass
    return None


def get_category_from_cwe(cwe: int) -> str | None:
    """Map CWE to OWASP category."""
    return CWE_TO_CATEGORY.get(cwe)


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
    if len(sys.argv) < 3:
        print("Usage: python3 codeql_to_benchmark.py results.sarif expected.csv", file=sys.stderr)
        sys.exit(1)

    sarif_path = sys.argv[1]
    csv_path = sys.argv[2]

    # Load expected results
    expected = load_expected_results(csv_path)

    # Load SARIF results
    with open(sarif_path, "r") as f:
        sarif = json.load(f)

    # Build rule ID to CWE mapping
    rule_cwes = {}
    for run in sarif.get("runs", []):
        tool = run.get("tool", {})
        driver = tool.get("driver", {})
        for rule in driver.get("rules", []):
            rule_id = rule.get("id", "")
            tags = rule.get("properties", {}).get("tags", [])
            cwe = extract_cwe(rule_id, tags)
            if cwe:
                rule_cwes[rule_id] = cwe

    # Map findings to test names with categories
    flagged_tests = defaultdict(list)
    total_results = 0

    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            total_results += 1
            rule_id = result.get("ruleId", "")

            locations = result.get("locations", [])
            if not locations:
                continue

            physical = locations[0].get("physicalLocation", {})
            artifact = physical.get("artifactLocation", {})
            file_path = artifact.get("uri", "")

            test_name = extract_test_name(file_path)
            if not test_name:
                continue

            cwe = rule_cwes.get(rule_id)
            if cwe:
                category = get_category_from_cwe(cwe)
                if category:
                    flagged_tests[test_name].append((rule_id, category, cwe))

    # Calculate metrics
    tp = fp = fn = tn = 0

    for test_name, info in expected.items():
        test_category = info["category"]
        is_vulnerable = info["vulnerable"]

        flags = flagged_tests.get(test_name, [])
        correctly_flagged = any(cat == test_category for _, cat, _ in flags)
        flagged_at_all = len(flags) > 0

        if is_vulnerable:
            if correctly_flagged:
                tp += 1
            else:
                fn += 1
        else:
            if flagged_at_all:
                fp += 1
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
        correctly_flagged = any(c == cat for _, c, _ in flags)
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
    print(f"  CODEQL OWASP Java Benchmark Results")
    print(f"{'='*60}")

    print(f"\nOverall Metrics:")
    print(f"  Precision: {precision*100:.1f}%")
    print(f"  Recall:    {recall*100:.1f}%")
    print(f"  F1 Score:  {f1*100:.1f}%")
    print(f"\n  True Positives:  {tp}")
    print(f"  False Positives: {fp}")
    print(f"  False Negatives: {fn}")
    print(f"  True Negatives:  {tn}")
    print(f"\n  Total CodeQL Findings: {total_results}")
    print(f"  Unique Tests Hit:      {len(flagged_tests)}")
    print(f"  Total Test Cases:      {len(expected)}")

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
