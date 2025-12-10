#!/usr/bin/env python3
"""
Score Bandit results against OWASP Python Benchmark expected results.

Usage:
    bandit -r testcode -f json | python3 bandit_to_benchmark.py expected.csv
"""

import csv
import json
import re
import sys
from collections import defaultdict

# Bandit test IDs to OWASP categories
# https://bandit.readthedocs.io/en/latest/plugins/index.html
BANDIT_TO_CATEGORY = {
    # Command Injection
    "B102": "cmdi",  # exec_used
    "B103": "cmdi",  # set_bad_file_permissions
    "B301": "cmdi",  # pickle
    "B307": "cmdi",  # eval
    "B601": "cmdi",  # paramiko_calls
    "B602": "cmdi",  # subprocess_popen_with_shell_equals_true
    "B603": "cmdi",  # subprocess_without_shell_equals_true
    "B604": "cmdi",  # any_other_function_with_shell_equals_true
    "B605": "cmdi",  # start_process_with_a_shell
    "B606": "cmdi",  # start_process_with_no_shell
    "B607": "cmdi",  # start_process_with_partial_path
    "B609": "cmdi",  # linux_commands_wildcard_injection

    # Code Injection
    "B307": "codeinj",  # eval

    # SQL Injection
    "B608": "sqli",  # hardcoded_sql_expressions
    "B610": "sqli",  # django_extra_used
    "B611": "sqli",  # django_rawsql_used

    # XSS
    "B701": "xss",  # jinja2_autoescape_false
    "B702": "xss",  # use_of_mako_templates
    "B703": "xss",  # django_mark_safe

    # Weak Crypto
    "B303": "crypto",  # md5
    "B304": "crypto",  # des
    "B305": "crypto",  # cipher

    # Weak Hash
    "B303": "hash",  # md5 (also maps to hash)
    "B324": "hash",  # hashlib

    # Weak Random
    "B311": "weakrand",  # random

    # Path Traversal
    "B310": "pathtraver",  # urllib_urlopen

    # XXE
    "B313": "xxe",  # xml_bad_cElementTree
    "B314": "xxe",  # xml_bad_ElementTree
    "B315": "xxe",  # xml_bad_expatreader
    "B316": "xxe",  # xml_bad_expatbuilder
    "B317": "xxe",  # xml_bad_sax
    "B318": "xxe",  # xml_bad_minidom
    "B319": "xxe",  # xml_bad_pulldom
    "B320": "xxe",  # xml_bad_etree

    # Deserialization
    "B301": "deserialization",  # pickle
    "B302": "deserialization",  # marshal
    "B306": "deserialization",  # mktemp_q
    "B403": "deserialization",  # import_pickle
    "B404": "deserialization",  # import_subprocess

    # LDAP
    "B321": "ldapi",  # ftplib

    # Hardcoded passwords/secrets
    "B105": "trustbound",  # hardcoded_password_string
    "B106": "trustbound",  # hardcoded_password_funcarg
    "B107": "trustbound",  # hardcoded_password_default
}

# CWE to category mapping
CWE_TO_CATEGORY = {
    78: "cmdi",
    79: "xss",
    89: "sqli",
    90: "ldapi",
    22: "pathtraver",
    94: "codeinj",
    327: "crypto",
    328: "hash",
    330: "weakrand",
    501: "trustbound",
    502: "deserialization",
    611: "xxe",
    614: "securecookie",
    643: "xpathi",
}


def get_category_from_bandit(result: dict) -> str | None:
    """Extract OWASP category from a Bandit result."""
    test_id = result.get("test_id", "")

    if test_id in BANDIT_TO_CATEGORY:
        return BANDIT_TO_CATEGORY[test_id]

    # Try CWE
    cwe = result.get("issue_cwe", {})
    if isinstance(cwe, dict):
        cwe_id = cwe.get("id")
        if cwe_id and cwe_id in CWE_TO_CATEGORY:
            return CWE_TO_CATEGORY[cwe_id]

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
        print("Usage: bandit ... -f json | python3 bandit_to_benchmark.py expected.csv", file=sys.stderr)
        sys.exit(1)

    csv_path = sys.argv[1]

    # Load expected results
    expected = load_expected_results(csv_path)

    # Load Bandit JSON from stdin
    bandit_data = json.load(sys.stdin)
    results = bandit_data.get("results", [])

    # Map findings to test names with categories
    flagged_tests = defaultdict(list)

    for result in results:
        file_path = result.get("filename", "")
        test_name = extract_test_name(file_path)

        if not test_name:
            continue

        category = get_category_from_bandit(result)
        if category:
            flagged_tests[test_name].append((result.get("test_id", ""), category))

    # Calculate metrics
    tp = fp = fn = tn = 0

    for test_name, info in expected.items():
        test_category = info["category"]
        is_vulnerable = info["vulnerable"]

        flags = flagged_tests.get(test_name, [])
        correctly_flagged = any(cat == test_category for _, cat in flags)
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
    print(f"  BANDIT OWASP Python Benchmark Results")
    print(f"{'='*60}")

    print(f"\nOverall Metrics:")
    print(f"  Precision: {precision*100:.1f}%")
    print(f"  Recall:    {recall*100:.1f}%")
    print(f"  F1 Score:  {f1*100:.1f}%")
    print(f"\n  True Positives:  {tp}")
    print(f"  False Positives: {fp}")
    print(f"  False Negatives: {fn}")
    print(f"  True Negatives:  {tn}")
    print(f"\n  Total Bandit Findings:  {len(results)}")
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
