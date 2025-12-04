# SAST Smoke Test Suite

This directory contains vulnerability test cases across all supported languages to test the Gittera SAST scanner.

## Languages

| Language | Files | Description |
|----------|-------|-------------|
| JavaScript | 25 | SQL injection, XSS, command injection, etc. |
| Python | 32 | SQL injection, command injection, path traversal, etc. |
| Go | 31 | SQL injection, command injection, SSRF, etc. |
| Java | 29 | SQL injection, XXE, deserialization, etc. |
| Rust | 8 | Command injection, unsafe code, weak crypto, etc. |
| TypeScript | 6 | SQL injection, XSS, command injection, etc. |
| C | 7 | Buffer overflow, format string, memory issues, etc. |
| C++ | 6 | Buffer overflow, memory issues, SQL injection, etc. |
| C# | 6 | SQL injection, command injection, deserialization, etc. |
| Ruby | 6 | SQL injection, command injection, deserialization, etc. |
| Kotlin | 5 | SQL injection, command injection, weak crypto, etc. |
| Scala | 5 | SQL injection, command injection, weak crypto, etc. |
| Swift | 5 | SQL injection, command injection, path traversal, etc. |
| PHP | 7 | SQL injection, XSS, command injection, LFI, etc. |
| Groovy | 5 | SQL injection, command injection, weak crypto, etc. |

## How to Run the Tests

1. **Build the SAST scanner:**

   ```bash
   cargo build --release
   ```

2. **Run the scanner on the test suite:**

   Scan all languages:
   ```bash
   cargo run --release -- scan smoke_tests
   ```

   Scan a specific language:
   ```bash
   cargo run --release -- scan smoke_tests/python
   ```

   Scan a single file:
   ```bash
   cargo run --release -- scan smoke_tests/python/sql_injection_raw.py
   ```

3. **Review the results:**

   Output to file:
   ```bash
   cargo run --release -- scan smoke_tests > scan_results.txt
   ```

   JSON format:
   ```bash
   cargo run --release -- scan smoke_tests --format json > scan_results.json
   ```

## Vulnerability Categories

- SQL Injection
- Command Injection
- Path Traversal / LFI
- Cross-Site Scripting (XSS)
- Hardcoded Secrets/Credentials
- Weak Cryptography (MD5, SHA1, DES, ECB mode)
- Insecure Deserialization
- Server-Side Request Forgery (SSRF)
- Buffer Overflow (C/C++)
- Format String Vulnerabilities (C)
- Memory Safety Issues (C/C++/Rust)
- XML External Entity (XXE)
- Code Injection / Eval
