# Gemini SAST Test Suite

This directory contains 100 test cases with various vulnerabilities to test the Gittera SAST scanner.
The tests are organized by language.

## Languages

- Python (25 tests)
- Java (25 tests)
- Go (25 tests)
- JavaScript (25 tests)

## How to Run the Tests

1.  **Build the SAST scanner:**

    Open your terminal in the root of the `sast` project and run the following command to build the scanner in release mode:

    ```bash
    cargo build --release
    ```

2.  **Run the scanner on the test suite:**

    Once the build is complete, you can run the scanner on this directory of test files. The binary is named `gittera`, but it's easier to run it via `cargo`.

    To scan the entire `gemini_tests` directory, run the following command from the root of the `sast` project:

    ```bash
    cargo run --release -- scan gemini_tests
    ```

    You can also scan a specific language folder:

    ```bash
    cargo run --release -- scan gemini_tests/python
    ```

    Or even a single file:

    ```bash
    cargo run --release -- scan gemini_tests/python/sql_injection_raw.py
    ```

3.  **Review the results:**

    The scanner will output the findings to your terminal. You can redirect the output to a file for easier review:

    ```bash
    cargo run --release -- scan gemini_tests > scan_results.txt
    ```

    You can also specify a different output format, like JSON:

    ```bash
    cargo run --release -- scan gemini_tests --format json > scan_results.json
    ```
