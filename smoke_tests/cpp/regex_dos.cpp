// Regular Expression DoS (ReDoS) vulnerabilities in C++
#include <iostream>
#include <string>
#include <regex>
#include <chrono>

// Test 1: Catastrophic backtracking with nested quantifiers
bool validate_evil(const std::string& input) {
    // VULNERABLE: (a+)+ causes exponential backtracking
    std::regex pattern("(a+)+b");
    return std::regex_match(input, pattern);
}

// Test 2: Overlapping alternation
bool check_overlap(const std::string& input) {
    // VULNERABLE: Overlapping alternatives cause backtracking
    std::regex pattern("(a|a)+b");
    return std::regex_match(input, pattern);
}

// Test 3: Nested quantifiers with alternation
bool validate_nested(const std::string& input) {
    // VULNERABLE: Complex nested pattern
    std::regex pattern("(a*)*b");
    return std::regex_match(input, pattern);
}

// Test 4: Email validation with ReDoS
bool validate_email(const std::string& email) {
    // VULNERABLE: Classic email ReDoS pattern
    std::regex pattern("^([a-zA-Z0-9]+)+@([a-zA-Z0-9]+)+\\.([a-zA-Z]+)+$");
    return std::regex_match(email, pattern);
}

// Test 5: URL validation with ReDoS
bool validate_url(const std::string& url) {
    // VULNERABLE: Nested groups in URL pattern
    std::regex pattern("^(https?://)?([a-zA-Z0-9.-]+)+(/.*)*$");
    return std::regex_match(url, pattern);
}

// Test 6: Greedy quantifiers on same character class
bool match_greedy(const std::string& input) {
    // VULNERABLE: .* followed by similar pattern
    std::regex pattern(".*a.*a.*a.*a.*a$");
    return std::regex_match(input, pattern);
}

// Test 7: User-supplied regex pattern
bool user_regex(const std::string& input, const std::string& user_pattern) {
    // VULNERABLE: User can supply malicious pattern
    std::regex pattern(user_pattern);
    return std::regex_match(input, pattern);
}

// Test 8: Repetition with optional groups
bool optional_repeat(const std::string& input) {
    // VULNERABLE: Optional group with repetition
    std::regex pattern("(a?a?)+b");
    return std::regex_match(input, pattern);
}

// Test 9: Multiple variable-length groups
bool multi_groups(const std::string& input) {
    // VULNERABLE: Multiple greedy groups
    std::regex pattern("([a-z]+)*([0-9]+)*$");
    return std::regex_match(input, pattern);
}

// Test 10: Backreference with repetition
bool backref_repeat(const std::string& input) {
    // VULNERABLE: Backreference in repetition
    std::regex pattern("(a+)\\1+b");
    return std::regex_match(input, pattern);
}

// Test 11: Unbounded repetition near end
bool unbounded_end(const std::string& input) {
    // VULNERABLE: Unbounded .* with complex suffix
    std::regex pattern("^.*([a-z]+)+$");
    return std::regex_match(input, pattern);
}

// Demonstration of ReDoS impact
void demonstrate_redos() {
    // Input that triggers exponential time
    std::string evil_input(25, 'a');  // "aaaaaaaaaaaaaaaaaaaaaaaaa"

    auto start = std::chrono::high_resolution_clock::now();

    // This will hang or take extremely long
    // validate_evil(evil_input);

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    std::cout << "Time: " << duration.count() << "ms" << std::endl;
}
