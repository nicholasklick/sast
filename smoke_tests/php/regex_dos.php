<?php
// Regular Expression DoS (ReDoS) vulnerabilities in PHP

// Test 1: Nested quantifiers
function validate_nested() {
    $input = $_GET['input'];
    // VULNERABLE: (a+)+ causes exponential backtracking
    return preg_match('/^(a+)+b$/', $input);
}

// Test 2: Overlapping alternation
function check_overlap() {
    $input = $_GET['input'];
    // VULNERABLE: Overlapping alternatives
    return preg_match('/^(a|a)+b$/', $input);
}

// Test 3: Email validation ReDoS
function validate_email() {
    $email = $_POST['email'];
    // VULNERABLE: Classic email ReDoS pattern
    $pattern = '/^([a-zA-Z0-9]+)+@([a-zA-Z0-9]+)+\.([a-zA-Z]+)+$/';
    return preg_match($pattern, $email);
}

// Test 4: URL validation ReDoS
function validate_url() {
    $url = $_GET['url'];
    // VULNERABLE: Nested groups in URL pattern
    $pattern = '/^(https?:\/\/)?([a-zA-Z0-9.-]+)+(\/.*)*$/';
    return preg_match($pattern, $url);
}

// Test 5: User-supplied regex
function custom_match() {
    $input = $_POST['input'];
    $pattern = $_POST['pattern'];
    // VULNERABLE: User supplies regex pattern
    return preg_match($pattern, $input);
}

// Test 6: preg_replace with vulnerable pattern
function replace_pattern() {
    $input = $_POST['input'];
    // VULNERABLE: Vulnerable pattern in preg_replace
    return preg_replace('/(a+)+/', 'X', $input);
}

// Test 7: preg_match_all with backtracking
function match_all() {
    $input = $_GET['input'];
    // VULNERABLE: Match all with exponential pattern
    preg_match_all('/(.+)+x/', $input, $matches);
    return count($matches[0]);
}

// Test 8: preg_split ReDoS
function split_input() {
    $input = $_POST['input'];
    // VULNERABLE: Split can trigger ReDoS
    return preg_split('/(\s+)+/', $input);
}

// Test 9: HTML tag matching ReDoS
function match_html() {
    $html = $_POST['html'];
    // VULNERABLE: Complex HTML pattern
    preg_match_all('/<([a-z]+)([^>]*)*>/', $html, $matches);
    return count($matches[0]);
}

// Test 10: Multiline ReDoS
function multiline_match() {
    $content = $_POST['content'];
    // VULNERABLE: Multiline with backtracking
    return preg_match('/^(.+)+$/m', $content);
}

// Test 11: Regex from database
function dynamic_regex() {
    $id = $_GET['id'];
    $input = $_GET['input'];
    // Assume pattern comes from database
    $pattern = get_pattern_from_db($id);
    // VULNERABLE: Pattern from database (could be user-supplied)
    return preg_match($pattern, $input);
}

// Test 12: PCRE recursive pattern
function recursive_match() {
    $input = $_GET['input'];
    // VULNERABLE: Recursive patterns can cause stack overflow
    $pattern = '/(?:a(?:a(?:a(?:a(?:a)*)*)*)*)+/';
    return preg_match($pattern, $input);
}

// Test 13: ereg (deprecated but still risky if used)
function ereg_match() {
    $input = $_GET['input'];
    // VULNERABLE: Deprecated and potentially ReDoS prone
    // return ereg('(a+)+', $input);  // Would fail in PHP 7+
}

function get_pattern_from_db($id) {
    // Placeholder
    return '/^test$/';
}
?>
