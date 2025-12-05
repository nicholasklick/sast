// Regular Expression Denial of Service (ReDoS) vulnerabilities in Groovy
package com.example.security

import java.util.regex.Pattern

class RegexDosVulnerabilities {

    // Test 1: Catastrophic backtracking
    boolean validateEmail(String email) {
        // VULNERABLE: Nested quantifiers cause exponential backtracking
        def pattern = /^([a-zA-Z0-9]+)+@[a-zA-Z0-9]+\.[a-zA-Z]+$/
        email ==~ pattern
    }

    // Test 2: Overlapping alternation
    boolean validateInput(String input) {
        // VULNERABLE: Overlapping patterns
        def pattern = /^(a+|a+b)+$/
        input ==~ pattern
    }

    // Test 3: User-provided regex
    boolean matchPattern(String input, String pattern) {
        // VULNERABLE: User controls regex
        input ==~ pattern
    }

    // Test 4: Complex URL validation
    boolean validateUrl(String url) {
        // VULNERABLE: Complex regex with backtracking
        def pattern = /^(https?:\/\/)?([\\da-z\\.-]+)\\.([a-z\\.]{2,6})([\/\\w \\.-]*)*\/?$/
        url ==~ pattern
    }

    // Test 5: HTML tag stripping
    String stripHtml(String html) {
        // VULNERABLE: Greedy quantifiers
        html.replaceAll(/<[^>]*>/, "")
    }

    // Test 6: Password strength regex
    boolean isStrongPassword(String password) {
        // VULNERABLE: Multiple lookaheads with quantifiers
        def pattern = /^(?=.*[a-z]+)(?=.*[A-Z]+)(?=.*[0-9]+)(?=.*[!@#\$%^&*]+).{8,}$/
        password ==~ pattern
    }

    // Test 7: Log parsing regex
    List parseLogLine(String line) {
        // VULNERABLE: Greedy .* patterns
        def pattern = /^(.*) - (.*) \[(.*?)\] "(.*)" (\d+) (.*)$/
        def matcher = (line =~ pattern)
        matcher.find() ? (1..matcher.groupCount()).collect { matcher.group(it) } : null
    }

    // Test 8: Repeated groups
    boolean validateFormat(String input) {
        // VULNERABLE: Repeated capturing groups
        def pattern = /^(([a-z])+\.)+[a-z]+$/
        input ==~ pattern
    }

    // Test 9: Whitespace normalization
    String normalizeWhitespace(String text) {
        // VULNERABLE: Multiple spaces on large input
        text.replaceAll(/\s+/, " ")
    }

    // Test 10: Phone number validation
    boolean validatePhone(String phone) {
        // VULNERABLE: Alternation with backtracking
        def pattern = /^(\+\d{1,3}[- ]?)?(\(\d{1,4}\)[- ]?)?\d{1,4}([- ]?\d{1,4}){1,3}$/
        phone ==~ pattern
    }

    // Test 11: JSON-like validation
    boolean validateJsonLike(String input) {
        // VULNERABLE: Recursive-like patterns
        def pattern = /^\{("[^"]+"\s*:\s*("[^"]*"|\d+|true|false|null),?\s*)+\}$/
        input ==~ pattern
    }

    // Test 12: Pattern compile from user
    Pattern compileUserPattern(String userPattern) {
        // VULNERABLE: User-controlled pattern
        Pattern.compile(userPattern)
    }

    // Test 13: Groovy bitwiseNegate pattern
    def groovyPatternMatch(String input, String pattern) {
        // VULNERABLE: Groovy pattern operator with user input
        input =~ pattern
    }
}
