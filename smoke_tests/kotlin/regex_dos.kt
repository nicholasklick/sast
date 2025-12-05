// Regular Expression Denial of Service (ReDoS) vulnerabilities in Kotlin
package com.example.security

import java.util.regex.Pattern

class RegexDosVulnerabilities {

    // Test 1: Catastrophic backtracking
    fun validateEmail(email: String): Boolean {
        // VULNERABLE: Nested quantifiers cause exponential backtracking
        val pattern = "^([a-zA-Z0-9]+)+@[a-zA-Z0-9]+\\.[a-zA-Z]+$"
        return email.matches(Regex(pattern))
    }

    // Test 2: Overlapping alternation
    fun validateInput(input: String): Boolean {
        // VULNERABLE: Overlapping patterns
        val pattern = "^(a+|a+b)+$"
        return input.matches(Regex(pattern))
    }

    // Test 3: User-provided regex
    fun matchPattern(input: String, pattern: String): Boolean {
        // VULNERABLE: User controls regex
        return input.matches(Regex(pattern))
    }

    // Test 4: Complex URL validation
    fun validateUrl(url: String): Boolean {
        // VULNERABLE: Complex regex with backtracking
        val pattern = "^(https?://)?([\\da-z\\.-]+)\\.([a-z\\.]{2,6})([/\\w \\.-]*)*/?$"
        return url.matches(Regex(pattern))
    }

    // Test 5: HTML tag stripping
    fun stripHtml(html: String): String {
        // VULNERABLE: Greedy quantifiers
        val pattern = "<[^>]*>"
        return html.replace(Regex(pattern), "")
    }

    // Test 6: Password strength regex
    fun isStrongPassword(password: String): Boolean {
        // VULNERABLE: Multiple lookaheads with quantifiers
        val pattern = "^(?=.*[a-z]+)(?=.*[A-Z]+)(?=.*[0-9]+)(?=.*[!@#\$%^&*]+).{8,}$"
        return password.matches(Regex(pattern))
    }

    // Test 7: Log parsing regex
    fun parseLogLine(line: String): List<String>? {
        // VULNERABLE: Greedy .* patterns
        val pattern = "^(.*) - (.*) \\[(.*?)\\] \"(.*)\" (\\d+) (.*)$"
        val regex = Regex(pattern)
        return regex.find(line)?.groupValues?.drop(1)
    }

    // Test 8: Repeated groups
    fun validateFormat(input: String): Boolean {
        // VULNERABLE: Repeated capturing groups
        val pattern = "^(([a-z])+\\.)+[a-z]+$"
        return input.matches(Regex(pattern))
    }

    // Test 9: Whitespace normalization
    fun normalizeWhitespace(text: String): String {
        // VULNERABLE: Multiple spaces on large input
        return text.replace(Regex("\\s+"), " ")
    }

    // Test 10: CSV field extraction
    fun extractFields(csvLine: String): List<String> {
        // VULNERABLE: Complex CSV regex
        val pattern = "(?:^|,)(?:\"([^\"]*(?:\"\"[^\"]*)*)\"|([^\",]*))"
        val regex = Regex(pattern)
        return regex.findAll(csvLine).map { it.value }.toList()
    }

    // Test 11: Phone number validation
    fun validatePhone(phone: String): Boolean {
        // VULNERABLE: Alternation with backtracking
        val pattern = "^(\\+\\d{1,3}[- ]?)?(\\(\\d{1,4}\\)[- ]?)?\\d{1,4}([- ]?\\d{1,4}){1,3}$"
        return phone.matches(Regex(pattern))
    }

    // Test 12: JSON-like validation
    fun validateJsonLike(input: String): Boolean {
        // VULNERABLE: Recursive-like patterns
        val pattern = "^\\{(\"[^\"]+\":\\s*(\"[^\"]*\"|\\d+|true|false|null),?\\s*)+\\}$"
        return input.matches(Regex(pattern))
    }

    // Test 13: Pattern compile from user
    fun compileUserPattern(userPattern: String): Pattern {
        // VULNERABLE: User-controlled pattern
        return Pattern.compile(userPattern)
    }
}
