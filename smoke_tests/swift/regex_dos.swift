// Regular Expression Denial of Service (ReDoS) vulnerabilities in Swift
import Foundation

class RegexDosVulnerabilities {

    // Test 1: Catastrophic backtracking with nested quantifiers
    func validateEmail(email: String) -> Bool {
        // VULNERABLE: Nested quantifiers cause exponential backtracking
        let pattern = "^([a-zA-Z0-9]+)+@[a-zA-Z0-9]+\\.[a-zA-Z]+$"
        return email.range(of: pattern, options: .regularExpression) != nil
    }

    // Test 2: Overlapping alternation
    func validateInput(input: String) -> Bool {
        // VULNERABLE: Overlapping patterns
        let pattern = "^(a+|a+b)+$"
        return input.range(of: pattern, options: .regularExpression) != nil
    }

    // Test 3: User-provided regex
    func matchPattern(input: String, pattern: String) -> Bool {
        // VULNERABLE: User controls regex pattern
        return input.range(of: pattern, options: .regularExpression) != nil
    }

    // Test 4: Complex URL validation
    func validateUrl(url: String) -> Bool {
        // VULNERABLE: Complex regex with backtracking
        let pattern = "^(https?://)?([\\da-z\\.-]+)\\.([a-z\\.]{2,6})([/\\w \\.-]*)*/?$"
        return url.range(of: pattern, options: .regularExpression) != nil
    }

    // Test 5: HTML tag stripping
    func stripHtml(html: String) -> String {
        // VULNERABLE: Greedy quantifiers on user input
        let pattern = "<[^>]*>"
        return html.replacingOccurrences(of: pattern, with: "", options: .regularExpression)
    }

    // Test 6: Password strength check
    func isStrongPassword(password: String) -> Bool {
        // VULNERABLE: Multiple lookaheads with quantifiers
        let pattern = "^(?=.*[a-z]+)(?=.*[A-Z]+)(?=.*[0-9]+)(?=.*[!@#$%^&*]+).{8,}$"
        return password.range(of: pattern, options: .regularExpression) != nil
    }

    // Test 7: Log parsing regex
    func parseLogLine(line: String) -> [String]? {
        // VULNERABLE: Greedy .* patterns
        let pattern = "^(.*) - (.*) \\[(.*?)\\] \"(.*)\" (\\d+) (.*)$"
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return nil }
        let range = NSRange(line.startIndex..., in: line)
        guard let match = regex.firstMatch(in: line, range: range) else { return nil }
        return (1..<match.numberOfRanges).compactMap { i in
            Range(match.range(at: i), in: line).map { String(line[$0]) }
        }
    }

    // Test 8: Repeated groups
    func validateFormat(input: String) -> Bool {
        // VULNERABLE: Repeated capturing groups
        let pattern = "^(([a-z])+\\.)+[a-z]+$"
        return input.range(of: pattern, options: .regularExpression) != nil
    }

    // Test 9: Whitespace normalization
    func normalizeWhitespace(text: String) -> String {
        // VULNERABLE: Multiple spaces pattern on large input
        let pattern = "\\s+"
        return text.replacingOccurrences(of: pattern, with: " ", options: .regularExpression)
    }

    // Test 10: CSV field extraction
    func extractFields(csvLine: String) -> [String] {
        // VULNERABLE: Complex CSV regex
        let pattern = "(?:^|,)(?:\"([^\"]*(?:\"\"[^\"]*)*)\"|([^\",]*))"
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        let range = NSRange(csvLine.startIndex..., in: csvLine)
        let matches = regex.matches(in: csvLine, range: range)
        return matches.compactMap { match in
            Range(match.range, in: csvLine).map { String(csvLine[$0]) }
        }
    }

    // Test 11: NSRegularExpression with timeout
    func matchWithTimeout(input: String, pattern: String) -> Bool {
        // VULNERABLE: No timeout mechanism
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return false }
        let range = NSRange(input.startIndex..., in: input)
        return regex.firstMatch(in: input, range: range) != nil
    }

    // Test 12: Phone number validation
    func validatePhone(phone: String) -> Bool {
        // VULNERABLE: Alternation with backtracking
        let pattern = "^(\\+\\d{1,3}[- ]?)?(\\(\\d{1,4}\\)[- ]?)?\\d{1,4}([- ]?\\d{1,4}){1,3}$"
        return phone.range(of: pattern, options: .regularExpression) != nil
    }

    // Test 13: JSON-like validation
    func validateJsonLike(input: String) -> Bool {
        // VULNERABLE: Recursive-like patterns
        let pattern = "^\\{(\"[^\"]+\":\\s*(\"[^\"]*\"|\\d+|true|false|null),?\\s*)+\\}$"
        return input.range(of: pattern, options: .regularExpression) != nil
    }
}
