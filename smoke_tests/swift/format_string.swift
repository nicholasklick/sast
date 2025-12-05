// Format String vulnerabilities in Swift
import Foundation

class FormatStringVulnerabilities {

    // Test 1: NSLog with user input
    func logUserInput(input: String) {
        // VULNERABLE: User input as format string
        NSLog(input)
    }

    // Test 2: String(format:) with user input
    func formatUserString(format: String) -> String {
        // VULNERABLE: User-controlled format string
        return String(format: format)
    }

    // Test 3: Printf-style format
    func printFormatted(format: String, args: CVarArg...) {
        // VULNERABLE: User format with args
        let result = String(format: format, arguments: args)
        print(result)
    }

    // Test 4: NSString format
    func nsStringFormat(format: String) -> NSString {
        // VULNERABLE: User-controlled format
        return NSString(format: format as NSString)
    }

    // Test 5: Error message formatting
    func formatError(userMessage: String) {
        // VULNERABLE: User message as format
        let formatted = String(format: userMessage)
        print("Error: \(formatted)")
    }

    // Test 6: Logging framework
    func logMessage(format: String, args: CVarArg...) {
        // VULNERABLE: Format from user
        NSLog(format, args)
    }

    // Test 7: Localized format string
    func localizedFormat(key: String, args: CVarArg...) -> String {
        // VULNERABLE: Key could load malicious format from user
        let format = NSLocalizedString(key, comment: "")
        return String(format: format, arguments: args)
    }

    // Test 8: StringBuilder with format
    func buildString(template: String, values: [CVarArg]) -> String {
        // VULNERABLE: Template from user
        return String(format: template, arguments: values)
    }

    // Test 9: URL encoding with format
    func formatUrl(pattern: String, param: String) -> URL? {
        // VULNERABLE: Pattern from user
        let urlString = String(format: pattern, param)
        return URL(string: urlString)
    }

    // Test 10: Debug logging
    func debugLog(format: String) {
        #if DEBUG
        // VULNERABLE: User format in debug
        NSLog("DEBUG: " + format)
        #endif
    }

    // Test 11: AttributedString format
    func formatAttributedString(format: String) -> NSAttributedString {
        // VULNERABLE: Format string from user
        let formatted = String(format: format)
        return NSAttributedString(string: formatted)
    }

    // Test 12: Predicate format
    func createPredicate(format: String) -> NSPredicate {
        // VULNERABLE: Predicate format from user
        return NSPredicate(format: format)
    }

    // Test 13: Core Data fetch with format
    func fetchWithFormat(format: String, args: CVarArg...) {
        // VULNERABLE: Format string injection in fetch
        let predicate = NSPredicate(format: format, arguments: getVaList(args))
        print("Fetching with: \(predicate)")
    }
}
