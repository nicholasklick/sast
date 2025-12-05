// Log Injection vulnerabilities in Swift
import Foundation
import os.log

class LogInjectionVulnerabilities {

    let logger = Logger(subsystem: "com.app", category: "security")

    // Test 1: print() with user input
    func logUserAction(username: String) {
        // VULNERABLE: User input in log
        print("User action: \(username)")
    }

    // Test 2: NSLog with user data
    func logLogin(email: String) {
        // VULNERABLE: Email could contain log injection
        NSLog("Login attempt for: %@", email)
    }

    // Test 3: os_log with user input
    func logRequest(path: String) {
        // VULNERABLE: Path from user
        os_log("Request path: %{public}@", path)
    }

    // Test 4: Logger API with user data
    func logActivity(userId: String, action: String) {
        // VULNERABLE: Both parameters from user
        logger.info("User \(userId) performed \(action)")
    }

    // Test 5: Error logging with stack trace manipulation
    func logError(userMessage: String) {
        // VULNERABLE: User can inject fake stack traces
        logger.error("Error occurred: \(userMessage)")
    }

    // Test 6: File logging
    func logToFile(message: String) {
        let logPath = "/var/log/app.log"
        let timestamp = ISO8601DateFormatter().string(from: Date())
        // VULNERABLE: Message injection
        let logLine = "\(timestamp) - \(message)\n"
        if let data = logLine.data(using: .utf8) {
            FileManager.default.createFile(atPath: logPath, contents: data)
        }
    }

    // Test 7: Debug logging with request data
    func logRequest(headers: [String: String]) {
        for (key, value) in headers {
            // VULNERABLE: Header values in logs
            print("Header: \(key) = \(value)")
        }
    }

    // Test 8: Audit log injection
    func auditLog(event: String, details: String) {
        let entry = [
            "timestamp": Date().description,
            "event": event,  // VULNERABLE
            "details": details  // VULNERABLE
        ]
        // Write to audit log
        print("AUDIT: \(entry)")
    }

    // Test 9: JSON in logs
    func logJsonPayload(payload: [String: Any]) {
        if let data = try? JSONSerialization.data(withJSONObject: payload),
           let str = String(data: data, encoding: .utf8) {
            // VULNERABLE: JSON payload could contain log injection
            logger.debug("Payload: \(str)")
        }
    }

    // Test 10: Multi-line log injection
    func logMultiLine(input: String) {
        // VULNERABLE: Newlines allow fake log entries
        logger.info("""
            Processing input:
            \(input)
            End of input
            """)
    }

    // Test 11: Format string vulnerability
    func logFormat(format: String, args: CVarArg...) {
        // VULNERABLE: User-controlled format string
        let message = String(format: format, arguments: args)
        NSLog("%@", message)
    }

    // Test 12: Sensitive data in logs
    func logTransaction(cardNumber: String, amount: Double) {
        // VULNERABLE: Sensitive data logged
        print("Transaction: card=\(cardNumber), amount=\(amount)")
        NSLog("Processing payment for card %@", cardNumber)
    }

    // Test 13: Exception message logging
    func logException(error: Error, context: String) {
        // VULNERABLE: Context from user
        logger.error("Exception in \(context): \(error.localizedDescription)")
    }
}
