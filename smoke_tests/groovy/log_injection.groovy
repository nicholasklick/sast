// Log Injection vulnerabilities in Groovy
package com.example.security

import org.slf4j.LoggerFactory
import java.util.logging.Logger

class LogInjectionVulnerabilities {

    def slf4jLogger = LoggerFactory.getLogger(LogInjectionVulnerabilities)
    def javaLogger = Logger.getLogger("security")

    // Test 1: println with user input
    void logUserAction(String username) {
        // VULNERABLE: User input directly in log
        println "User action: ${username}"
    }

    // Test 2: SLF4J with user input
    void logLogin(String email) {
        // VULNERABLE: Email could contain log injection
        slf4jLogger.info("Login attempt for: ${email}")
    }

    // Test 3: Java util logging
    void logRequest(String path) {
        // VULNERABLE: Path from user
        javaLogger.info("Request path: ${path}")
    }

    // Test 4: Log forging with newlines
    void logActivity(String userId, String action) {
        // VULNERABLE: Can forge log entries with newlines
        slf4jLogger.info("User ${userId} performed ${action}")
    }

    // Test 5: Error logging with user message
    void logError(String userMessage) {
        // VULNERABLE: User can inject fake errors
        slf4jLogger.error("Error occurred: ${userMessage}")
    }

    // Test 6: File logging
    void logToFile(String message) {
        def logFile = new File("/var/log/app.log")
        // VULNERABLE: Message injection
        logFile.append("${new Date()} - ${message}\n")
    }

    // Test 7: HTTP header logging
    void logHeaders(Map headers) {
        headers.each { key, value ->
            // VULNERABLE: Header values in logs
            slf4jLogger.debug("Header: ${key} = ${value}")
        }
    }

    // Test 8: Audit log injection
    void auditLog(String event, String details) {
        // VULNERABLE: Both from user input
        javaLogger.info("AUDIT: event=${event}, details=${details}")
    }

    // Test 9: JSON payload logging
    void logPayload(String payload) {
        // VULNERABLE: JSON payload could contain injection
        slf4jLogger.debug("Received payload: ${payload}")
    }

    // Test 10: GString interpolation in logs
    void logWithGString(String userInput) {
        // VULNERABLE: GString with user input
        def logMessage = "Processing: ${userInput}"
        slf4jLogger.info(logMessage)
    }

    // Test 11: Sensitive data in logs
    void logTransaction(String cardNumber, double amount) {
        // VULNERABLE: Sensitive data logged
        slf4jLogger.info("Transaction: card=${cardNumber}, amount=${amount}")
    }

    // Test 12: Exception context logging
    void logException(Exception error, String context) {
        // VULNERABLE: Context from user
        slf4jLogger.error("Exception in ${context}", error)
    }

    // Test 13: Multi-line log
    void logMultiLine(String input) {
        // VULNERABLE: Newlines allow fake entries
        slf4jLogger.info("""
            Processing input:
            ${input}
            End of input
        """)
    }
}
