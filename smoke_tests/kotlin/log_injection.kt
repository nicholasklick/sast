// Log Injection vulnerabilities in Kotlin
package com.example.security

import org.slf4j.LoggerFactory
import java.util.logging.Logger

class LogInjectionVulnerabilities {

    private val slf4jLogger = LoggerFactory.getLogger(LogInjectionVulnerabilities::class.java)
    private val javaLogger = Logger.getLogger("security")

    // Test 1: println with user input
    fun logUserAction(username: String) {
        // VULNERABLE: User input directly in log
        println("User action: $username")
    }

    // Test 2: SLF4J with user input
    fun logLogin(email: String) {
        // VULNERABLE: Email could contain log injection
        slf4jLogger.info("Login attempt for: $email")
    }

    // Test 3: Java util logging
    fun logRequest(path: String) {
        // VULNERABLE: Path from user
        javaLogger.info("Request path: $path")
    }

    // Test 4: Log forging with newlines
    fun logActivity(userId: String, action: String) {
        // VULNERABLE: Can forge log entries with newlines
        slf4jLogger.info("User $userId performed $action")
    }

    // Test 5: Error logging with user message
    fun logError(userMessage: String) {
        // VULNERABLE: User can inject fake errors
        slf4jLogger.error("Error occurred: $userMessage")
    }

    // Test 6: File logging
    fun logToFile(message: String) {
        val logFile = java.io.File("/var/log/app.log")
        // VULNERABLE: Message injection
        logFile.appendText("${java.time.Instant.now()} - $message\n")
    }

    // Test 7: HTTP header logging
    fun logHeaders(headers: Map<String, String>) {
        headers.forEach { (key, value) ->
            // VULNERABLE: Header values in logs
            slf4jLogger.debug("Header: $key = $value")
        }
    }

    // Test 8: Audit log injection
    fun auditLog(event: String, details: String) {
        // VULNERABLE: Both from user input
        javaLogger.info("AUDIT: event=$event, details=$details")
    }

    // Test 9: JSON payload logging
    fun logPayload(payload: String) {
        // VULNERABLE: JSON payload could contain injection
        slf4jLogger.debug("Received payload: $payload")
    }

    // Test 10: Multi-line log
    fun logMultiLine(input: String) {
        // VULNERABLE: Newlines allow fake entries
        slf4jLogger.info("""
            Processing input:
            $input
            End of input
        """.trimIndent())
    }

    // Test 11: Format string
    fun logFormat(format: String, vararg args: Any) {
        // VULNERABLE: User-controlled format
        javaLogger.info(String.format(format, *args))
    }

    // Test 12: Sensitive data in logs
    fun logTransaction(cardNumber: String, amount: Double) {
        // VULNERABLE: Sensitive data logged
        slf4jLogger.info("Transaction: card=$cardNumber, amount=$amount")
    }

    // Test 13: Exception context logging
    fun logException(error: Exception, context: String) {
        // VULNERABLE: Context from user
        slf4jLogger.error("Exception in $context", error)
    }

    // Test 14: Log4j style
    fun log4jStyle(message: String) {
        // VULNERABLE: Could contain JNDI lookup strings
        slf4jLogger.info("Message: $message")
    }
}
