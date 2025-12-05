// Log Injection vulnerabilities in Scala
package com.example.security

import org.slf4j.LoggerFactory
import java.util.logging.Logger

class LogInjectionVulnerabilities {

  private val slf4jLogger = LoggerFactory.getLogger(classOf[LogInjectionVulnerabilities])
  private val javaLogger = Logger.getLogger("security")

  // Test 1: println with user input
  def logUserAction(username: String): Unit = {
    // VULNERABLE: User input directly in log
    println(s"User action: $username")
  }

  // Test 2: SLF4J with user input
  def logLogin(email: String): Unit = {
    // VULNERABLE: Email could contain log injection
    slf4jLogger.info(s"Login attempt for: $email")
  }

  // Test 3: Java util logging
  def logRequest(path: String): Unit = {
    // VULNERABLE: Path from user
    javaLogger.info(s"Request path: $path")
  }

  // Test 4: Log forging with newlines
  def logActivity(userId: String, action: String): Unit = {
    // VULNERABLE: Can forge log entries with newlines
    slf4jLogger.info(s"User $userId performed $action")
  }

  // Test 5: Error logging with user message
  def logError(userMessage: String): Unit = {
    // VULNERABLE: User can inject fake errors
    slf4jLogger.error(s"Error occurred: $userMessage")
  }

  // Test 6: File logging
  def logToFile(message: String): Unit = {
    import java.io._
    val logFile = new File("/var/log/app.log")
    // VULNERABLE: Message injection
    val writer = new FileWriter(logFile, true)
    writer.write(s"${java.time.Instant.now()} - $message\n")
    writer.close()
  }

  // Test 7: HTTP header logging
  def logHeaders(headers: Map[String, String]): Unit = {
    headers.foreach { case (key, value) =>
      // VULNERABLE: Header values in logs
      slf4jLogger.debug(s"Header: $key = $value")
    }
  }

  // Test 8: Audit log injection
  def auditLog(event: String, details: String): Unit = {
    // VULNERABLE: Both from user input
    javaLogger.info(s"AUDIT: event=$event, details=$details")
  }

  // Test 9: JSON payload logging
  def logPayload(payload: String): Unit = {
    // VULNERABLE: JSON payload could contain injection
    slf4jLogger.debug(s"Received payload: $payload")
  }

  // Test 10: Format string (Scala string interpolation)
  def logFormat(format: String, args: Any*): Unit = {
    // VULNERABLE: User-controlled format
    println(format.format(args: _*))
  }

  // Test 11: Sensitive data in logs
  def logTransaction(cardNumber: String, amount: Double): Unit = {
    // VULNERABLE: Sensitive data logged
    slf4jLogger.info(s"Transaction: card=$cardNumber, amount=$amount")
  }

  // Test 12: Exception context logging
  def logException(error: Exception, context: String): Unit = {
    // VULNERABLE: Context from user
    slf4jLogger.error(s"Exception in $context", error)
  }

  // Test 13: Multi-line log
  def logMultiLine(input: String): Unit = {
    // VULNERABLE: Newlines allow fake entries
    slf4jLogger.info(
      s"""Processing input:
         |$input
         |End of input""".stripMargin)
  }
}
