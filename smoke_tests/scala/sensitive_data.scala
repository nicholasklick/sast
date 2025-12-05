// Sensitive Data Exposure vulnerabilities in Scala
package com.example.security

import java.io.{File, FileWriter}

class SensitiveDataExposure {

  // Test 1: Hardcoded API key
  def makeApiCall(): Unit = {
    // VULNERABLE: Hardcoded API key
    val apiKey = "sk-live-abcd1234567890xyz"
    // Use API key
  }

  // Test 2: Hardcoded database credentials
  def connectToDatabase(): Unit = {
    // VULNERABLE: Hardcoded credentials
    val username = "admin"
    val password = "SuperSecret123!"
    val connectionString = s"jdbc:mysql://db.example.com/production?user=$username&password=$password"
  }

  // Test 3: Private key in code
  def signData(data: Array[Byte]): Unit = {
    // VULNERABLE: Private key embedded
    val privateKey =
      """-----BEGIN RSA PRIVATE KEY-----
        |MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy...
        |-----END RSA PRIVATE KEY-----""".stripMargin
  }

  // Test 4: Sensitive data in URL
  def fetchUserData(userId: String, ssn: String): Unit = {
    // VULNERABLE: SSN in URL
    val url = s"https://api.example.com/user/$userId?ssn=$ssn"
  }

  // Test 5: Credit card in logs
  def processPayment(cardNumber: String, cvv: String): Unit = {
    // VULNERABLE: Card data logged
    println(s"Processing card: $cardNumber")
  }

  // Test 6: PII stored unencrypted
  def storePii(ssn: String, dob: String): Unit = {
    // VULNERABLE: Plaintext storage
    val file = new File("user_data.txt")
    val writer = new FileWriter(file)
    writer.write(s"ssn=$ssn\ndob=$dob")
    writer.close()
  }

  // Test 7: Password in error message
  def validateCredentials(username: String, password: String): Unit = {
    // VULNERABLE: Password in error
    if (!isValidPassword(password)) {
      throw new IllegalArgumentException(s"Invalid password: $password")
    }
  }

  // Test 8: AWS credentials
  def configureAws(): Unit = {
    // VULNERABLE: AWS credentials in code
    val accessKey = "AKIAIOSFODNN7EXAMPLE"
    val secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  }

  // Test 9: Session token in response
  def handleAuthResponse(): Map[String, String] = {
    val token = generateToken()
    val refreshToken = generateRefreshToken()
    // VULNERABLE: Exposing all tokens
    Map(
      "access_token" -> token,
      "refresh_token" -> refreshToken,
      "internal_id" -> "internal-123"
    )
  }

  // Test 10: Encryption key hardcoded
  def encryptData(data: Array[Byte]): Array[Byte] = {
    // VULNERABLE: Hardcoded encryption key
    val key = "MySecretEncryptionKey123"
    encrypt(data, key)
  }

  // Test 11: Database connection string
  def getConnectionString(): String = {
    // VULNERABLE: Full connection string with password
    "Server=db.example.com;Database=prod;User Id=admin;Password=P@ssw0rd123;"
  }

  // Test 12: OAuth client secret
  def getOAuthConfig(): Map[String, String] = {
    // VULNERABLE: Client secret in code
    Map(
      "client_id" -> "app-client-id",
      "client_secret" -> "super-secret-oauth-client-secret"
    )
  }

  // Test 13: Cookie without secure flag
  def setSessionCookie(token: String): String = {
    // VULNERABLE: Missing Secure flag
    s"session=$token; Path=/; HttpOnly"
  }

  private def isValidPassword(password: String): Boolean = true
  private def generateToken(): String = "token"
  private def generateRefreshToken(): String = "refresh"
  private def encrypt(data: Array[Byte], key: String): Array[Byte] = data
}
