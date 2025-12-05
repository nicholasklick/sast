// Authentication vulnerabilities in Scala
package com.example.security

import java.security.MessageDigest
import java.util.Base64
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

class AuthenticationVulnerabilities {

  // Test 1: Hardcoded credentials
  def authenticate(username: String, password: String): Boolean = {
    // VULNERABLE: Hardcoded credentials
    username == "admin" && password == "admin123"
  }

  // Test 2: MD5 password hashing
  def hashPasswordMd5(password: String): String = {
    // VULNERABLE: MD5 is cryptographically broken
    val md = MessageDigest.getInstance("MD5")
    val digest = md.digest(password.getBytes)
    digest.map("%02x".format(_)).mkString
  }

  // Test 3: SHA1 without salt
  def hashPasswordSha1(password: String): String = {
    // VULNERABLE: Unsalted SHA1
    val md = MessageDigest.getInstance("SHA-1")
    val digest = md.digest(password.getBytes)
    digest.map("%02x".format(_)).mkString
  }

  // Test 4: Password in logs
  def loginWithLogging(username: String, password: String): Boolean = {
    // VULNERABLE: Password logged
    println(s"Login attempt: $username / $password")
    authenticate(username, password)
  }

  // Test 5: Timing attack vulnerable comparison
  def verifyPassword(input: String, stored: String): Boolean = {
    // VULNERABLE: Non-constant time comparison
    input == stored
  }

  // Test 6: Weak password requirements
  def validatePassword(password: String): Boolean = {
    // VULNERABLE: Too weak requirements
    password.length >= 4
  }

  // Test 7: Predictable session token
  def generateSessionToken(userId: Int): String = {
    // VULNERABLE: Predictable token
    val timestamp = System.currentTimeMillis()
    s"$userId-$timestamp"
  }

  // Test 8: Weak PBKDF2 iterations
  def hashPasswordPbkdf2(password: String, salt: Array[Byte]): Array[Byte] = {
    // VULNERABLE: Too few iterations
    val spec = new PBEKeySpec(password.toCharArray, salt, 100, 256)
    val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
    factory.generateSecret(spec).getEncoded
  }

  // Test 9: JWT with weak secret
  def createJwt(userId: Int): String = {
    // VULNERABLE: Weak signing secret
    val secret = "secret"
    val header = Base64.getEncoder.encodeToString("""{"alg":"HS256","typ":"JWT"}""".getBytes)
    val payload = Base64.getEncoder.encodeToString(s"""{"userId":$userId}""".getBytes)
    s"$header.$payload.signature"
  }

  // Test 10: Remember me with weak token
  def generateRememberToken(userId: Int): String = {
    // VULNERABLE: Predictable remember me token
    Base64.getEncoder.encodeToString(s"$userId:${System.currentTimeMillis()}".getBytes)
  }

  // Test 11: No account lockout
  def login(username: String, password: String): Boolean = {
    // VULNERABLE: No failed attempt tracking
    checkCredentials(username, password)
  }

  // Test 12: Password stored in plaintext
  def storePassword(userId: Int, password: String): Unit = {
    // VULNERABLE: Plaintext storage
    database.save(s"user_$userId", password)
  }

  // Test 13: Password reset token weak
  def generateResetToken(email: String): String = {
    // VULNERABLE: Predictable reset token
    email.hashCode.toString + System.currentTimeMillis()
  }

  private def checkCredentials(username: String, password: String): Boolean = false
  private val database = new {
    def save(key: String, value: String): Unit = ()
  }
}
