// Insecure Randomness vulnerabilities in Scala
package com.example.security

import java.util.Random
import scala.util.Random as ScalaRandom

class InsecureRandomVulnerabilities {

  // Test 1: java.util.Random for security
  def generateToken(): String = {
    // VULNERABLE: Not cryptographically secure
    val random = new Random()
    (1 to 32).map(_ => "%02x".format(random.nextInt(256))).mkString
  }

  // Test 2: scala.util.Random for security
  def generateScalaToken(): String = {
    // VULNERABLE: scala.util.Random not crypto secure
    ScalaRandom.alphanumeric.take(32).mkString
  }

  // Test 3: Seeded random with predictable seed
  def generateWithSeed(): Int = {
    // VULNERABLE: Time-based seed is predictable
    val random = new Random(System.currentTimeMillis())
    random.nextInt()
  }

  // Test 4: Math.random for security
  def generateOtp(): String = {
    // VULNERABLE: Math.random not crypto secure
    val otp = (Math.random() * 1000000).toInt
    f"$otp%06d"
  }

  // Test 5: Predictable UUID-like ID
  def generateId(userId: Int): String = {
    // VULNERABLE: Predictable ID generation
    s"$userId-${System.currentTimeMillis()}"
  }

  // Test 6: Weak password generation
  def generatePassword(length: Int): String = {
    val chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    // VULNERABLE: Non-secure random
    val random = new Random()
    (1 to length).map(_ => chars.charAt(random.nextInt(chars.length))).mkString
  }

  // Test 7: IV generation
  def generateIV(): Array[Byte] = {
    // VULNERABLE: IV should use SecureRandom
    val random = new Random()
    val iv = new Array[Byte](16)
    random.nextBytes(iv)
    iv
  }

  // Test 8: Salt generation
  def generateSalt(): Array[Byte] = {
    // VULNERABLE: Salt should use SecureRandom
    val random = new Random()
    val salt = new Array[Byte](32)
    random.nextBytes(salt)
    salt
  }

  // Test 9: Nonce generation
  def generateNonce(): Long = {
    // VULNERABLE: Predictable nonce
    System.nanoTime()
  }

  // Test 10: CSRF token
  def generateCsrfToken(): String = {
    // VULNERABLE: Not crypto random
    ScalaRandom.nextLong().toHexString
  }

  // Test 11: Shuffling for security
  def shuffleSecure[T](items: Seq[T]): Seq[T] = {
    // VULNERABLE: shuffle uses non-secure random
    ScalaRandom.shuffle(items)
  }

  // Test 12: Email verification code
  def generateVerificationCode(): String = {
    // VULNERABLE: Predictable code
    val random = new Random()
    (1 to 6).map(_ => random.nextInt(10)).mkString
  }

  // Test 13: ThreadLocalRandom for secrets
  def generateApiKey(): String = {
    // VULNERABLE: Not designed for cryptography
    val random = java.util.concurrent.ThreadLocalRandom.current()
    val bytes = new Array[Byte](32)
    random.nextBytes(bytes)
    bytes.map("%02x".format(_)).mkString
  }

  // Secure alternative
  def secureRandom(size: Int): Array[Byte] = {
    val random = new java.security.SecureRandom()
    val bytes = new Array[Byte](size)
    random.nextBytes(bytes)
    bytes
  }
}
