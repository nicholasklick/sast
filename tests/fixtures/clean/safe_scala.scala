// Clean Scala code with no vulnerabilities - should produce zero findings
package com.example.safe

import java.sql.{Connection, PreparedStatement}
import java.nio.file.{Paths, Path}
import java.security.{SecureRandom, MessageDigest}
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class SafeScalaCode {

  // 1. Safe SQL Query - Using PreparedStatement
  def getUserById(connection: Connection, userId: Int): Option[String] = {
    val query = "SELECT * FROM users WHERE id = ?"
    val stmt = connection.prepareStatement(query)
    try {
      stmt.setInt(1, userId)
      val resultSet = stmt.executeQuery()
      if (resultSet.next()) Some(resultSet.getString("name")) else None
    } finally {
      stmt.close()
    }
  }

  // 2. Safe File Access - Path validation
  def readFile(filename: String): String = {
    val basePath = Paths.get("/var/data").toAbsolutePath.normalize()
    val filePath = basePath.resolve(filename).normalize()

    // Validate path is within base directory
    if (!filePath.startsWith(basePath)) {
      throw new SecurityException("Path traversal attempt detected")
    }

    scala.io.Source.fromFile(filePath.toFile).mkString
  }

  // 3. Safe Configuration - Environment variable
  def getApiKey(): String = {
    sys.env.getOrElse("API_KEY", throw new IllegalStateException("API_KEY not set"))
  }

  // 4. Safe Cryptography - AES-256
  def encryptData(data: Array[Byte], keyBytes: Array[Byte]): Array[Byte] = {
    val key = new SecretKeySpec(keyBytes, "AES")
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, key)
    cipher.doFinal(data)
  }

  // 5. Safe Hashing - SHA-256
  def hashPassword(password: String): String = {
    val digest = MessageDigest.getInstance("SHA-256")
    digest.digest(password.getBytes).map("%02x".format(_)).mkString
  }

  // 6. Safe Random Number Generation
  def generateSecureToken(): String = {
    val random = new SecureRandom()
    val bytes = new Array[Byte](32)
    random.nextBytes(bytes)
    bytes.map("%02x".format(_)).mkString
  }

  // 7. Safe XML Processing - XXE protection
  def parseXmlSafely(xmlContent: String): Unit = {
    val factory = javax.xml.parsers.DocumentBuilderFactory.newInstance()
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)

    val builder = factory.newDocumentBuilder()
    builder.parse(new java.io.ByteArrayInputStream(xmlContent.getBytes))
  }

  // 8. Safe Command Execution - Validated input
  def listFiles(directory: String): Seq[String] = {
    val allowedDirs = Set("/tmp", "/var/log")
    if (!allowedDirs.contains(directory)) {
      throw new SecurityException("Directory not allowed")
    }

    import scala.sys.process._
    Seq("ls", "-la", directory).!!.split("\n").toSeq
  }

  // 9. Safe URL Fetching - Whitelist validation
  def fetchUrl(url: String): String = {
    val allowedHosts = Set("api.example.com", "data.example.com")
    val uri = new java.net.URI(url)

    if (!allowedHosts.contains(uri.getHost)) {
      throw new SecurityException("Host not allowed")
    }

    scala.io.Source.fromURL(url).mkString
  }

  // 10. Safe Input Validation
  def validateAndSanitize(input: String): String = {
    input.replaceAll("[^a-zA-Z0-9_-]", "")
  }

  // 11. Safe Pattern Matching
  def processUserRole(role: String): String = role match {
    case "admin" | "user" | "guest" => s"Valid role: $role"
    case _ => throw new IllegalArgumentException("Invalid role")
  }

  // 12. Safe Collection Operations
  def filterSensitiveData(data: List[String]): List[String] = {
    data.filter(_.length > 0).map(_.trim)
  }
}
