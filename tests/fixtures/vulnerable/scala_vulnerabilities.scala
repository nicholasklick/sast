// Scala Vulnerability Test Fixtures
package com.example.vulnerabilities

import java.sql.{Connection, DriverManager, Statement}
import java.io.{File, ObjectInputStream, ByteArrayInputStream}
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import scala.sys.process._
import scala.io.Source

class ScalaVulnerabilities {

  // 1. SQL Injection - String interpolation
  def sqlInjectionInterpolation(userId: String): Option[String] = {
    val connection = DriverManager.getConnection("jdbc:mysql://localhost/db")
    val statement = connection.createStatement()
    val query = s"SELECT * FROM users WHERE id = '$userId'"
    val resultSet = statement.executeQuery(query)
    if (resultSet.next()) Some(resultSet.getString("name")) else None
  }

  // 2. SQL Injection - String concatenation
  def sqlInjectionConcat(username: String): Boolean = {
    val connection = DriverManager.getConnection("jdbc:mysql://localhost/db")
    val query = "SELECT * FROM users WHERE username = '" + username + "'"
    val statement = connection.createStatement()
    val resultSet = statement.executeQuery(query)
    resultSet.next()
  }

  // 3. Command Injection - scala.sys.process
  def commandInjection(filename: String): Int = {
    s"cat $filename".!
  }

  // 4. Command Injection - Process with string interpolation
  def commandInjectionProcess(userInput: String): String = {
    val command = s"ls -la $userInput"
    command.!!
  }

  // 5. Path Traversal
  def pathTraversal(filename: String): String = {
    val file = new File(s"/var/data/$filename")
    Source.fromFile(file).mkString
  }

  // 6. Hardcoded Credentials - API Key
  val apiKey: String = "sk_live_abcdef1234567890"

  // 7. Hardcoded Credentials - Database
  def connectToDatabase(): Connection = {
    val password = "SuperSecret456!"
    DriverManager.getConnection("jdbc:mysql://localhost/db", "admin", password)
  }

  // 8. Weak Cryptography - DES
  def weakCryptoDes(data: Array[Byte]): Array[Byte] = {
    val key = new SecretKeySpec("12345678".getBytes, "DES")
    val cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key)
    cipher.doFinal(data)
  }

  // 9. Weak Cryptography - MD5
  def weakHashMd5(input: String): String = {
    val md = java.security.MessageDigest.getInstance("MD5")
    md.digest(input.getBytes).map("%02x".format(_)).mkString
  }

  // 10. XXE Vulnerability
  def parseXml(xmlContent: String): Unit = {
    val factory = javax.xml.parsers.DocumentBuilderFactory.newInstance()
    // Missing secure processing features
    val builder = factory.newDocumentBuilder()
    val doc = builder.parse(new ByteArrayInputStream(xmlContent.getBytes))
  }

  // 11. Insecure Deserialization
  def deserializeObject(data: Array[Byte]): AnyRef = {
    val ois = new ObjectInputStream(new ByteArrayInputStream(data))
    ois.readObject()
  }

  // 12. LDAP Injection
  def ldapInjection(username: String): Boolean = {
    val env = new java.util.Hashtable[String, String]()
    env.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory")
    env.put("java.naming.provider.url", "ldap://localhost:389")
    val ctx = new javax.naming.directory.InitialDirContext(env)
    val filter = s"(uid=$username)"
    val results = ctx.search("ou=users,dc=example,dc=com", filter, null)
    results.hasMore
  }

  // 13. SSRF Vulnerability
  def fetchUrl(url: String): String = {
    Source.fromURL(url).mkString
  }

  // 14. Unsafe Random Number Generation
  def generateToken(): String = {
    val random = new scala.util.Random()
    random.nextLong().toString
  }

  // 15. Template Injection (Play Framework pattern)
  def renderTemplate(userInput: String): String = {
    s"<html><body><h1>Welcome $userInput</h1></body></html>"
  }

  // 16. NoSQL Injection (MongoDB pattern)
  def mongoQuery(userId: String): Unit = {
    val query = s"""{ "userId": "$userId" }"""
    // db.collection.find(query) - vulnerable to injection
  }

  // 17. Open Redirect
  def redirect(url: String): Unit = {
    // response.redirect(url) - vulnerable to open redirect
    println(s"Redirecting to: $url")
  }

  // 18. Zip Slip Vulnerability
  def extractZip(zipEntry: java.util.zip.ZipEntry, targetDir: String): File = {
    val targetFile = new File(targetDir, zipEntry.getName)
    // Missing path traversal check
    targetFile
  }
}
