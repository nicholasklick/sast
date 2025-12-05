// Information Disclosure vulnerabilities in Scala
package com.example.security

import java.io.File

class InformationDisclosureVulnerabilities {

  // Test 1: Detailed error messages
  def processRequest(data: Array[Byte]): Map[String, Any] = {
    try {
      parseData(data)
    } catch {
      case e: Exception =>
        // VULNERABLE: Detailed error to user
        Map("error" -> s"Parse error: ${e.getMessage}. Stack: ${e.getStackTrace.mkString("\n")}")
    }
  }

  // Test 2: Stack trace exposure
  def handleError(error: Exception): Map[String, Any] = {
    // VULNERABLE: Stack trace in response
    Map(
      "error" -> error.getMessage,
      "stack" -> error.getStackTrace.map(_.toString).toList,
      "cause" -> Option(error.getCause).map(_.getMessage).orNull
    )
  }

  // Test 3: Server version disclosure
  def getServerInfo(): Map[String, String] = {
    // VULNERABLE: Version information
    Map(
      "server" -> "CustomServer/2.1.3",
      "scala_version" -> util.Properties.versionString,
      "java_version" -> System.getProperty("java.version"),
      "os" -> System.getProperty("os.name")
    )
  }

  // Test 4: Database error details
  def executeQuery(sql: String): List[Map[String, Any]] = {
    // VULNERABLE: SQL and internal details exposed
    throw new RuntimeException(s"SQL Error: syntax error near '$sql' at line 42")
  }

  // Test 5: File path disclosure
  def readConfig(): String = {
    val path = "/etc/app/config.json"
    val file = new File(path)
    if (!file.exists()) {
      // VULNERABLE: Full path in error
      throw new java.io.FileNotFoundException(s"Config not found at: $path")
    }
    scala.io.Source.fromFile(file).mkString
  }

  // Test 6: Debug mode information
  def getDebugInfo(): Map[String, Any] = {
    // VULNERABLE: Debug info exposed
    Map(
      "memory_used" -> (Runtime.getRuntime.totalMemory() - Runtime.getRuntime.freeMemory()),
      "environment" -> sys.env,
      "properties" -> System.getProperties
    )
  }

  // Test 7: User enumeration
  def checkUser(email: String): String = {
    if (userExists(email)) {
      // VULNERABLE: Reveals user existence
      "User exists, check your password"
    } else {
      "No user found with this email"
    }
  }

  // Test 8: Timing-based information leak
  def verifyCredentials(username: String, password: String): Boolean = {
    findUser(username) match {
      case None => false // VULNERABLE: Fast return reveals user doesn't exist
      case Some(user) => verifyPassword(password, user.passwordHash)
    }
  }

  // Test 9: Internal IP disclosure
  def getNetworkInfo(): Map[String, Any] = {
    // VULNERABLE: Internal network info
    Map(
      "internal_ip" -> java.net.InetAddress.getLocalHost.getHostAddress,
      "hostname" -> java.net.InetAddress.getLocalHost.getHostName
    )
  }

  // Test 10: Directory listing
  def listDirectory(path: String): List[String] = {
    // VULNERABLE: Listing arbitrary directories
    new File(path).listFiles().map(_.getName).toList
  }

  // Test 11: Verbose response
  def processTransaction(transactionId: String): Map[String, Any] = {
    // VULNERABLE: Internal details in response
    Map(
      "status" -> "processed",
      "internal_id" -> java.util.UUID.randomUUID().toString,
      "server_node" -> "server-02.internal",
      "db_replica" -> "db-replica-3"
    )
  }

  // Test 12: Exception type disclosure
  def parseXml(data: String): Any = {
    try {
      scala.xml.XML.loadString(data)
    } catch {
      case e: Exception =>
        // VULNERABLE: Full exception details
        throw new RuntimeException(s"XML Error: ${e.getClass.getName} - ${e.getMessage}")
    }
  }

  // Test 13: Akka actor path exposure
  def exposeActorPath(): String = {
    // VULNERABLE: Internal actor paths
    "akka://system/user/internal-processor"
  }

  private def parseData(data: Array[Byte]): Map[String, Any] = Map.empty
  private def userExists(email: String): Boolean = false
  private def findUser(username: String): Option[UserRecord] = None
  private def verifyPassword(password: String, hash: String): Boolean = false
}

case class UserRecord(username: String, passwordHash: String)
