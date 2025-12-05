// Insecure Network Communication vulnerabilities in Scala
package com.example.security

import java.net.{URL, HttpURLConnection}
import javax.net.ssl._
import java.security.cert.X509Certificate
import scala.io.Source

class InsecureNetworkVulnerabilities {

  // Test 1: HTTP instead of HTTPS
  def fetchOverHttp(): String = {
    // VULNERABLE: Using HTTP
    val url = new URL("http://api.example.com/data")
    Source.fromURL(url).mkString
  }

  // Test 2: Trust all certificates
  def createTrustAllManager(): TrustManager = {
    // VULNERABLE: Trust all certs
    new X509TrustManager {
      override def checkClientTrusted(chain: Array[X509Certificate], authType: String): Unit = ()
      override def checkServerTrusted(chain: Array[X509Certificate], authType: String): Unit = ()
      override def getAcceptedIssuers: Array[X509Certificate] = Array.empty
    }
  }

  // Test 3: Disable hostname verification
  def disableHostnameVerification(): HostnameVerifier = {
    // VULNERABLE: Accept any hostname
    (hostname: String, session: SSLSession) => true
  }

  // Test 4: Insecure SSL context
  def createInsecureSslContext(): SSLContext = {
    val trustAllCerts = Array[TrustManager](createTrustAllManager().asInstanceOf[X509TrustManager])
    // VULNERABLE: SSL context trusting all certs
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, trustAllCerts, new java.security.SecureRandom())
    sslContext
  }

  // Test 5: Credentials in URL
  def fetchWithCredsInUrl(): String = {
    // VULNERABLE: Credentials visible
    val url = new URL("https://user:password@api.example.com/data")
    Source.fromURL(url).mkString
  }

  // Test 6: Unencrypted WebSocket
  def connectWebSocket(): String = {
    // VULNERABLE: Using ws:// instead of wss://
    "ws://example.com/socket"
  }

  // Test 7: No certificate pinning
  def fetchWithoutPinning(urlString: String): String = {
    // VULNERABLE: No certificate pinning
    val url = new URL(urlString)
    Source.fromURL(url).mkString
  }

  // Test 8: API key in header
  def fetchWithApiKey(): String = {
    val url = new URL("https://api.example.com/data")
    val connection = url.openConnection().asInstanceOf[HttpURLConnection]
    // VULNERABLE: API key transmitted
    connection.setRequestProperty("X-API-Key", "sk-secret-api-key-12345")
    Source.fromInputStream(connection.getInputStream).mkString
  }

  // Test 9: Logging network responses
  def fetchAndLog(url: URL): String = {
    val response = Source.fromURL(url).mkString
    // VULNERABLE: Logging potentially sensitive response
    println(s"Response: $response")
    response
  }

  // Test 10: Weak TLS version
  def configureWeakTls(): SSLContext = {
    // VULNERABLE: Using weak TLS version
    SSLContext.getInstance("TLSv1")
  }

  // Test 11: Cleartext traffic
  def sendCleartextData(host: String, data: String): Unit = {
    // VULNERABLE: Unencrypted socket
    val socket = new java.net.Socket(host, 80)
    socket.getOutputStream.write(data.getBytes)
    socket.close()
  }

  // Test 12: Basic auth over HTTP
  def basicAuthHttp(username: String, password: String): String = {
    // VULNERABLE: Basic auth over HTTP
    val url = new URL("http://api.example.com/secure")
    val connection = url.openConnection().asInstanceOf[HttpURLConnection]
    val credentials = java.util.Base64.getEncoder.encodeToString(s"$username:$password".getBytes)
    connection.setRequestProperty("Authorization", s"Basic $credentials")
    Source.fromInputStream(connection.getInputStream).mkString
  }

  // Test 13: Akka HTTP insecure (conceptual)
  def akkaHttpInsecure(): String = {
    // VULNERABLE: Allowing insecure connections
    "ConnectionContext.httpsClient(createInsecureSslContext())"
  }
}
