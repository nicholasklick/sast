// Server-Side Request Forgery (SSRF) vulnerabilities in Scala
package com.example.security

import java.net.{URL, HttpURLConnection}
import scala.io.Source

class SsrfVulnerabilities {

  // Test 1: Direct URL fetch
  def fetchUrl(urlString: String): String = {
    // VULNERABLE: User-controlled URL
    val url = new URL(urlString)
    Source.fromURL(url).mkString
  }

  // Test 2: Image proxy
  def proxyImage(imageUrl: String): Array[Byte] = {
    // VULNERABLE: Fetching arbitrary URLs
    val url = new URL(imageUrl)
    val connection = url.openConnection()
    val stream = connection.getInputStream
    Stream.continually(stream.read).takeWhile(_ != -1).map(_.toByte).toArray
  }

  // Test 3: Webhook URL
  def sendWebhook(webhookUrl: String, payload: String): Int = {
    // VULNERABLE: Webhook destination from user
    val url = new URL(webhookUrl)
    val connection = url.openConnection().asInstanceOf[HttpURLConnection]
    connection.setRequestMethod("POST")
    connection.setDoOutput(true)
    connection.getOutputStream.write(payload.getBytes)
    connection.getResponseCode
  }

  // Test 4: Partial URL construction
  def fetchFromHost(hostname: String): String = {
    // VULNERABLE: User controls hostname
    val url = new URL(s"http://$hostname/api/data")
    Source.fromURL(url).mkString
  }

  // Test 5: Port scanning
  def checkPort(host: String, port: Int): Boolean = {
    // VULNERABLE: Port from user
    try {
      val url = new URL(s"http://$host:$port/")
      val connection = url.openConnection().asInstanceOf[HttpURLConnection]
      connection.setConnectTimeout(1000)
      connection.connect()
      true
    } catch {
      case _: Exception => false
    }
  }

  // Test 6: Akka HTTP client (conceptual)
  def akkaHttpRequest(targetUrl: String): String = {
    // VULNERABLE: User URL with Akka HTTP
    s"Http().singleRequest(HttpRequest(uri = $targetUrl))"
  }

  // Test 7: File protocol SSRF
  def readResource(uri: String): String = {
    // VULNERABLE: Can use file:// protocol
    val url = new URL(uri)
    Source.fromURL(url).mkString
  }

  // Test 8: Redirect following
  def fetchWithRedirects(urlString: String): String = {
    val url = new URL(urlString)
    val connection = url.openConnection().asInstanceOf[HttpURLConnection]
    // VULNERABLE: Following redirects to internal
    connection.setInstanceFollowRedirects(true)
    Source.fromInputStream(connection.getInputStream).mkString
  }

  // Test 9: DNS rebinding
  def fetchExternal(domain: String, path: String): String = {
    // VULNERABLE: DNS can resolve to internal IP
    val url = new URL(s"http://$domain/$path")
    Source.fromURL(url).mkString
  }

  // Test 10: sttp client
  def sttpRequest(targetUrl: String): String = {
    // VULNERABLE: User URL with sttp
    s"basicRequest.get(uri\"$targetUrl\")"
  }

  // Test 11: API endpoint construction
  def callExternalApi(baseUrl: String, endpoint: String): String = {
    // VULNERABLE: Both from user
    val url = new URL(s"$baseUrl/$endpoint")
    Source.fromURL(url).mkString
  }

  // Test 12: Play WS client
  def playWsRequest(targetUrl: String): String = {
    // VULNERABLE: User URL with Play WS
    s"ws.url($targetUrl).get()"
  }
}
