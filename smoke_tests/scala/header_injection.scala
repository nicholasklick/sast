// HTTP Header Injection vulnerabilities in Scala
package com.example.security

class HeaderInjectionVulnerabilities {

  // Test 1: User input in response header
  def setCustomHeader(response: HttpResponse, userValue: String): HttpResponse = {
    // VULNERABLE: User value in header
    response.withHeader("X-Custom-Header", userValue)
  }

  // Test 2: Cookie value injection
  def setCookie(name: String, value: String): String = {
    // VULNERABLE: Both name and value from user
    s"Set-Cookie: $name=$value"
  }

  // Test 3: Location header injection
  def redirectHeader(location: String): HttpResponse = {
    // VULNERABLE: Location from user
    HttpResponse(302).withHeader("Location", location)
  }

  // Test 4: Content-Type injection
  def setContentType(contentType: String): HttpResponse = {
    // VULNERABLE: Content-Type from user
    HttpResponse(200).withHeader("Content-Type", contentType)
  }

  // Test 5: Cache-Control manipulation
  def setCacheControl(directive: String): HttpResponse = {
    // VULNERABLE: Directive from user
    HttpResponse(200).withHeader("Cache-Control", directive)
  }

  // Test 6: CORS header injection
  def setCorsOrigin(origin: String): HttpResponse = {
    // VULNERABLE: Origin reflected without validation
    HttpResponse(200).withHeader("Access-Control-Allow-Origin", origin)
  }

  // Test 7: Content-Disposition injection
  def setDownloadHeader(filename: String): HttpResponse = {
    // VULNERABLE: Filename from user
    HttpResponse(200).withHeader("Content-Disposition", s"""attachment; filename="$filename"""")
  }

  // Test 8: WWW-Authenticate injection
  def setAuthHeader(realm: String): HttpResponse = {
    // VULNERABLE: Realm from user
    HttpResponse(401).withHeader("WWW-Authenticate", s"""Basic realm="$realm"""")
  }

  // Test 9: Link header injection
  def setLinkHeader(url: String, rel: String): HttpResponse = {
    // VULNERABLE: Both URL and rel from user
    HttpResponse(200).withHeader("Link", s"""<$url>; rel="$rel"""")
  }

  // Test 10: Response splitting via newlines
  def setHeaderWithNewlines(value: String): HttpResponse = {
    // VULNERABLE: Newlines allow header injection
    HttpResponse(200).withHeader("X-Custom", value)
  }

  // Test 11: Play Framework headers
  def playHeaders(key: String, value: String): Map[String, String] = {
    // VULNERABLE: Both from user
    Map(key -> value)
  }

  // Test 12: Akka HTTP header
  def akkaHeader(headerName: String, headerValue: String): String = {
    // VULNERABLE: Header from user
    s"RawHeader($headerName, $headerValue)"
  }

  // Test 13: Host header injection
  def setHostHeader(host: String): HttpResponse = {
    // VULNERABLE: Host from user
    HttpResponse(200).withHeader("Host", host)
  }
}

// Mock HTTP types
case class HttpResponse(status: Int, headers: Map[String, String] = Map.empty) {
  def withHeader(name: String, value: String): HttpResponse =
    copy(headers = headers + (name -> value))
}
