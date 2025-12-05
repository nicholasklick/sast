// Cross-Site Request Forgery (CSRF) vulnerabilities in Scala
package com.example.security

class CsrfVulnerabilities {

  // Test 1: State-changing GET request
  def handleGetRequest(action: String, userId: Int): Unit = {
    // VULNERABLE: State change via GET
    action match {
      case "delete" => deleteUser(userId)
      case "promote" => promoteUser(userId)
      case _ => ()
    }
  }

  // Test 2: Missing CSRF token
  def handlePostRequest(params: Map[String, String]): String = {
    // VULNERABLE: No CSRF token validation
    params.get("action").foreach(performAction)
    "success"
  }

  // Test 3: CSRF token in URL
  def generateFormUrl(token: String): String = {
    // VULNERABLE: Token visible in URL
    s"https://example.com/action?csrf_token=$token"
  }

  // Test 4: Predictable CSRF token
  def generateCsrfToken(userId: Int): String = {
    // VULNERABLE: Predictable token
    s"csrf_${userId}_${System.currentTimeMillis()}"
  }

  // Test 5: Token without session binding
  private val validTokens = scala.collection.mutable.Set[String]()

  def validateCsrfToken(token: String): Boolean = {
    // VULNERABLE: Not bound to user session
    validTokens.contains(token)
  }

  // Test 6: Cookie without SameSite (Play Framework style)
  def setCookie(token: String): String = {
    // VULNERABLE: Missing SameSite attribute
    s"session=$token; Path=/; HttpOnly"
  }

  // Test 7: CORS misconfiguration
  def handleCorsRequest(origin: String): Map[String, String] = {
    // VULNERABLE: Reflecting arbitrary origin
    Map(
      "Access-Control-Allow-Origin" -> origin,
      "Access-Control-Allow-Credentials" -> "true"
    )
  }

  // Test 8: JSON endpoint without CSRF
  def handleJsonPost(json: String): Map[String, Any] = {
    // VULNERABLE: JSON POST without CSRF protection
    processJson(json)
  }

  // Test 9: Form without token
  def renderForm(): String = {
    // VULNERABLE: No CSRF token in form
    """
      |<form action="/transfer" method="POST">
      |  <input name="amount" type="text">
      |  <input name="recipient" type="text">
      |  <button type="submit">Transfer</button>
      |</form>
    """.stripMargin
  }

  // Test 10: Token reuse
  private val tokenCache = scala.collection.mutable.Map[String, String]()

  def getCsrfToken(sessionId: String): String = {
    // VULNERABLE: Same token reused
    tokenCache.getOrElseUpdate(sessionId, java.util.UUID.randomUUID().toString)
  }

  // Test 11: Referer-only validation
  def validateRequest(referer: Option[String]): Boolean = {
    // VULNERABLE: Referer can be spoofed
    referer.exists(_.contains("example.com"))
  }

  // Test 12: Play Framework without CSRF filter
  def playAction(request: Request): String = {
    // VULNERABLE: Action without CSRF check
    "Action executed"
  }

  private def deleteUser(userId: Int): Unit = ()
  private def promoteUser(userId: Int): Unit = ()
  private def performAction(action: String): Unit = ()
  private def processJson(json: String): Map[String, Any] = Map.empty
}

case class Request(body: String)
