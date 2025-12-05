// Cross-Site Scripting (XSS) vulnerabilities in Scala
package com.example.security

import scala.xml._

class XssVulnerabilities {

  // Test 1: Reflected XSS in response
  def handleRequest(name: String): String = {
    // VULNERABLE: Direct output
    s"<html><body>Hello, $name!</body></html>"
  }

  // Test 2: Stored XSS via database
  def displayComment(commentId: Int): String = {
    val comment = getCommentFromDb(commentId)
    // VULNERABLE: Unsanitized database content
    s"<div class='comment'>$comment</div>"
  }

  // Test 3: DOM XSS setup
  def generateScript(userId: String): String = {
    // VULNERABLE: User data in JavaScript
    s"""
      <script>
        var userId = '$userId';
        document.getElementById('user').innerHTML = userId;
      </script>
    """
  }

  // Test 4: JSON response injection
  def jsonResponse(callback: String, data: String): String = {
    // VULNERABLE: JSONP callback
    s"$callback($data)"
  }

  // Test 5: Attribute injection
  def generateLink(url: String): String = {
    // VULNERABLE: URL in href attribute
    s"""<a href="$url">Click here</a>"""
  }

  // Test 6: XML literal with user input
  def createXmlElement(userContent: String): Elem = {
    // VULNERABLE: User input in XML literal
    <div class="content">{userContent}</div>
  }

  // Test 7: Event handler injection
  def generateButton(handler: String): String = {
    // VULNERABLE: Handler from user
    s"""<button onclick="$handler">Submit</button>"""
  }

  // Test 8: Template interpolation
  def renderTemplate(title: String, content: String): String = {
    // VULNERABLE: Both parameters unescaped
    s"""
      <html>
      <head><title>$title</title></head>
      <body>$content</body>
      </html>
    """
  }

  // Test 9: Play Framework Twirl (conceptual)
  def renderHtml(name: String): String = {
    // VULNERABLE: Raw HTML output
    s"@Html($name)"
  }

  // Test 10: Style injection
  def applyStyle(userStyle: String): String = {
    // VULNERABLE: CSS injection
    s"""<div style="$userStyle">Content</div>"""
  }

  // Test 11: Meta tag injection
  def setMetaTag(content: String): String = {
    // VULNERABLE: Meta refresh injection
    s"""<meta http-equiv="refresh" content="$content">"""
  }

  // Test 12: Iframe source injection
  def embedIframe(src: String): String = {
    // VULNERABLE: javascript: URLs possible
    s"""<iframe src="$src"></iframe>"""
  }

  private def getCommentFromDb(id: Int): String = "comment"
}
