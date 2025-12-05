// Open Redirect vulnerabilities in Scala
package com.example.security

class OpenRedirectVulnerabilities {

  // Test 1: Direct redirect from parameter
  def handleRedirect(redirectUrl: String): Response = {
    // VULNERABLE: User-controlled redirect
    Redirect(redirectUrl)
  }

  // Test 2: Return URL redirect
  def loginRedirect(returnUrl: String, authenticated: Boolean): Response = {
    if (authenticated) {
      // VULNERABLE: returnUrl from user
      Redirect(returnUrl)
    } else {
      Unauthorized()
    }
  }

  // Test 3: Weak validation
  def safeRedirect(url: String): Response = {
    // VULNERABLE: Weak validation (example.com.evil.com passes)
    if (url.contains("example.com")) {
      Redirect(url)
    } else {
      BadRequest()
    }
  }

  // Test 4: Protocol-relative redirect
  def protocolRelativeRedirect(path: String): Response = {
    // VULNERABLE: Protocol-relative URL
    Redirect(s"//$path")
  }

  // Test 5: Logout redirect
  def logout(redirectUrl: String): Response = {
    clearSession()
    // VULNERABLE: Post-logout redirect
    Redirect(redirectUrl)
  }

  // Test 6: Play Framework redirect (conceptual)
  def playRedirect(url: String): String = {
    // VULNERABLE: Play redirect
    s"Redirect($url)"
  }

  // Test 7: Akka HTTP redirect
  def akkaRedirect(location: String): Response = {
    // VULNERABLE: Location from user
    RedirectWithHeader(location)
  }

  // Test 8: Error page redirect
  def errorRedirect(returnPath: String): Response = {
    // VULNERABLE: Return path from parameter
    Redirect(s"/error?return=$returnPath")
  }

  // Test 9: JavaScript redirect
  def jsRedirect(url: String): String = {
    // VULNERABLE: JavaScript redirect
    s"<script>window.location='$url'</script>"
  }

  // Test 10: Meta refresh redirect
  def metaRedirect(url: String): String = {
    // VULNERABLE: Meta tag redirect
    s"""<meta http-equiv="refresh" content="0;url=$url">"""
  }

  // Test 11: Prefix validation bypass
  def prefixValidatedRedirect(url: String): Response = {
    // VULNERABLE: Can bypass with https://example.com@evil.com
    if (url.startsWith("https://example.com")) {
      Redirect(url)
    } else {
      BadRequest()
    }
  }

  // Test 12: http4s redirect
  def http4sRedirect(uri: String): String = {
    // VULNERABLE: URI from user
    s"Response.seeOther(Uri.unsafeFromString($uri))"
  }

  private def clearSession(): Unit = ()
}

// Mock response types
case class Response(status: Int = 200)
case class Redirect(url: String) extends Response(302)
case class RedirectWithHeader(location: String) extends Response(302)
case class Unauthorized() extends Response(401)
case class BadRequest() extends Response(400)
