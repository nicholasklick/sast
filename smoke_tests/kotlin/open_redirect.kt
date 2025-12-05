// Open Redirect vulnerabilities in Kotlin
package com.example.security

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class OpenRedirectVulnerabilities {

    // Test 1: Direct redirect from parameter
    fun handleRedirect(request: HttpServletRequest, response: HttpServletResponse) {
        val redirectUrl = request.getParameter("url")
        // VULNERABLE: User-controlled redirect
        response.sendRedirect(redirectUrl)
    }

    // Test 2: Return URL redirect
    fun loginRedirect(request: HttpServletRequest, response: HttpServletResponse) {
        val returnUrl = request.getParameter("returnUrl")
        if (authenticate(request)) {
            // VULNERABLE: returnUrl from user
            response.sendRedirect(returnUrl)
        }
    }

    // Test 3: Weak validation
    fun safeRedirect(request: HttpServletRequest, response: HttpServletResponse) {
        val url = request.getParameter("redirect")
        // VULNERABLE: Weak validation (example.com.evil.com passes)
        if (url?.contains("example.com") == true) {
            response.sendRedirect(url)
        }
    }

    // Test 4: Protocol-relative redirect
    fun protocolRelativeRedirect(path: String, response: HttpServletResponse) {
        // VULNERABLE: Protocol-relative URL
        response.sendRedirect("//$path")
    }

    // Test 5: Logout redirect
    fun logout(request: HttpServletRequest, response: HttpServletResponse) {
        clearSession(request)
        val redirectUrl = request.getParameter("next")
        // VULNERABLE: Post-logout redirect
        response.sendRedirect(redirectUrl ?: "/")
    }

    // Test 6: OAuth callback
    fun handleOAuthCallback(request: HttpServletRequest, response: HttpServletResponse) {
        val redirectUri = request.getParameter("redirect_uri")
        // VULNERABLE: OAuth redirect URI
        response.sendRedirect(redirectUri)
    }

    // Test 7: Error page redirect
    fun errorRedirect(request: HttpServletRequest, response: HttpServletResponse) {
        val returnPath = request.getParameter("return")
        // VULNERABLE: Return path from parameter
        response.sendRedirect("/error?return=$returnPath")
    }

    // Test 8: Location header injection
    fun setLocationHeader(url: String, response: HttpServletResponse) {
        // VULNERABLE: Direct header set
        response.setHeader("Location", url)
        response.status = 302
    }

    // Test 9: JavaScript redirect
    fun jsRedirect(url: String): String {
        // VULNERABLE: JavaScript redirect
        return "<script>window.location='$url'</script>"
    }

    // Test 10: Meta refresh redirect
    fun metaRedirect(url: String): String {
        // VULNERABLE: Meta tag redirect
        return "<meta http-equiv=\"refresh\" content=\"0;url=$url\">"
    }

    // Test 11: Prefix validation bypass
    fun prefixValidatedRedirect(request: HttpServletRequest, response: HttpServletResponse) {
        val url = request.getParameter("url") ?: ""
        // VULNERABLE: Can bypass with https://example.com@evil.com
        if (url.startsWith("https://example.com")) {
            response.sendRedirect(url)
        }
    }

    // Test 12: Path-based redirect
    fun pathRedirect(path: String, response: HttpServletResponse) {
        // VULNERABLE: Path can be //evil.com
        response.sendRedirect(path)
    }

    private fun authenticate(request: HttpServletRequest): Boolean = true
    private fun clearSession(request: HttpServletRequest) {}
}
