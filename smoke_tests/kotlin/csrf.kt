// Cross-Site Request Forgery (CSRF) vulnerabilities in Kotlin
package com.example.security

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class CsrfVulnerabilities {

    // Test 1: State-changing GET request
    fun handleGetRequest(request: HttpServletRequest) {
        val action = request.getParameter("action")
        val userId = request.getParameter("userId")?.toInt() ?: return
        // VULNERABLE: State change via GET
        when (action) {
            "delete" -> deleteUser(userId)
            "promote" -> promoteUser(userId)
        }
    }

    // Test 2: Missing CSRF token
    fun handlePostRequest(request: HttpServletRequest): String {
        // VULNERABLE: No CSRF token validation
        val action = request.getParameter("action")
        performAction(action)
        return "success"
    }

    // Test 3: CSRF token in URL
    fun generateFormUrl(token: String): String {
        // VULNERABLE: Token visible in URL
        return "https://example.com/action?csrf_token=$token"
    }

    // Test 4: Predictable CSRF token
    fun generateCsrfToken(userId: Int): String {
        // VULNERABLE: Predictable token
        return "csrf_${userId}_${System.currentTimeMillis()}"
    }

    // Test 5: Token without session binding
    private val validTokens = mutableSetOf<String>()

    fun validateCsrfToken(token: String): Boolean {
        // VULNERABLE: Not bound to user session
        return validTokens.contains(token)
    }

    // Test 6: Cookie without SameSite
    fun setCookie(response: HttpServletResponse, token: String) {
        // VULNERABLE: Missing SameSite attribute
        response.setHeader("Set-Cookie", "session=$token; Path=/; HttpOnly")
    }

    // Test 7: CORS misconfiguration
    fun handleCorsRequest(request: HttpServletRequest, response: HttpServletResponse) {
        val origin = request.getHeader("Origin")
        // VULNERABLE: Reflecting arbitrary origin
        response.setHeader("Access-Control-Allow-Origin", origin)
        response.setHeader("Access-Control-Allow-Credentials", "true")
    }

    // Test 8: JSON endpoint without CSRF
    fun handleJsonPost(request: HttpServletRequest): Map<String, Any> {
        // VULNERABLE: JSON POST without CSRF protection
        val reader = request.reader
        val json = reader.readText()
        return processJson(json)
    }

    // Test 9: Form without token
    fun renderForm(): String {
        // VULNERABLE: No CSRF token in form
        return """
            <form action="/transfer" method="POST">
                <input name="amount" type="text">
                <input name="recipient" type="text">
                <button type="submit">Transfer</button>
            </form>
        """.trimIndent()
    }

    // Test 10: Token reuse
    private val tokenCache = mutableMapOf<String, String>()

    fun getCsrfToken(sessionId: String): String {
        // VULNERABLE: Same token reused
        return tokenCache.getOrPut(sessionId) { java.util.UUID.randomUUID().toString() }
    }

    // Test 11: Referer-only validation
    fun validateRequest(request: HttpServletRequest): Boolean {
        // VULNERABLE: Referer can be spoofed
        val referer = request.getHeader("Referer")
        return referer?.contains("example.com") == true
    }

    // Test 12: API without CSRF for web
    fun handleApiCall(request: HttpServletRequest) {
        val method = request.method
        // VULNERABLE: No CSRF for state-changing methods
        when (method) {
            "POST", "PUT", "DELETE" -> processApiRequest(request)
        }
    }

    private fun deleteUser(userId: Int) {}
    private fun promoteUser(userId: Int) {}
    private fun performAction(action: String?) {}
    private fun processJson(json: String): Map<String, Any> = emptyMap()
    private fun processApiRequest(request: HttpServletRequest) {}
}
