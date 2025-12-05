// HTTP Header Injection vulnerabilities in Kotlin
package com.example.security

import javax.servlet.http.HttpServletResponse

class HeaderInjectionVulnerabilities {

    // Test 1: User input in response header
    fun setCustomHeader(response: HttpServletResponse, userValue: String) {
        // VULNERABLE: User value in header
        response.setHeader("X-Custom-Header", userValue)
    }

    // Test 2: Cookie value injection
    fun setCookie(name: String, value: String): String {
        // VULNERABLE: Both name and value from user
        return "Set-Cookie: $name=$value"
    }

    // Test 3: Location header injection
    fun redirectHeader(response: HttpServletResponse, location: String) {
        // VULNERABLE: Location from user
        response.setHeader("Location", location)
        response.status = 302
    }

    // Test 4: Content-Type injection
    fun setContentType(response: HttpServletResponse, type: String) {
        // VULNERABLE: Content-Type from user
        response.setHeader("Content-Type", type)
    }

    // Test 5: Cache-Control manipulation
    fun setCacheControl(response: HttpServletResponse, directive: String) {
        // VULNERABLE: Directive from user
        response.setHeader("Cache-Control", directive)
    }

    // Test 6: CORS header injection
    fun setCorsOrigin(response: HttpServletResponse, origin: String) {
        // VULNERABLE: Origin reflected without validation
        response.setHeader("Access-Control-Allow-Origin", origin)
    }

    // Test 7: Content-Disposition injection
    fun setDownloadHeader(response: HttpServletResponse, filename: String) {
        // VULNERABLE: Filename from user
        response.setHeader("Content-Disposition", "attachment; filename=\"$filename\"")
    }

    // Test 8: WWW-Authenticate injection
    fun setAuthHeader(response: HttpServletResponse, realm: String) {
        // VULNERABLE: Realm from user
        response.setHeader("WWW-Authenticate", "Basic realm=\"$realm\"")
    }

    // Test 9: Link header injection
    fun setLinkHeader(response: HttpServletResponse, url: String, rel: String) {
        // VULNERABLE: Both URL and rel from user
        response.setHeader("Link", "<$url>; rel=\"$rel\"")
    }

    // Test 10: Response splitting via newlines
    fun setHeaderWithNewlines(response: HttpServletResponse, value: String) {
        // VULNERABLE: Newlines allow header injection
        response.setHeader("X-Custom", value)
    }

    // Test 11: X-Forwarded headers
    fun forwardHeaders(response: HttpServletResponse, forwardedFor: String) {
        // VULNERABLE: Trusting X-Forwarded-For
        response.setHeader("X-Forwarded-For", forwardedFor)
    }

    // Test 12: Vary header injection
    fun setVaryHeader(response: HttpServletResponse, vary: String) {
        // VULNERABLE: Vary from user
        response.setHeader("Vary", vary)
    }

    // Test 13: Host header injection
    fun setHostHeader(response: HttpServletResponse, host: String) {
        // VULNERABLE: Host from user
        response.setHeader("Host", host)
    }
}
