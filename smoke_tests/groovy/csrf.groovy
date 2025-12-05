// Cross-Site Request Forgery (CSRF) vulnerabilities in Groovy
package com.example.security

class CsrfVulnerabilities {

    def validTokens = [] as Set
    def tokenCache = [:]

    // Test 1: State-changing GET request
    void handleGetRequest(String action, int userId) {
        // VULNERABLE: State change via GET
        switch (action) {
            case "delete":
                deleteUser(userId)
                break
            case "promote":
                promoteUser(userId)
                break
        }
    }

    // Test 2: Missing CSRF token
    String handlePostRequest(Map params) {
        // VULNERABLE: No CSRF token validation
        if (params.action) {
            performAction(params.action)
        }
        "success"
    }

    // Test 3: CSRF token in URL
    String generateFormUrl(String token) {
        // VULNERABLE: Token visible in URL
        "https://example.com/action?csrf_token=${token}"
    }

    // Test 4: Predictable CSRF token
    String generateCsrfToken(int userId) {
        // VULNERABLE: Predictable token
        "csrf_${userId}_${System.currentTimeMillis()}"
    }

    // Test 5: Token without session binding
    boolean validateCsrfToken(String token) {
        // VULNERABLE: Not bound to user session
        validTokens.contains(token)
    }

    // Test 6: Cookie without SameSite
    String setCookie(String token) {
        // VULNERABLE: Missing SameSite attribute
        "session=${token}; Path=/; HttpOnly"
    }

    // Test 7: CORS misconfiguration
    Map handleCorsRequest(String origin) {
        // VULNERABLE: Reflecting arbitrary origin
        [
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true"
        ]
    }

    // Test 8: JSON endpoint without CSRF
    Map handleJsonPost(String json) {
        // VULNERABLE: JSON POST without CSRF protection
        def slurper = new groovy.json.JsonSlurper()
        slurper.parseText(json)
    }

    // Test 9: Form without token
    String renderForm() {
        // VULNERABLE: No CSRF token in form
        """
        <form action="/transfer" method="POST">
            <input name="amount" type="text">
            <input name="recipient" type="text">
            <button type="submit">Transfer</button>
        </form>
        """
    }

    // Test 10: Token reuse
    String getCsrfToken(String sessionId) {
        // VULNERABLE: Same token reused
        if (!tokenCache[sessionId]) {
            tokenCache[sessionId] = UUID.randomUUID().toString()
        }
        tokenCache[sessionId]
    }

    // Test 11: Referer-only validation
    boolean validateRequest(String referer) {
        // VULNERABLE: Referer can be spoofed
        referer?.contains("example.com")
    }

    // Test 12: Grails without CSRF filter
    def grailsAction(Map params) {
        // VULNERABLE: Action without CSRF check
        "Action executed"
    }

    private void deleteUser(int userId) {}
    private void promoteUser(int userId) {}
    private void performAction(String action) {}
}
