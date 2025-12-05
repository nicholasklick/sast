// HTTP Header Injection vulnerabilities in Groovy
package com.example.security

class HeaderInjectionVulnerabilities {

    // Test 1: Response header injection
    void setCustomHeader(response, String headerName, String headerValue) {
        // VULNERABLE: User-controlled header value
        response.setHeader(headerName, headerValue)
    }

    // Test 2: Cookie value injection
    void setCookie(response, String name, String value) {
        // VULNERABLE: Cookie value from user
        response.addHeader("Set-Cookie", "${name}=${value}")
    }

    // Test 3: Location header injection
    void redirect(response, String url) {
        // VULNERABLE: URL in Location header
        response.setHeader("Location", url)
    }

    // Test 4: Content-Type injection
    void setContentType(response, String contentType) {
        // VULNERABLE: User-controlled content type
        response.setHeader("Content-Type", contentType)
    }

    // Test 5: CORS header injection
    void setCorsOrigin(response, String origin) {
        // VULNERABLE: Origin from request
        response.setHeader("Access-Control-Allow-Origin", origin)
    }

    // Test 6: Content-Disposition injection
    void setFilename(response, String filename) {
        // VULNERABLE: Filename in header
        response.setHeader("Content-Disposition", "attachment; filename=\"${filename}\"")
    }

    // Test 7: Custom header with CRLF
    void setCustomHeaderUnsafe(response, String value) {
        // VULNERABLE: CRLF injection possible
        response.setHeader("X-Custom-Header", value)
    }

    // Test 8: Multiple headers via map
    void setHeaders(response, Map headers) {
        // VULNERABLE: All headers from user
        headers.each { name, value ->
            response.setHeader(name, value)
        }
    }

    // Test 9: Grails response header
    void grailsSetHeader(response, String key, String value) {
        // VULNERABLE: Header injection in Grails
        response.setHeader(key, value)
    }

    // Test 10: Cache-Control manipulation
    void setCacheControl(response, String directive) {
        // VULNERABLE: User-controlled cache directive
        response.setHeader("Cache-Control", directive)
    }

    // Test 11: X-Forwarded-For trust
    String getClientIp(request) {
        // VULNERABLE: Trusting X-Forwarded-For
        request.getHeader("X-Forwarded-For") ?: request.remoteAddr
    }

    // Test 12: Host header injection
    String buildUrl(request, String path) {
        // VULNERABLE: Using Host header
        def host = request.getHeader("Host")
        "https://${host}${path}"
    }

    // Test 13: Link header injection
    void setLinkHeader(response, String rel, String url) {
        // VULNERABLE: URL in Link header
        response.setHeader("Link", "<${url}>; rel=\"${rel}\"")
    }
}
