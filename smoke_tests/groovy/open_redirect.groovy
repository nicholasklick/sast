// Open Redirect vulnerabilities in Groovy
package com.example.security

class OpenRedirectVulnerabilities {

    // Test 1: Direct redirect from parameter
    def handleRedirect(String redirectUrl) {
        // VULNERABLE: User-controlled redirect
        [redirect: redirectUrl, status: 302]
    }

    // Test 2: Return URL redirect
    def loginRedirect(String returnUrl, boolean authenticated) {
        if (authenticated) {
            // VULNERABLE: returnUrl from user
            [redirect: returnUrl, status: 302]
        } else {
            [status: 401]
        }
    }

    // Test 3: Weak validation
    def safeRedirect(String url) {
        // VULNERABLE: Weak validation (example.com.evil.com passes)
        if (url.contains("example.com")) {
            [redirect: url, status: 302]
        } else {
            [status: 400]
        }
    }

    // Test 4: Protocol-relative redirect
    def protocolRelativeRedirect(String path) {
        // VULNERABLE: Protocol-relative URL
        [redirect: "//${path}", status: 302]
    }

    // Test 5: Logout redirect
    def logout(String redirectUrl) {
        clearSession()
        // VULNERABLE: Post-logout redirect
        [redirect: redirectUrl, status: 302]
    }

    // Test 6: Grails redirect (conceptual)
    def grailsRedirect(String url) {
        // VULNERABLE: Grails redirect
        "redirect(url: '${url}')"
    }

    // Test 7: Error page redirect
    def errorRedirect(String returnPath) {
        // VULNERABLE: Return path from parameter
        [redirect: "/error?return=${returnPath}", status: 302]
    }

    // Test 8: JavaScript redirect
    String jsRedirect(String url) {
        // VULNERABLE: JavaScript redirect
        "<script>window.location='${url}'</script>"
    }

    // Test 9: Meta refresh redirect
    String metaRedirect(String url) {
        // VULNERABLE: Meta tag redirect
        "<meta http-equiv=\"refresh\" content=\"0;url=${url}\">"
    }

    // Test 10: Prefix validation bypass
    def prefixValidatedRedirect(String url) {
        // VULNERABLE: Can bypass with https://example.com@evil.com
        if (url.startsWith("https://example.com")) {
            [redirect: url, status: 302]
        } else {
            [status: 400]
        }
    }

    // Test 11: Path-based redirect
    def pathRedirect(String path) {
        // VULNERABLE: Path can be //evil.com
        [redirect: path, status: 302]
    }

    // Test 12: Header-based redirect
    def headerRedirect(response, String location) {
        // VULNERABLE: Location from user
        response.setHeader("Location", location)
        response.setStatus(302)
    }

    private void clearSession() {}
}
