// Cross-Site Request Forgery (CSRF) vulnerabilities in Swift
import Foundation

class CsrfVulnerabilities {

    // Test 1: State-changing GET request
    func handleGetRequest(action: String, userId: Int) {
        // VULNERABLE: State change via GET
        if action == "delete" {
            deleteUser(userId: userId)
        } else if action == "promote" {
            promoteUser(userId: userId)
        }
    }

    // Test 2: Missing CSRF token validation
    func handlePostRequest(params: [String: Any]) {
        // VULNERABLE: No CSRF token check
        if let action = params["action"] as? String {
            performAction(action)
        }
    }

    // Test 3: CSRF token in URL
    func generateFormUrl(token: String) -> String {
        // VULNERABLE: Token exposed in URL (visible in logs, referrer)
        return "https://api.example.com/action?csrf_token=\(token)"
    }

    // Test 4: Predictable CSRF token
    func generateCsrfToken(userId: Int) -> String {
        // VULNERABLE: Predictable token
        return "csrf_\(userId)_\(Date().timeIntervalSince1970)"
    }

    // Test 5: CSRF token without session binding
    func validateCsrfToken(token: String) -> Bool {
        // VULNERABLE: Not bound to user session
        return validTokens.contains(token)
    }

    // Test 6: SameSite cookie not set
    func setCookie(response: inout HTTPURLResponse, token: String) {
        // VULNERABLE: Missing SameSite attribute
        let cookie = "session=\(token); Path=/; HttpOnly"
        // Should have SameSite=Strict or SameSite=Lax
    }

    // Test 7: CORS misconfiguration enabling CSRF
    func handleCorsRequest(origin: String) -> [String: String] {
        // VULNERABLE: Reflecting any origin
        return [
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true"
        ]
    }

    // Test 8: JSON endpoint without CSRF
    func handleJsonPost(data: Data) -> [String: Any] {
        // VULNERABLE: JSON POST without CSRF token
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return ["error": "Invalid JSON"]
        }
        return processData(json)
    }

    // Test 9: Form submission without token
    func renderForm() -> String {
        // VULNERABLE: No CSRF token in form
        return """
        <form action="/transfer" method="POST">
            <input name="amount" type="text">
            <input name="recipient" type="text">
            <button type="submit">Transfer</button>
        </form>
        """
    }

    // Test 10: CSRF token reuse
    func getCsrfToken(sessionId: String) -> String {
        // VULNERABLE: Same token reused across requests
        if let existing = tokenCache[sessionId] {
            return existing
        }
        let token = UUID().uuidString
        tokenCache[sessionId] = token
        return token
    }

    // Test 11: Weak CSRF validation
    func validateRequest(headers: [String: String], params: [String: String]) -> Bool {
        // VULNERABLE: Only checking referer, which can be spoofed
        guard let referer = headers["Referer"] else { return false }
        return referer.contains("example.com")
    }

    // Test 12: API without CSRF for web clients
    func handleApiCall(method: String, path: String, headers: [String: String]) {
        // VULNERABLE: No CSRF protection for web API calls
        if method == "POST" || method == "PUT" || method == "DELETE" {
            // Should validate CSRF token for web clients
            processApiRequest(path: path)
        }
    }

    private var validTokens: Set<String> = []
    private var tokenCache: [String: String] = [:]

    private func deleteUser(userId: Int) {}
    private func promoteUser(userId: Int) {}
    private func performAction(_ action: String) {}
    private func processData(_ data: [String: Any]) -> [String: Any] { [:] }
    private func processApiRequest(path: String) {}
}
