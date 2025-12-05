// HTTP Header Injection vulnerabilities in Swift
import Foundation

class HeaderInjectionVulnerabilities {

    // Test 1: User input in response header
    func setCustomHeader(response: inout [String: String], userValue: String) {
        // VULNERABLE: User value in header
        response["X-Custom-Header"] = userValue
    }

    // Test 2: Cookie value injection
    func setCookie(name: String, value: String) -> String {
        // VULNERABLE: Both name and value from user
        return "Set-Cookie: \(name)=\(value)"
    }

    // Test 3: Location header injection
    func redirectHeader(location: String) -> String {
        // VULNERABLE: Location from user input
        return "Location: \(location)"
    }

    // Test 4: Content-Type injection
    func setContentType(type: String) -> String {
        // VULNERABLE: Content-Type from user
        return "Content-Type: \(type)"
    }

    // Test 5: Cache-Control manipulation
    func setCacheControl(directive: String) -> String {
        // VULNERABLE: Directive from user
        return "Cache-Control: \(directive)"
    }

    // Test 6: CORS header injection
    func setCorsOrigin(origin: String) -> String {
        // VULNERABLE: Origin reflected without validation
        return "Access-Control-Allow-Origin: \(origin)"
    }

    // Test 7: Content-Disposition injection
    func setDownloadHeader(filename: String) -> String {
        // VULNERABLE: Filename from user
        return "Content-Disposition: attachment; filename=\"\(filename)\""
    }

    // Test 8: WWW-Authenticate injection
    func setAuthHeader(realm: String) -> String {
        // VULNERABLE: Realm from user
        return "WWW-Authenticate: Basic realm=\"\(realm)\""
    }

    // Test 9: Link header injection
    func setLinkHeader(url: String, rel: String) -> String {
        // VULNERABLE: Both URL and rel from user
        return "Link: <\(url)>; rel=\"\(rel)\""
    }

    // Test 10: X-Forwarded headers
    func forwardHeaders(forwardedFor: String) -> [String: String] {
        // VULNERABLE: Trusting X-Forwarded-For
        return [
            "X-Forwarded-For": forwardedFor,
            "X-Real-IP": forwardedFor
        ]
    }

    // Test 11: Response splitting via newlines
    func setHeaderWithNewlines(value: String) -> String {
        // VULNERABLE: Newlines allow header injection
        return "X-Custom: \(value)"
    }

    // Test 12: URLRequest header injection
    func makeRequest(url: URL, customHeader: String) {
        var request = URLRequest(url: url)
        // VULNERABLE: User-controlled header value
        request.setValue(customHeader, forHTTPHeaderField: "X-Custom")
        URLSession.shared.dataTask(with: request).resume()
    }

    // Test 13: Host header injection
    func setHostHeader(host: String) -> String {
        // VULNERABLE: Host from user
        return "Host: \(host)"
    }
}
