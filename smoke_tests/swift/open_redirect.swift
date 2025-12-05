// Open Redirect vulnerabilities in Swift
import Foundation
import UIKit

class OpenRedirectVulnerabilities {

    // Test 1: Direct URL redirect
    func redirectToUrl(urlString: String) {
        // VULNERABLE: User-controlled redirect
        if let url = URL(string: urlString) {
            UIApplication.shared.open(url)
        }
    }

    // Test 2: Deep link handling
    func handleDeepLink(url: URL) {
        // VULNERABLE: No validation of redirect target
        if let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
           let redirectUrl = components.queryItems?.first(where: { $0.name == "redirect" })?.value,
           let targetUrl = URL(string: redirectUrl) {
            UIApplication.shared.open(targetUrl)
        }
    }

    // Test 3: OAuth callback redirect
    func handleOAuthCallback(redirectUri: String) {
        // VULNERABLE: Redirect URI from request
        if let url = URL(string: redirectUri) {
            UIApplication.shared.open(url)
        }
    }

    // Test 4: Login redirect
    func loginAndRedirect(username: String, password: String, returnUrl: String) {
        if authenticate(username: username, password: password) {
            // VULNERABLE: returnUrl from user
            if let url = URL(string: returnUrl) {
                UIApplication.shared.open(url)
            }
        }
    }

    // Test 5: Partial URL validation
    func redirectIfSafe(urlString: String) {
        // VULNERABLE: Weak validation (example.com.evil.com would pass)
        if urlString.contains("example.com") {
            if let url = URL(string: urlString) {
                UIApplication.shared.open(url)
            }
        }
    }

    // Test 6: Protocol-relative redirect
    func redirectProtocolRelative(path: String) {
        // VULNERABLE: Protocol-relative URL
        let urlString = "//\(path)"
        if let url = URL(string: "https:\(urlString)") {
            UIApplication.shared.open(url)
        }
    }

    // Test 7: WebView redirect
    func loadWebViewUrl(webView: WKWebView, urlString: String) {
        // VULNERABLE: Loading arbitrary URL
        if let url = URL(string: urlString) {
            webView.load(URLRequest(url: url))
        }
    }

    // Test 8: Logout redirect
    func logout(redirectUrl: String) {
        clearSession()
        // VULNERABLE: Post-logout redirect
        if let url = URL(string: redirectUrl) {
            UIApplication.shared.open(url)
        }
    }

    // Test 9: Share URL redirect
    func shareAndRedirect(content: String, redirectAfter: String) {
        // Share content...
        // VULNERABLE: Redirect after share
        if let url = URL(string: redirectAfter) {
            UIApplication.shared.open(url)
        }
    }

    // Test 10: Payment callback
    func handlePaymentCallback(params: [String: String]) {
        if params["status"] == "success" {
            // VULNERABLE: Redirect from payment params
            if let redirectUrl = params["redirect"],
               let url = URL(string: redirectUrl) {
                UIApplication.shared.open(url)
            }
        }
    }

    // Test 11: Error page redirect
    func showError(message: String, returnUrl: String) {
        print("Error: \(message)")
        // VULNERABLE: Return URL from parameter
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
            if let url = URL(string: returnUrl) {
                UIApplication.shared.open(url)
            }
        }
    }

    // Test 12: Shortlink expansion
    func expandAndRedirect(shortUrl: String) {
        // VULNERABLE: Following arbitrary shortlinks
        if let url = URL(string: shortUrl) {
            let task = URLSession.shared.dataTask(with: url) { _, response, _ in
                if let httpResponse = response as? HTTPURLResponse,
                   let location = httpResponse.allHeaderFields["Location"] as? String,
                   let redirectUrl = URL(string: location) {
                    UIApplication.shared.open(redirectUrl)
                }
            }
            task.resume()
        }
    }

    private func authenticate(username: String, password: String) -> Bool { true }
    private func clearSession() {}
}

import WebKit
class WKWebView {
    func load(_ request: URLRequest) {}
}
