// URL Scheme and Deep Link vulnerabilities in Swift
import Foundation
import UIKit

class UrlSchemeVulnerabilities {

    // Test 1: Unvalidated URL scheme handler
    func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any]) -> Bool {
        // VULNERABLE: No validation of scheme or host
        if let host = url.host {
            navigateTo(path: host)
        }
        return true
    }

    // Test 2: Command execution via URL
    func handleCustomUrl(url: URL) {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return }
        // VULNERABLE: Executing commands from URL
        if let command = components.queryItems?.first(where: { $0.name == "cmd" })?.value {
            executeCommand(command)
        }
    }

    // Test 3: Data URL injection
    func processDataUrl(url: URL) {
        // VULNERABLE: Data URLs can contain malicious content
        if url.scheme == "data" {
            let webView = WKWebView(frame: .zero)
            webView.load(URLRequest(url: url))
        }
    }

    // Test 4: File URL access
    func openFileUrl(url: URL) {
        // VULNERABLE: Accessing arbitrary files
        if url.scheme == "file" {
            let data = try? Data(contentsOf: url)
            processFile(data: data)
        }
    }

    // Test 5: JavaScript URL
    func loadUrl(urlString: String, webView: WKWebView) {
        // VULNERABLE: JavaScript URLs can execute code
        if let url = URL(string: urlString) {
            webView.load(URLRequest(url: url))
        }
    }

    // Test 6: Intent spoofing via URL
    func handleUniversalLink(url: URL) {
        // VULNERABLE: No app association validation
        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        if let action = components?.queryItems?.first(where: { $0.name == "action" })?.value {
            performAction(action)
        }
    }

    // Test 7: Sensitive data in URL callback
    func registerCallback(token: String) -> URL {
        // VULNERABLE: Token exposed in URL
        return URL(string: "myapp://callback?token=\(token)")!
    }

    // Test 8: URL parameter injection
    func buildRedirectUrl(returnPath: String) -> URL? {
        // VULNERABLE: Path injection
        return URL(string: "myapp://navigate\(returnPath)")
    }

    // Test 9: Cross-app communication without validation
    func handleAppLink(url: URL) {
        // VULNERABLE: No source app validation
        if url.host == "transfer" {
            if let amount = url.queryParameters?["amount"],
               let recipient = url.queryParameters?["to"] {
                initiateTransfer(amount: amount, to: recipient)
            }
        }
    }

    // Test 10: Custom scheme password reset
    func handlePasswordReset(url: URL) {
        // VULNERABLE: Token in URL scheme
        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        if let token = components?.queryItems?.first(where: { $0.name == "reset_token" })?.value {
            resetPassword(token: token)
        }
    }

    // Test 11: Clipboard URL handling
    func handleClipboardUrl() {
        // VULNERABLE: Processing untrusted clipboard URL
        if let urlString = UIPasteboard.general.string,
           let url = URL(string: urlString) {
            openUrl(url)
        }
    }

    // Test 12: QR code URL
    func handleQrCode(content: String) {
        // VULNERABLE: Opening URL from QR without validation
        if let url = URL(string: content) {
            UIApplication.shared.open(url)
        }
    }

    // Test 13: Universal link path traversal
    func handleUniversalPath(url: URL) {
        let path = url.path
        // VULNERABLE: Path traversal via universal link
        let filePath = "/app/data\(path)"
        let data = FileManager.default.contents(atPath: filePath)
    }

    private func navigateTo(path: String) {}
    private func executeCommand(_ command: String) {}
    private func processFile(data: Data?) {}
    private func performAction(_ action: String) {}
    private func initiateTransfer(amount: String, to: String) {}
    private func resetPassword(token: String) {}
    private func openUrl(_ url: URL) {}
}

extension URL {
    var queryParameters: [String: String]? {
        guard let components = URLComponents(url: self, resolvingAgainstBaseURL: false),
              let queryItems = components.queryItems else { return nil }
        return queryItems.reduce(into: [:]) { $0[$1.name] = $1.value }
    }
}

class WKWebView {
    init(frame: CGRect) {}
    func load(_ request: URLRequest) {}
}

class UIPasteboard {
    static var general = UIPasteboard()
    var string: String?
}
