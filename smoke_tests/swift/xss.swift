// Cross-Site Scripting (XSS) vulnerabilities in Swift (WebView contexts)
import Foundation
import WebKit

class XssVulnerabilities {
    var webView: WKWebView!

    // Test 1: loadHTMLString with user input
    func loadUserContent(userInput: String) {
        // VULNERABLE: User input directly in HTML
        let html = "<html><body><h1>\(userInput)</h1></body></html>"
        webView.loadHTMLString(html, baseURL: nil)
    }

    // Test 2: JavaScript execution with user data
    func executeUserScript(userData: String) {
        // VULNERABLE: User data in JavaScript
        let script = "document.getElementById('output').innerHTML = '\(userData)';"
        webView.evaluateJavaScript(script, completionHandler: nil)
    }

    // Test 3: URL loading without validation
    func loadUrl(urlString: String) {
        // VULNERABLE: Can load javascript: URLs
        if let url = URL(string: urlString) {
            webView.load(URLRequest(url: url))
        }
    }

    // Test 4: JavaScript enabled for untrusted content
    func configureWebView() {
        let config = WKWebViewConfiguration()
        let prefs = WKPreferences()
        // VULNERABLE: JavaScript enabled for all content
        prefs.javaScriptEnabled = true
        config.preferences = prefs
        webView = WKWebView(frame: .zero, configuration: config)
    }

    // Test 5: Message handler without sanitization
    func setupMessageHandler() {
        let contentController = WKUserContentController()
        // Handler receives user-controlled data from JavaScript
        contentController.add(self, name: "messageHandler")
    }

    // Test 6: User script injection
    func injectUserScript(code: String) {
        // VULNERABLE: Injecting user-controlled script
        let script = WKUserScript(source: code, injectionTime: .atDocumentEnd, forMainFrameOnly: false)
        webView.configuration.userContentController.addUserScript(script)
    }

    // Test 7: String interpolation in JavaScript
    func updateElement(elementId: String, content: String) {
        // VULNERABLE: Both parameters from user
        let js = "document.getElementById('\(elementId)').innerHTML = '\(content)';"
        webView.evaluateJavaScript(js, completionHandler: nil)
    }

    // Test 8: JSON embedding without encoding
    func embedJsonData(data: [String: Any]) {
        if let jsonData = try? JSONSerialization.data(withJSONObject: data),
           let jsonString = String(data: jsonData, encoding: .utf8) {
            // VULNERABLE: JSON data may contain XSS payload
            let html = "<html><body><script>var data = \(jsonString);</script></body></html>"
            webView.loadHTMLString(html, baseURL: nil)
        }
    }

    // Test 9: Template rendering
    func renderTemplate(name: String, value: String) {
        // VULNERABLE: User values in template
        let html = """
        <html>
        <body>
            <h1>Hello, \(name)!</h1>
            <p>Your value: \(value)</p>
        </body>
        </html>
        """
        webView.loadHTMLString(html, baseURL: nil)
    }

    // Test 10: URL parameter reflection
    func loadWithParams(baseUrl: String, param: String) {
        // VULNERABLE: Parameter reflected in page
        let html = "<html><body><script>var param = '\(param)';</script></body></html>"
        webView.loadHTMLString(html, baseURL: URL(string: baseUrl))
    }

    // Test 11: Event handler injection
    func addClickHandler(handler: String) {
        // VULNERABLE: User-controlled event handler
        let html = "<html><body><button onclick=\"\(handler)\">Click</button></body></html>"
        webView.loadHTMLString(html, baseURL: nil)
    }

    // Test 12: Style injection
    func applyUserStyle(style: String) {
        // VULNERABLE: CSS injection can lead to data exfiltration
        let html = "<html><head><style>\(style)</style></head><body>Content</body></html>"
        webView.loadHTMLString(html, baseURL: nil)
    }
}

// WKScriptMessageHandler conformance
extension XssVulnerabilities: WKScriptMessageHandler {
    func userContentController(_ userContentController: WKUserContentController,
                              didReceive message: WKScriptMessage) {
        // Handle message
    }
}
