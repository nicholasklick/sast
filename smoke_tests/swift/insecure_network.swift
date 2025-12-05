// Insecure Network Communication vulnerabilities in Swift
import Foundation

class InsecureNetwork {

    // Test 1: HTTP instead of HTTPS
    func fetchOverHttp() {
        // VULNERABLE: Using HTTP
        let url = URL(string: "http://api.example.com/data")!
        let task = URLSession.shared.dataTask(with: url) { data, response, error in
            print("Received data")
        }
        task.resume()
    }

    // Test 2: Disabling ATS (App Transport Security)
    // In Info.plist:
    // <key>NSAppTransportSecurity</key>
    // <dict>
    //   <key>NSAllowsArbitraryLoads</key>
    //   <true/>  <!-- VULNERABLE -->
    // </dict>

    // Test 3: Trust all certificates
    class TrustAllDelegate: NSObject, URLSessionDelegate {
        func urlSession(_ session: URLSession,
                       didReceive challenge: URLAuthenticationChallenge,
                       completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            // VULNERABLE: Accepting all certificates
            if let trust = challenge.protectionSpace.serverTrust {
                completionHandler(.useCredential, URLCredential(trust: trust))
            }
        }
    }

    // Test 4: Ignoring certificate errors
    func fetchIgnoringCerts(url: URL) {
        let config = URLSessionConfiguration.default
        let delegate = TrustAllDelegate()
        // VULNERABLE: Using delegate that trusts all certs
        let session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
        session.dataTask(with: url).resume()
    }

    // Test 5: No certificate pinning
    func fetchWithoutPinning(url: URL) {
        // VULNERABLE: No certificate pinning implemented
        URLSession.shared.dataTask(with: url) { data, response, error in
            // Process response
        }.resume()
    }

    // Test 6: Credentials in URL
    func fetchWithCredsInUrl() {
        // VULNERABLE: Credentials visible in URL
        let url = URL(string: "https://user:password@api.example.com/data")!
        URLSession.shared.dataTask(with: url).resume()
    }

    // Test 7: Sensitive data over unencrypted WebSocket
    func connectWebSocket() {
        // VULNERABLE: Using ws:// instead of wss://
        let url = URL(string: "ws://example.com/socket")!
        let task = URLSession.shared.webSocketTask(with: url)
        task.resume()
    }

    // Test 8: Man-in-the-middle vulnerable
    func connectToBackend() {
        // VULNERABLE: No additional security measures
        var request = URLRequest(url: URL(string: "https://api.example.com")!)
        // Should implement certificate pinning
        URLSession.shared.dataTask(with: request).resume()
    }

    // Test 9: Cleartext traffic exception
    // In Info.plist:
    // <key>NSAppTransportSecurity</key>
    // <dict>
    //   <key>NSExceptionDomains</key>
    //   <dict>
    //     <key>example.com</key>
    //     <dict>
    //       <key>NSExceptionAllowsInsecureHTTPLoads</key>
    //       <true/>  <!-- VULNERABLE -->
    //     </dict>
    //   </dict>
    // </dict>

    // Test 10: Weak TLS version
    func configureWeakTLS() -> URLSessionConfiguration {
        let config = URLSessionConfiguration.default
        // VULNERABLE: Would allow weak TLS if possible
        // Modern iOS doesn't allow this but older versions might
        return config
    }

    // Test 11: API key in request header
    func fetchWithApiKey() {
        var request = URLRequest(url: URL(string: "https://api.example.com")!)
        // VULNERABLE: API key could be intercepted without proper security
        request.setValue("sk-secret-api-key-12345", forHTTPHeaderField: "X-API-Key")
        URLSession.shared.dataTask(with: request).resume()
    }

    // Test 12: Logging network responses
    func fetchAndLog(url: URL) {
        URLSession.shared.dataTask(with: url) { data, response, error in
            // VULNERABLE: Logging potentially sensitive response
            if let data = data, let str = String(data: data, encoding: .utf8) {
                print("Response: \(str)")
                NSLog("Response data: %@", str)
            }
        }.resume()
    }
}
