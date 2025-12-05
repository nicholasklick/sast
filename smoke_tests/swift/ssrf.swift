// Server-Side Request Forgery (SSRF) vulnerabilities in Swift
import Foundation

class SsrfVulnerabilities {

    // Test 1: URLSession with user-controlled URL
    func fetchUrl(urlString: String, completion: @escaping (Data?) -> Void) {
        guard let url = URL(string: urlString) else {
            completion(nil)
            return
        }
        // VULNERABLE: User-controlled URL
        URLSession.shared.dataTask(with: url) { data, _, _ in
            completion(data)
        }.resume()
    }

    // Test 2: Partial URL construction
    func fetchFromHost(host: String, completion: @escaping (Data?) -> Void) {
        // VULNERABLE: User controls hostname
        let urlString = "http://\(host)/api/data"
        guard let url = URL(string: urlString) else {
            completion(nil)
            return
        }
        URLSession.shared.dataTask(with: url) { data, _, _ in
            completion(data)
        }.resume()
    }

    // Test 3: Port scanning via SSRF
    func checkPort(port: Int, completion: @escaping (Bool) -> Void) {
        // VULNERABLE: User controls port
        let urlString = "http://internal-server:\(port)/"
        guard let url = URL(string: urlString) else {
            completion(false)
            return
        }

        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 5
        let session = URLSession(configuration: config)

        session.dataTask(with: url) { _, response, error in
            completion(error == nil)
        }.resume()
    }

    // Test 4: Image proxy
    func fetchImage(imageUrl: String, completion: @escaping (Data?) -> Void) {
        guard let url = URL(string: imageUrl) else {
            completion(nil)
            return
        }
        // VULNERABLE: Can fetch internal resources
        URLSession.shared.dataTask(with: url) { data, _, _ in
            completion(data)
        }.resume()
    }

    // Test 5: Webhook URL
    func sendWebhook(webhookUrl: String, data: Data, completion: @escaping (Bool) -> Void) {
        guard let url = URL(string: webhookUrl) else {
            completion(false)
            return
        }
        // VULNERABLE: User-controlled webhook destination
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = data

        URLSession.shared.dataTask(with: request) { _, _, error in
            completion(error == nil)
        }.resume()
    }

    // Test 6: DNS rebinding
    func fetchExternal(domain: String, completion: @escaping (Data?) -> Void) {
        // VULNERABLE: DNS can resolve to internal IP
        let urlString = "http://\(domain)/data"
        guard let url = URL(string: urlString) else {
            completion(nil)
            return
        }
        URLSession.shared.dataTask(with: url) { data, _, _ in
            completion(data)
        }.resume()
    }

    // Test 7: File protocol SSRF
    func readResource(uri: String, completion: @escaping (Data?) -> Void) {
        guard let url = URL(string: uri) else {
            completion(nil)
            return
        }
        // VULNERABLE: Could be file:///etc/passwd
        URLSession.shared.dataTask(with: url) { data, _, _ in
            completion(data)
        }.resume()
    }

    // Test 8: Redirect following
    func fetchWithRedirect(urlString: String, completion: @escaping (Data?) -> Void) {
        guard let url = URL(string: urlString) else {
            completion(nil)
            return
        }

        let config = URLSessionConfiguration.default
        // VULNERABLE: Following redirects to internal resources
        let session = URLSession(configuration: config)

        session.dataTask(with: url) { data, _, _ in
            completion(data)
        }.resume()
    }

    // Test 9: URL from user input in API call
    func callExternalApi(endpoint: String, completion: @escaping (Data?) -> Void) {
        // VULNERABLE: Endpoint from user
        guard let url = URL(string: endpoint) else {
            completion(nil)
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"

        URLSession.shared.dataTask(with: request) { data, _, _ in
            completion(data)
        }.resume()
    }

    // Test 10: URL components manipulation
    func fetchWithPath(basePath: String, completion: @escaping (Data?) -> Void) {
        var components = URLComponents(string: "http://api.example.com")!
        // VULNERABLE: Path from user can include /../ or @
        components.path = basePath

        guard let url = components.url else {
            completion(nil)
            return
        }

        URLSession.shared.dataTask(with: url) { data, _, _ in
            completion(data)
        }.resume()
    }
}
