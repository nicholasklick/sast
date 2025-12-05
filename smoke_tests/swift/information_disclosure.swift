// Information Disclosure vulnerabilities in Swift
import Foundation

class InformationDisclosureVulnerabilities {

    // Test 1: Detailed error messages
    func processRequest(data: Data) throws -> [String: Any] {
        do {
            return try JSONSerialization.jsonObject(with: data) as! [String: Any]
        } catch {
            // VULNERABLE: Detailed error to user
            throw NSError(domain: "App", code: 1,
                         userInfo: [NSLocalizedDescriptionKey: "Parse error: \(error). Data: \(String(data: data, encoding: .utf8) ?? "")"])
        }
    }

    // Test 2: Stack trace exposure
    func handleError(error: Error) -> [String: Any] {
        // VULNERABLE: Stack trace in response
        return [
            "error": error.localizedDescription,
            "stack": Thread.callStackSymbols
        ]
    }

    // Test 3: Server version disclosure
    func getServerInfo() -> [String: String] {
        // VULNERABLE: Version information exposed
        return [
            "server": "CustomServer/2.1.3",
            "swift_version": "5.9",
            "os": ProcessInfo.processInfo.operatingSystemVersionString
        ]
    }

    // Test 4: Database error details
    func executeQuery(sql: String) throws -> [[String: Any]] {
        // Simulated database error
        // VULNERABLE: SQL and internal details exposed
        throw NSError(domain: "DB", code: 1001,
                     userInfo: [NSLocalizedDescriptionKey: "SQL Error at line 42: \(sql) - table 'users' column 'password_hash' not found"])
    }

    // Test 5: File path disclosure
    func readConfig() throws -> Data {
        let path = "/etc/app/config.json"
        guard let data = FileManager.default.contents(atPath: path) else {
            // VULNERABLE: Full path in error
            throw NSError(domain: "App", code: 404,
                         userInfo: [NSLocalizedDescriptionKey: "Config not found at: \(path)"])
        }
        return data
    }

    // Test 6: Debug mode in production
    func getDebugInfo() -> [String: Any] {
        // VULNERABLE: Debug info should not be exposed
        return [
            "memory_usage": ProcessInfo.processInfo.physicalMemory,
            "environment": ProcessInfo.processInfo.environment,
            "arguments": ProcessInfo.processInfo.arguments
        ]
    }

    // Test 7: User enumeration
    func checkUser(email: String) -> String {
        if userExists(email: email) {
            // VULNERABLE: Reveals user existence
            return "User exists, check your password"
        } else {
            return "No user found with this email"
        }
    }

    // Test 8: Timing-based information leak
    func verifyCredentials(username: String, password: String) -> Bool {
        guard let user = findUser(username: username) else {
            return false  // VULNERABLE: Fast return reveals user doesn't exist
        }
        // Slow password verification
        return verifyPassword(password, hash: user.passwordHash)
    }

    // Test 9: Internal IP disclosure
    func getNetworkInfo() -> [String: Any] {
        // VULNERABLE: Internal network info exposed
        return [
            "internal_ip": getInternalIP(),
            "hostname": ProcessInfo.processInfo.hostName
        ]
    }

    // Test 10: Source code in error
    func compileDynamic(code: String) throws {
        // VULNERABLE: Source code in error message
        throw NSError(domain: "Compiler", code: 1,
                     userInfo: [NSLocalizedDescriptionKey: "Compilation failed for: \(code)"])
    }

    // Test 11: Directory listing
    func listDirectory(path: String) throws -> [String] {
        // VULNERABLE: Listing arbitrary directories
        return try FileManager.default.contentsOfDirectory(atPath: path)
    }

    // Test 12: Verbose logging in response
    func processTransaction(transactionId: String) -> [String: Any] {
        // VULNERABLE: Internal processing details
        return [
            "status": "processed",
            "internal_id": UUID().uuidString,
            "processing_server": "server-02.internal.example.com",
            "database_node": "db-replica-3"
        ]
    }

    // Test 13: Exception type disclosure
    func parseXml(data: Data) throws -> Any {
        do {
            return try XMLParser(data: data)
        } catch let nsError as NSError {
            // VULNERABLE: Full exception details
            throw NSError(domain: "XML", code: nsError.code,
                         userInfo: [NSLocalizedDescriptionKey: "XML Error: \(nsError.domain) - \(nsError.userInfo)"])
        }
    }

    private func userExists(email: String) -> Bool { false }
    private func findUser(username: String) -> (passwordHash: String, id: Int)? { nil }
    private func verifyPassword(_ password: String, hash: String) -> Bool { false }
    private func getInternalIP() -> String { "10.0.0.1" }
}
