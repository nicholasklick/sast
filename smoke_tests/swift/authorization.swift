// Authorization and Access Control vulnerabilities in Swift
import Foundation

class AuthorizationVulnerabilities {

    var currentUserId: Int = 0
    var isAdmin: Bool = false

    // Test 1: Missing authorization check
    func deleteUser(userId: Int) {
        // VULNERABLE: No authorization check
        UserDatabase.shared.delete(userId: userId)
    }

    // Test 2: Client-side authorization
    func viewAdminPanel() -> String {
        // VULNERABLE: Authorization on client side only
        if UserDefaults.standard.bool(forKey: "isAdmin") {
            return "Admin Panel Content"
        }
        return "Access Denied"
    }

    // Test 3: Insecure Direct Object Reference (IDOR)
    func getUserData(userId: Int) -> UserData? {
        // VULNERABLE: No ownership check
        return UserDatabase.shared.fetch(userId: userId)
    }

    // Test 4: Horizontal privilege escalation
    func updateProfile(userId: Int, data: [String: Any]) {
        // VULNERABLE: User can update any profile
        UserDatabase.shared.update(userId: userId, data: data)
    }

    // Test 5: Vertical privilege escalation
    func setUserRole(userId: Int, role: String) {
        // VULNERABLE: No admin check before role change
        UserDatabase.shared.setRole(userId: userId, role: role)
    }

    // Test 6: Bypassing authorization via parameter manipulation
    func accessResource(resourceId: String, userId: Int) -> Data? {
        // VULNERABLE: userId from request, not session
        return ResourceManager.shared.get(id: resourceId, ownerId: userId)
    }

    // Test 7: Mass assignment with role
    func updateUser(userId: Int, params: [String: Any]) {
        // VULNERABLE: Can set isAdmin via params
        var user = UserDatabase.shared.fetch(userId: userId)
        if let admin = params["isAdmin"] as? Bool {
            user?.isAdmin = admin  // VULNERABLE
        }
        if let role = params["role"] as? String {
            user?.role = role  // VULNERABLE
        }
    }

    // Test 8: File access without authorization
    func downloadFile(filename: String) -> Data? {
        let path = "/uploads/\(filename)"
        // VULNERABLE: No ownership check
        return FileManager.default.contents(atPath: path)
    }

    // Test 9: API endpoint without auth middleware
    func handleApiRequest(endpoint: String, params: [String: Any]) -> [String: Any] {
        // VULNERABLE: No authentication check
        switch endpoint {
        case "/users":
            return ["users": UserDatabase.shared.getAllUsers()]
        case "/admin/settings":
            return ["settings": getSettings()]
        default:
            return ["error": "Not found"]
        }
    }

    // Test 10: Token-based auth bypass
    func validateToken(token: String) -> Bool {
        // VULNERABLE: Accepts empty or special tokens
        if token.isEmpty { return false }
        if token == "debug" { return true }  // BACKDOOR
        return TokenValidator.validate(token)
    }

    // Test 11: Function-level access control missing
    func adminFunction(action: String) {
        // VULNERABLE: No role check
        switch action {
        case "deleteAll":
            UserDatabase.shared.deleteAll()
        case "export":
            exportAllData()
        default:
            break
        }
    }

    // Test 12: Cached authorization
    func checkPermission(userId: Int, resource: String) -> Bool {
        let cacheKey = "\(userId)-\(resource)"
        // VULNERABLE: Cached permissions may be stale
        if let cached = PermissionCache.shared.get(key: cacheKey) {
            return cached
        }
        let result = checkActualPermission(userId: userId, resource: resource)
        PermissionCache.shared.set(key: cacheKey, value: result)
        return result
    }

    private func getSettings() -> [String: Any] { [:] }
    private func exportAllData() {}
    private func checkActualPermission(userId: Int, resource: String) -> Bool { false }
}

struct UserData {
    var id: Int
    var name: String
    var isAdmin: Bool
    var role: String
}

class UserDatabase {
    static let shared = UserDatabase()
    func delete(userId: Int) {}
    func fetch(userId: Int) -> UserData? { nil }
    func update(userId: Int, data: [String: Any]) {}
    func setRole(userId: Int, role: String) {}
    func getAllUsers() -> [UserData] { [] }
    func deleteAll() {}
}

class ResourceManager {
    static let shared = ResourceManager()
    func get(id: String, ownerId: Int) -> Data? { nil }
}

class TokenValidator {
    static func validate(_ token: String) -> Bool { false }
}

class PermissionCache {
    static let shared = PermissionCache()
    func get(key: String) -> Bool? { nil }
    func set(key: String, value: Bool) {}
}
