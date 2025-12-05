// Authorization and Access Control vulnerabilities in Groovy
package com.example.security

class AuthorizationVulnerabilities {

    def userRepository = new UserRepository()
    def resourceRepository = new ResourceRepository()
    def tokenValidator = new TokenValidator()

    // Test 1: Missing authorization check
    void deleteUser(int userId) {
        // VULNERABLE: No authorization check
        userRepository.delete(userId)
    }

    // Test 2: Insecure Direct Object Reference (IDOR)
    def getUserData(int userId) {
        // VULNERABLE: No ownership verification
        userRepository.findById(userId)
    }

    // Test 3: Horizontal privilege escalation
    void updateProfile(int userId, Map data) {
        // VULNERABLE: Can update any user's profile
        userRepository.update(userId, data)
    }

    // Test 4: Vertical privilege escalation
    void setUserRole(int userId, String role) {
        // VULNERABLE: No admin check
        userRepository.setRole(userId, role)
    }

    // Test 5: Client-side authorization
    String viewAdminPanel(boolean isAdmin) {
        // VULNERABLE: Trust client-side flag
        isAdmin ? "Admin Panel" : "Access Denied"
    }

    // Test 6: Parameter tampering
    def accessResource(String resourceId, int userId) {
        // VULNERABLE: userId from request, not session
        resourceRepository.get(resourceId, userId)
    }

    // Test 7: Missing function-level access control
    void adminFunction(String action) {
        // VULNERABLE: No role check
        switch (action) {
            case "deleteAll":
                userRepository.deleteAll()
                break
            case "export":
                exportAllData()
                break
            case "resetSystem":
                resetSystem()
                break
        }
    }

    // Test 8: Path-based authorization bypass
    byte[] accessFile(String path) {
        // VULNERABLE: No path authorization
        new File("/uploads/${path}").bytes
    }

    // Test 9: Broken access control in API
    def handleApiRequest(String endpoint, int userId) {
        // VULNERABLE: No authorization
        switch (endpoint) {
            case "/users":
                return userRepository.findAll()
            case "/admin/settings":
                return getAdminSettings()
            default:
                return [error: "Not found"]
        }
    }

    // Test 10: Mass assignment with role
    void updateUser(int userId, Map params) {
        def user = userRepository.findById(userId)
        // VULNERABLE: Can set isAdmin via params
        if (params.isAdmin != null) user.isAdmin = params.isAdmin
        if (params.role != null) user.role = params.role
        userRepository.save(user)
    }

    // Test 11: Token validation bypass
    boolean validateToken(String token) {
        // VULNERABLE: Debug backdoor
        if (token == "debug") return true
        if (!token) return false
        tokenValidator.validate(token)
    }

    // Test 12: Closure-based permission check
    def checkPermissionClosure = { userId, resource ->
        // VULNERABLE: Closure can be replaced
        true
    }

    private void exportAllData() {}
    private void resetSystem() {}
    private Map getAdminSettings() { [:] }
}

class User {
    int id
    String name
    boolean isAdmin = false
    String role = "user"
}

class UserRepository {
    void delete(int id) {}
    User findById(int id) { new User() }
    List findAll() { [] }
    void update(int id, Map data) {}
    void setRole(int id, String role) {}
    void deleteAll() {}
    void save(User user) {}
}

class ResourceRepository {
    def get(String id, int userId) { null }
}

class TokenValidator {
    boolean validate(String token) { false }
}
