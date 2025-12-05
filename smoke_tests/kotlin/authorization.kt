// Authorization and Access Control vulnerabilities in Kotlin
package com.example.security

import javax.servlet.http.HttpServletRequest

class AuthorizationVulnerabilities {

    // Test 1: Missing authorization check
    fun deleteUser(userId: Int) {
        // VULNERABLE: No authorization check
        userRepository.delete(userId)
    }

    // Test 2: Insecure Direct Object Reference (IDOR)
    fun getUserData(userId: Int): User? {
        // VULNERABLE: No ownership verification
        return userRepository.findById(userId)
    }

    // Test 3: Horizontal privilege escalation
    fun updateProfile(userId: Int, data: Map<String, Any>) {
        // VULNERABLE: Can update any user's profile
        userRepository.update(userId, data)
    }

    // Test 4: Vertical privilege escalation
    fun setUserRole(userId: Int, role: String) {
        // VULNERABLE: No admin check
        userRepository.setRole(userId, role)
    }

    // Test 5: Client-side authorization
    fun viewAdminPanel(request: HttpServletRequest): String {
        // VULNERABLE: Trust client-side isAdmin flag
        val isAdmin = request.getParameter("isAdmin")?.toBoolean() ?: false
        return if (isAdmin) "Admin Panel" else "Access Denied"
    }

    // Test 6: Parameter tampering
    fun accessResource(request: HttpServletRequest): Any? {
        val resourceId = request.getParameter("id")
        val userId = request.getParameter("userId")?.toInt()
        // VULNERABLE: userId from request, not session
        return resourceRepository.get(resourceId, userId)
    }

    // Test 7: Missing function-level access control
    fun adminFunction(action: String) {
        // VULNERABLE: No role check
        when (action) {
            "deleteAll" -> userRepository.deleteAll()
            "export" -> exportAllData()
            "resetSystem" -> resetSystem()
        }
    }

    // Test 8: Path-based authorization bypass
    fun accessFile(path: String): ByteArray? {
        // VULNERABLE: No path authorization
        return java.io.File("/uploads/$path").readBytes()
    }

    // Test 9: Broken access control in API
    fun handleApiRequest(endpoint: String, userId: Int): Any {
        // VULNERABLE: No authorization
        return when (endpoint) {
            "/users" -> userRepository.findAll()
            "/admin/settings" -> getAdminSettings()
            "/user/$userId" -> userRepository.findById(userId)
            else -> mapOf("error" to "Not found")
        }
    }

    // Test 10: Mass assignment with role
    fun updateUser(userId: Int, params: Map<String, Any>) {
        val user = userRepository.findById(userId)
        // VULNERABLE: Can set isAdmin via params
        params["isAdmin"]?.let { user?.isAdmin = it as Boolean }
        params["role"]?.let { user?.role = it as String }
        user?.let { userRepository.save(it) }
    }

    // Test 11: Cached authorization
    private val permissionCache = mutableMapOf<String, Boolean>()

    fun checkPermission(userId: Int, resource: String): Boolean {
        val key = "$userId-$resource"
        // VULNERABLE: Cached permissions may be stale
        return permissionCache.getOrPut(key) {
            checkActualPermission(userId, resource)
        }
    }

    // Test 12: Token validation bypass
    fun validateToken(token: String): Boolean {
        // VULNERABLE: Debug backdoor
        if (token == "debug") return true
        if (token.isEmpty()) return false
        return tokenValidator.validate(token)
    }

    private fun exportAllData() {}
    private fun resetSystem() {}
    private fun getAdminSettings(): Map<String, Any> = emptyMap()
    private fun checkActualPermission(userId: Int, resource: String): Boolean = false
    private val tokenValidator = object {
        fun validate(token: String): Boolean = false
    }
    private val userRepository = object {
        fun delete(id: Int) {}
        fun findById(id: Int): User? = null
        fun findAll(): List<User> = emptyList()
        fun update(id: Int, data: Map<String, Any>) {}
        fun setRole(id: Int, role: String) {}
        fun deleteAll() {}
        fun save(user: User) {}
    }
    private val resourceRepository = object {
        fun get(id: String?, userId: Int?): Any? = null
    }
}

data class User(
    var id: Int = 0,
    var name: String = "",
    var isAdmin: Boolean = false,
    var role: String = "user"
)
