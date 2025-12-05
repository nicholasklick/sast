// Mass Assignment vulnerabilities in Kotlin
package com.example.security

import com.fasterxml.jackson.databind.ObjectMapper

class MassAssignmentVulnerabilities {

    private val objectMapper = ObjectMapper()

    // Test 1: Direct map assignment
    fun updateUser(userId: Int, params: Map<String, Any>) {
        val user = getUser(userId)
        // VULNERABLE: All params assigned
        params.forEach { (key, value) ->
            setUserProperty(user, key, value)
        }
        saveUser(user)
    }

    // Test 2: Jackson deserialization
    fun createUserFromJson(json: String): User {
        // VULNERABLE: Decodes all fields including isAdmin
        return objectMapper.readValue(json, User::class.java)
    }

    // Test 3: Data class copy with spread
    fun patchUser(userId: Int, updates: Map<String, Any>): User {
        val user = getUser(userId)
        // VULNERABLE: Copying with untrusted updates
        return user.copy(
            name = updates["name"] as? String ?: user.name,
            email = updates["email"] as? String ?: user.email,
            isAdmin = updates["isAdmin"] as? Boolean ?: user.isAdmin, // VULNERABLE
            role = updates["role"] as? String ?: user.role // VULNERABLE
        )
    }

    // Test 4: Reflection-based assignment
    fun updateObject(obj: Any, params: Map<String, Any>) {
        // VULNERABLE: Setting arbitrary properties
        params.forEach { (key, value) ->
            val field = obj.javaClass.getDeclaredField(key)
            field.isAccessible = true
            field.set(obj, value)
        }
    }

    // Test 5: Form data binding
    fun handleFormSubmission(formData: Map<String, String>): Profile {
        // VULNERABLE: All form fields accepted
        return Profile(
            name = formData["name"] ?: "",
            bio = formData["bio"] ?: "",
            isVerified = formData["isVerified"]?.toBoolean() ?: false, // VULNERABLE
            permissions = formData["permissions"] ?: "" // VULNERABLE
        )
    }

    // Test 6: API request body
    fun handleApiRequest(body: Map<String, Any>): Map<String, Any> {
        // VULNERABLE: Copying all body params
        val userData = body["user"] as? Map<String, Any>
        if (userData != null) {
            createUser(userData)
        }
        return mapOf("status" to "created")
    }

    // Test 7: Apply extension function abuse
    fun updateSettings(settings: Settings, params: Map<String, Any>): Settings {
        // VULNERABLE: All params applied
        return settings.apply {
            params["theme"]?.let { theme = it as String }
            params["language"]?.let { language = it as String }
            params["adminMode"]?.let { adminMode = it as Boolean } // VULNERABLE
        }
    }

    // Test 8: Constructor with defaults
    fun createUserFromParams(params: Map<String, Any>): User {
        // VULNERABLE: All params used in construction
        return User(
            id = params["id"] as? Int ?: 0,
            name = params["name"] as? String ?: "",
            email = params["email"] as? String ?: "",
            isAdmin = params["isAdmin"] as? Boolean ?: false,
            role = params["role"] as? String ?: "user"
        )
    }

    // Test 9: GSON deserialization
    fun deserializeWithGson(json: String): User {
        // VULNERABLE: All fields decoded
        return com.google.gson.Gson().fromJson(json, User::class.java)
    }

    // Test 10: Merge maps
    fun mergeUserData(userId: Int, newData: Map<String, Any>): Map<String, Any> {
        val existingData = getUserData(userId).toMutableMap()
        // VULNERABLE: Merging untrusted data
        existingData.putAll(newData)
        return existingData
    }

    // Test 11: Kotlin serialization
    fun deserializeKotlinx(json: String): User {
        // VULNERABLE: All fields deserialized
        return kotlinx.serialization.json.Json.decodeFromString(json)
    }

    // Test 12: Builder pattern with untrusted input
    fun buildUser(params: Map<String, Any>): User {
        // VULNERABLE: Builder accepts all params
        return UserBuilder()
            .id(params["id"] as? Int ?: 0)
            .name(params["name"] as? String ?: "")
            .isAdmin(params["isAdmin"] as? Boolean ?: false) // VULNERABLE
            .build()
    }

    private fun getUser(userId: Int): User = User(userId, "", "", false, "user")
    private fun setUserProperty(user: User, key: String, value: Any) {}
    private fun saveUser(user: User) {}
    private fun createUser(data: Map<String, Any>) {}
    private fun getUserData(userId: Int): Map<String, Any> = emptyMap()
}

data class User(
    val id: Int,
    var name: String,
    var email: String,
    var isAdmin: Boolean,
    var role: String
)

data class Profile(
    val name: String,
    val bio: String,
    val isVerified: Boolean,
    val permissions: String
)

data class Settings(
    var theme: String = "light",
    var language: String = "en",
    var adminMode: Boolean = false
)

class UserBuilder {
    private var id: Int = 0
    private var name: String = ""
    private var isAdmin: Boolean = false

    fun id(id: Int) = apply { this.id = id }
    fun name(name: String) = apply { this.name = name }
    fun isAdmin(isAdmin: Boolean) = apply { this.isAdmin = isAdmin }
    fun build() = User(id, name, "", isAdmin, "user")
}
