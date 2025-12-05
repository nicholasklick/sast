// Null Safety and Exception vulnerabilities in Kotlin
package com.example.security

class NullSafetyVulnerabilities {

    // Test 1: Force unwrap with !!
    fun getUserName(userId: Int): String {
        val user = findUser(userId)
        // VULNERABLE: Force unwrap can throw NPE
        return user!!.name
    }

    // Test 2: Unsafe cast
    fun processResponse(data: Any): Map<String, Any> {
        // VULNERABLE: Unsafe cast can throw ClassCastException
        return data as Map<String, Any>
    }

    // Test 3: lateinit without initialization check
    lateinit var database: Database

    fun query(sql: String): List<Any> {
        // VULNERABLE: May throw UninitializedPropertyAccessException
        return database.execute(sql)
    }

    // Test 4: Array index without bounds check
    fun getItem(items: Array<String>, index: Int): String {
        // VULNERABLE: No bounds check
        return items[index]
    }

    // Test 5: First element without check
    fun getFirstUser(users: List<User>): User {
        // VULNERABLE: List might be empty
        return users.first()
    }

    // Test 6: Map get with !!
    fun getConfig(key: String): String {
        val config = loadConfig()
        // VULNERABLE: Key may not exist
        return config[key]!!
    }

    // Test 7: Platform types from Java
    fun processJavaObject(obj: JavaObject): String {
        // VULNERABLE: Platform type could be null
        return obj.getName().uppercase()
    }

    // Test 8: Double bang chain
    fun getNestedValue(data: Map<String, Any?>): String {
        // VULNERABLE: Multiple force unwraps
        return ((data["user"] as Map<String, Any?>)["profile"] as Map<String, Any?>)["name"]!!.toString()
    }

    // Test 9: let with side effect
    fun processOptional(value: String?) {
        // VULNERABLE: value could change between check and use in multi-threaded context
        if (value != null) {
            Thread.sleep(1)
            println(value.length) // value could be null if var
        }
    }

    // Test 10: Regex without match check
    fun extractNumber(input: String): String {
        val regex = Regex("\\d+")
        // VULNERABLE: find() might return null
        return regex.find(input)!!.value
    }

    // Test 11: Iterator next without hasNext
    fun getNext(items: Iterator<String>): String {
        // VULNERABLE: No hasNext check
        return items.next()
    }

    // Test 12: Single element from empty collection
    fun getSingle(items: List<String>): String {
        // VULNERABLE: Throws if not exactly one element
        return items.single()
    }

    // Test 13: Substring without bounds check
    fun extractPart(str: String, start: Int, end: Int): String {
        // VULNERABLE: IndexOutOfBoundsException
        return str.substring(start, end)
    }

    // Test 14: Division without zero check
    fun divide(a: Int, b: Int): Int {
        // VULNERABLE: Division by zero
        return a / b
    }

    // Test 15: Generic type erasure
    inline fun <reified T> parseJson(json: String): T {
        // VULNERABLE: Type mismatch at runtime
        return com.google.gson.Gson().fromJson(json, T::class.java)
    }

    private fun findUser(userId: Int): User? = null
    private fun loadConfig(): Map<String, String> = emptyMap()
}

data class User(val name: String)
class Database {
    fun execute(sql: String): List<Any> = emptyList()
}
interface JavaObject {
    fun getName(): String?
}
