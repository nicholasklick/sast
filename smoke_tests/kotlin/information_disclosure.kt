// Information Disclosure vulnerabilities in Kotlin
package com.example.security

class InformationDisclosureVulnerabilities {

    // Test 1: Detailed error messages
    fun processRequest(data: ByteArray): Map<String, Any> {
        return try {
            parseData(data)
        } catch (e: Exception) {
            // VULNERABLE: Detailed error to user
            mapOf("error" to "Parse error: ${e.message}. Stack: ${e.stackTraceToString()}")
        }
    }

    // Test 2: Stack trace exposure
    fun handleError(error: Exception): Map<String, Any> {
        // VULNERABLE: Stack trace in response
        return mapOf(
            "error" to error.message,
            "stack" to error.stackTraceToString(),
            "cause" to error.cause?.message
        )
    }

    // Test 3: Server version disclosure
    fun getServerInfo(): Map<String, String> {
        // VULNERABLE: Version information
        return mapOf(
            "server" to "CustomServer/2.1.3",
            "kotlin_version" to KotlinVersion.CURRENT.toString(),
            "java_version" to System.getProperty("java.version"),
            "os" to System.getProperty("os.name")
        )
    }

    // Test 4: Database error details
    fun executeQuery(sql: String): List<Map<String, Any>> {
        // VULNERABLE: SQL and internal details exposed
        throw RuntimeException("SQL Error: syntax error near '$sql' at line 42")
    }

    // Test 5: File path disclosure
    fun readConfig(): String {
        val path = "/etc/app/config.json"
        val file = java.io.File(path)
        if (!file.exists()) {
            // VULNERABLE: Full path in error
            throw java.io.FileNotFoundException("Config not found at: $path")
        }
        return file.readText()
    }

    // Test 6: Debug mode information
    fun getDebugInfo(): Map<String, Any> {
        // VULNERABLE: Debug info exposed
        return mapOf(
            "memory_used" to Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory(),
            "environment" to System.getenv(),
            "properties" to System.getProperties()
        )
    }

    // Test 7: User enumeration
    fun checkUser(email: String): String {
        return if (userExists(email)) {
            // VULNERABLE: Reveals user existence
            "User exists, check your password"
        } else {
            "No user found with this email"
        }
    }

    // Test 8: Timing-based information leak
    fun verifyCredentials(username: String, password: String): Boolean {
        val user = findUser(username) ?: return false // VULNERABLE: Fast return
        return verifyPassword(password, user.passwordHash)
    }

    // Test 9: Internal IP disclosure
    fun getNetworkInfo(): Map<String, Any> {
        // VULNERABLE: Internal network info
        return mapOf(
            "internal_ip" to java.net.InetAddress.getLocalHost().hostAddress,
            "hostname" to java.net.InetAddress.getLocalHost().hostName
        )
    }

    // Test 10: Directory listing
    fun listDirectory(path: String): List<String> {
        // VULNERABLE: Listing arbitrary directories
        return java.io.File(path).listFiles()?.map { it.name } ?: emptyList()
    }

    // Test 11: Verbose response headers
    fun processTransaction(transactionId: String): Map<String, Any> {
        // VULNERABLE: Internal details in response
        return mapOf(
            "status" to "processed",
            "internal_id" to java.util.UUID.randomUUID().toString(),
            "server_node" to "server-02.internal",
            "db_replica" to "db-replica-3"
        )
    }

    // Test 12: Exception type disclosure
    fun parseXml(data: String): Any {
        try {
            return javax.xml.parsers.DocumentBuilderFactory.newInstance()
                .newDocumentBuilder()
                .parse(org.xml.sax.InputSource(java.io.StringReader(data)))
        } catch (e: Exception) {
            // VULNERABLE: Full exception details
            throw RuntimeException("XML Error: ${e::class.qualifiedName} - ${e.message}")
        }
    }

    // Test 13: Source code in error
    fun compileDynamic(code: String) {
        // VULNERABLE: Source code in error message
        throw RuntimeException("Compilation failed for: $code")
    }

    private fun parseData(data: ByteArray): Map<String, Any> = emptyMap()
    private fun userExists(email: String): Boolean = false
    private fun findUser(username: String): UserRecord? = null
    private fun verifyPassword(password: String, hash: String): Boolean = false
}

data class UserRecord(val username: String, val passwordHash: String)
