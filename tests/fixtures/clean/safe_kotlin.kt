// Clean Kotlin code with no vulnerabilities - should produce zero findings
package com.example.safe

import java.sql.Connection
import java.sql.PreparedStatement
import java.nio.file.Paths
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest

class SafeKotlinCode {

    // 1. Safe SQL Query - Using PreparedStatement
    fun getUserById(connection: Connection, userId: Int): String? {
        val query = "SELECT * FROM users WHERE id = ?"
        connection.prepareStatement(query).use { stmt ->
            stmt.setInt(1, userId)
            val resultSet = stmt.executeQuery()
            return if (resultSet.next()) resultSet.getString("name") else null
        }
    }

    // 2. Safe File Access - Path validation
    fun readFile(filename: String): String {
        val basePath = Paths.get("/var/data").toAbsolutePath().normalize()
        val filePath = basePath.resolve(filename).normalize()

        // Validate path is within base directory
        if (!filePath.startsWith(basePath)) {
            throw SecurityException("Path traversal attempt detected")
        }

        return filePath.toFile().readText()
    }

    // 3. Safe Configuration - Environment variable
    fun getApiKey(): String {
        return System.getenv("API_KEY") ?: throw IllegalStateException("API_KEY not set")
    }

    // 4. Safe Cryptography - AES-256
    fun encryptData(data: ByteArray, keyBytes: ByteArray): ByteArray {
        val key = SecretKeySpec(keyBytes, "AES")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher.doFinal(data)
    }

    // 5. Safe Hashing - SHA-256
    fun hashPassword(password: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(password.toByteArray())
        return hash.joinToString("") { "%02x".format(it) }
    }

    // 6. Safe Random Number Generation
    fun generateSecureToken(): String {
        val random = SecureRandom()
        val bytes = ByteArray(32)
        random.nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }

    // 7. Safe XML Processing - XXE protection
    fun parseXmlSafely(xmlContent: String) {
        val factory = javax.xml.parsers.DocumentBuilderFactory.newInstance()
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)

        val builder = factory.newDocumentBuilder()
        builder.parse(java.io.ByteArrayInputStream(xmlContent.toByteArray()))
    }

    // 8. Safe Command Execution - Parameterized
    fun listFiles(directory: String): List<String> {
        // Using ProcessBuilder with separate arguments (no shell injection)
        val allowedDirs = setOf("/tmp", "/var/log")
        if (directory !in allowedDirs) {
            throw SecurityException("Directory not allowed")
        }

        val process = ProcessBuilder("ls", "-la", directory).start()
        return process.inputStream.bufferedReader().readLines()
    }

    // 9. Safe URL Fetching - Whitelist validation
    fun fetchUrl(url: String): String {
        val allowedHosts = setOf("api.example.com", "data.example.com")
        val uri = java.net.URI(url)

        if (uri.host !in allowedHosts) {
            throw SecurityException("Host not allowed")
        }

        return java.net.URL(url).readText()
    }

    // 10. Safe Input Validation
    fun validateAndSanitize(input: String): String {
        // Remove any special characters
        return input.replace(Regex("[^a-zA-Z0-9_-]"), "")
    }
}
