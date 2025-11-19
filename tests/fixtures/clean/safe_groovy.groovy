// Clean Groovy code with no vulnerabilities
package com.example.safe

import java.sql.Connection
import java.sql.PreparedStatement
import java.nio.file.Paths
import java.security.SecureRandom

class SafeGroovyCode {

    // 1. Safe SQL Query - PreparedStatement
    def getUserById(Connection connection, int userId) {
        def query = "SELECT * FROM users WHERE id = ?"
        def stmt = connection.prepareStatement(query)
        stmt.setInt(1, userId)
        def resultSet = stmt.executeQuery()
        return resultSet.next() ? resultSet.getString("name") : null
    }

    // 2. Safe File Access - Path validation
    def readFile(String filename) {
        def basePath = Paths.get("/var/data").toAbsolutePath().normalize()
        def filePath = basePath.resolve(filename).normalize()

        if (!filePath.startsWith(basePath)) {
            throw new SecurityException("Path traversal detected")
        }

        return new File(filePath.toString()).text
    }

    // 3. Safe Configuration
    def getApiKey() {
        return System.getenv("API_KEY") ?: { throw new IllegalStateException("API_KEY not set") }()
    }

    // 4. Safe Cryptography - AES
    def encryptData(byte[] data, byte[] keyBytes) {
        import javax.crypto.Cipher
        import javax.crypto.spec.SecretKeySpec

        def key = new SecretKeySpec(keyBytes, "AES")
        def cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher.doFinal(data)
    }

    // 5. Safe Hashing - SHA-256
    def hashPassword(String password) {
        import java.security.MessageDigest
        def digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(password.bytes).encodeHex().toString()
    }

    // 6. Safe Random Generation
    def generateSecureToken() {
        def random = new SecureRandom()
        def bytes = new byte[32]
        random.nextBytes(bytes)
        return bytes.encodeHex().toString()
    }

    // 7. Safe Command Execution
    def listFiles(String directory) {
        def allowedDirs = ["/tmp", "/var/log"]
        if (!(directory in allowedDirs)) {
            throw new SecurityException("Directory not allowed")
        }

        return ["ls", "-la", directory].execute().text
    }

    // 8. Safe Input Validation
    def validateAndSanitize(String input) {
        return input.replaceAll(/[^a-zA-Z0-9_-]/, "")
    }
}
