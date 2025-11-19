// Kotlin Vulnerability Test Fixtures
package com.example.vulnerabilities

import java.sql.Connection
import java.sql.DriverManager
import java.sql.Statement
import java.io.File
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class KotlinVulnerabilities {

    // 1. SQL Injection - String concatenation
    fun sqlInjectionConcat(userId: String): String {
        val connection = DriverManager.getConnection("jdbc:mysql://localhost/db")
        val statement = connection.createStatement()
        val query = "SELECT * FROM users WHERE id = '$userId'"
        val resultSet = statement.executeQuery(query)
        return if (resultSet.next()) resultSet.getString("name") else ""
    }

    // 2. SQL Injection - String interpolation
    fun sqlInjectionInterpolation(username: String): Boolean {
        val connection = DriverManager.getConnection("jdbc:mysql://localhost/db")
        val query = "SELECT * FROM users WHERE username = '$username'"
        val statement = connection.createStatement()
        val resultSet = statement.executeQuery(query)
        return resultSet.next()
    }

    // 3. Command Injection - Runtime.exec
    fun commandInjection(filename: String) {
        Runtime.getRuntime().exec("cat $filename")
    }

    // 4. Command Injection - ProcessBuilder
    fun commandInjectionBuilder(userInput: String) {
        val process = ProcessBuilder("sh", "-c", "ls $userInput").start()
        process.waitFor()
    }

    // 5. Path Traversal
    fun pathTraversal(filename: String): String {
        val file = File("/var/data/$filename")
        return file.readText()
    }

    // 6. Hardcoded Credentials - API Key
    val apiKey = "sk_live_1234567890abcdef"

    // 7. Hardcoded Credentials - Password
    fun authenticate() {
        val password = "admin123"
        val dbPassword = "SuperSecret123!"
    }

    // 8. Weak Cryptography - DES
    fun weakCrypto(data: ByteArray): ByteArray {
        val key = SecretKeySpec("12345678".toByteArray(), "DES")
        val cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher.doFinal(data)
    }

    // 9. Weak Cryptography - MD5
    fun weakHash(input: String): String {
        val md = java.security.MessageDigest.getInstance("MD5")
        return md.digest(input.toByteArray()).toString()
    }

    // 10. XXE Vulnerability
    fun parseXml(xmlContent: String) {
        val factory = javax.xml.parsers.DocumentBuilderFactory.newInstance()
        // Missing: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
        val builder = factory.newDocumentBuilder()
        val doc = builder.parse(java.io.ByteArrayInputStream(xmlContent.toByteArray()))
    }

    // 11. Insecure Deserialization
    fun deserializeObject(data: ByteArray): Any? {
        val ois = java.io.ObjectInputStream(java.io.ByteArrayInputStream(data))
        return ois.readObject()
    }

    // 12. LDAP Injection
    fun ldapInjection(username: String): Boolean {
        val env = java.util.Hashtable<String, String>()
        env["java.naming.factory.initial"] = "com.sun.jndi.ldap.LdapCtxFactory"
        env["java.naming.provider.url"] = "ldap://localhost:389"
        val ctx = javax.naming.directory.InitialDirContext(env)
        val filter = "(uid=$username)"
        val results = ctx.search("ou=users,dc=example,dc=com", filter, null)
        return results.hasMore()
    }

    // 13. XSS in Android WebView (Kotlin Android pattern)
    fun xssWebView(userInput: String) {
        // Simulating Android WebView
        val html = "<html><body>Hello $userInput</body></html>"
        // webView.loadData(html, "text/html", "UTF-8")
    }

    // 14. Unsafe Random
    fun generateToken(): String {
        val random = java.util.Random()
        return random.nextLong().toString()
    }

    // 15. SSRF Vulnerability
    fun fetchUrl(url: String): String {
        val connection = java.net.URL(url).openConnection()
        return connection.getInputStream().bufferedReader().readText()
    }
}
