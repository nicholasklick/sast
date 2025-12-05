// Server-Side Request Forgery (SSRF) vulnerabilities in Kotlin
package com.example.security

import java.net.URL
import java.net.HttpURLConnection
import java.io.BufferedReader
import java.io.InputStreamReader
import okhttp3.OkHttpClient
import okhttp3.Request

class SsrfVulnerabilities {

    private val httpClient = OkHttpClient()

    // Test 1: Direct URL fetch
    fun fetchUrl(urlString: String): String {
        // VULNERABLE: User-controlled URL
        val url = URL(urlString)
        val connection = url.openConnection() as HttpURLConnection
        return connection.inputStream.bufferedReader().readText()
    }

    // Test 2: Image proxy
    fun proxyImage(imageUrl: String): ByteArray {
        // VULNERABLE: Fetching arbitrary URLs
        val url = URL(imageUrl)
        return url.readBytes()
    }

    // Test 3: Webhook URL
    fun sendWebhook(webhookUrl: String, payload: String): Int {
        // VULNERABLE: Webhook destination from user
        val url = URL(webhookUrl)
        val connection = url.openConnection() as HttpURLConnection
        connection.requestMethod = "POST"
        connection.doOutput = true
        connection.outputStream.write(payload.toByteArray())
        return connection.responseCode
    }

    // Test 4: URL from database
    fun fetchFromConfig(configKey: String): String {
        val targetUrl = getConfigValue(configKey)
        // VULNERABLE: URL from potentially tainted config
        val url = URL(targetUrl)
        return url.readText()
    }

    // Test 5: Partial URL construction
    fun fetchFromHost(hostname: String): String {
        // VULNERABLE: User controls hostname
        val url = URL("http://$hostname/api/data")
        return url.readText()
    }

    // Test 6: Port scanning
    fun checkPort(host: String, port: Int): Boolean {
        // VULNERABLE: Port from user
        return try {
            val url = URL("http://$host:$port/")
            val connection = url.openConnection() as HttpURLConnection
            connection.connectTimeout = 1000
            connection.connect()
            true
        } catch (e: Exception) {
            false
        }
    }

    // Test 7: OkHttp client
    fun fetchWithOkHttp(targetUrl: String): String? {
        // VULNERABLE: User URL with OkHttp
        val request = Request.Builder()
            .url(targetUrl)
            .build()
        return httpClient.newCall(request).execute().body?.string()
    }

    // Test 8: File protocol SSRF
    fun readResource(uri: String): String {
        // VULNERABLE: Can use file:// protocol
        val url = URL(uri)
        return url.readText()
    }

    // Test 9: URL from headers
    fun fetchFromHeader(request: HttpRequest): String {
        val targetUrl = request.getHeader("X-Target-URL")
        // VULNERABLE: URL from header
        return URL(targetUrl).readText()
    }

    // Test 10: Redirect following
    fun fetchWithRedirects(urlString: String): String {
        val url = URL(urlString)
        val connection = url.openConnection() as HttpURLConnection
        // VULNERABLE: Following redirects to internal
        connection.instanceFollowRedirects = true
        return connection.inputStream.bufferedReader().readText()
    }

    // Test 11: DNS rebinding
    fun fetchExternal(domain: String, path: String): String {
        // VULNERABLE: DNS can resolve to internal IP
        val url = URL("http://$domain/$path")
        return url.readText()
    }

    // Test 12: API endpoint construction
    fun callExternalApi(baseUrl: String, endpoint: String): String {
        // VULNERABLE: Both from user
        val url = URL("$baseUrl/$endpoint")
        return url.readText()
    }

    private fun getConfigValue(key: String): String = ""
}

interface HttpRequest {
    fun getHeader(name: String): String
}
