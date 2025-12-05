// Insecure Network Communication vulnerabilities in Kotlin
package com.example.security

import java.net.URL
import java.net.HttpURLConnection
import javax.net.ssl.*
import java.security.cert.X509Certificate

class InsecureNetworkVulnerabilities {

    // Test 1: HTTP instead of HTTPS
    fun fetchOverHttp(): String {
        // VULNERABLE: Using HTTP
        val url = URL("http://api.example.com/data")
        return url.readText()
    }

    // Test 2: Trust all certificates
    fun createTrustAllManager(): TrustManager {
        // VULNERABLE: Trust all certs
        return object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }
    }

    // Test 3: Disable hostname verification
    fun disableHostnameVerification(): HostnameVerifier {
        // VULNERABLE: Accept any hostname
        return HostnameVerifier { _, _ -> true }
    }

    // Test 4: Insecure SSL context
    fun createInsecureSslContext(): SSLContext {
        val trustAllCerts = arrayOf<TrustManager>(createTrustAllManager() as X509TrustManager)
        // VULNERABLE: SSL context trusting all certs
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, trustAllCerts, java.security.SecureRandom())
        return sslContext
    }

    // Test 5: Credentials in URL
    fun fetchWithCredsInUrl(): String {
        // VULNERABLE: Credentials visible
        val url = URL("https://user:password@api.example.com/data")
        return url.readText()
    }

    // Test 6: Unencrypted WebSocket
    fun connectWebSocket(): String {
        // VULNERABLE: Using ws:// instead of wss://
        return "ws://example.com/socket"
    }

    // Test 7: No certificate pinning
    fun fetchWithoutPinning(urlString: String): String {
        // VULNERABLE: No certificate pinning
        val url = URL(urlString)
        val connection = url.openConnection() as HttpURLConnection
        return connection.inputStream.bufferedReader().readText()
    }

    // Test 8: API key in header
    fun fetchWithApiKey(): String {
        val url = URL("https://api.example.com/data")
        val connection = url.openConnection() as HttpURLConnection
        // VULNERABLE: API key transmitted
        connection.setRequestProperty("X-API-Key", "sk-secret-api-key-12345")
        return connection.inputStream.bufferedReader().readText()
    }

    // Test 9: Logging network responses
    fun fetchAndLog(url: URL): String {
        val response = url.readText()
        // VULNERABLE: Logging potentially sensitive response
        println("Response: $response")
        return response
    }

    // Test 10: Weak TLS version
    fun configureWeakTls(): SSLContext {
        // VULNERABLE: Using weak TLS version
        return SSLContext.getInstance("TLSv1")
    }

    // Test 11: Cleartext traffic
    fun sendCleartextData(host: String, data: String) {
        // VULNERABLE: Unencrypted socket
        val socket = java.net.Socket(host, 80)
        socket.getOutputStream().write(data.toByteArray())
    }

    // Test 12: Basic auth over HTTP
    fun basicAuthHttp(username: String, password: String): String {
        // VULNERABLE: Basic auth over HTTP
        val url = URL("http://api.example.com/secure")
        val connection = url.openConnection() as HttpURLConnection
        val credentials = java.util.Base64.getEncoder()
            .encodeToString("$username:$password".toByteArray())
        connection.setRequestProperty("Authorization", "Basic $credentials")
        return connection.inputStream.bufferedReader().readText()
    }

    // Test 13: Ignore SSL errors in OkHttp
    fun createInsecureOkHttpClient(): Any {
        // VULNERABLE: Would create client ignoring SSL
        val trustAllCerts = createTrustAllManager()
        return "insecure_client"
    }
}
