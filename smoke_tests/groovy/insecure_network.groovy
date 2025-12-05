// Insecure Network Communication vulnerabilities in Groovy
package com.example.security

import javax.net.ssl.*
import java.security.cert.X509Certificate

class InsecureNetworkVulnerabilities {

    // Test 1: HTTP instead of HTTPS
    String fetchOverHttp() {
        // VULNERABLE: Using HTTP
        new URL("http://api.example.com/data").text
    }

    // Test 2: Trust all certificates
    TrustManager createTrustAllManager() {
        // VULNERABLE: Trust all certs
        [
            checkClientTrusted: { chain, authType -> },
            checkServerTrusted: { chain, authType -> },
            getAcceptedIssuers: { [] as X509Certificate[] }
        ] as X509TrustManager
    }

    // Test 3: Disable hostname verification
    HostnameVerifier disableHostnameVerification() {
        // VULNERABLE: Accept any hostname
        { hostname, session -> true } as HostnameVerifier
    }

    // Test 4: Insecure SSL context
    SSLContext createInsecureSslContext() {
        def trustAllCerts = [createTrustAllManager()] as TrustManager[]
        // VULNERABLE: SSL context trusting all certs
        def sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, trustAllCerts, new java.security.SecureRandom())
        sslContext
    }

    // Test 5: Credentials in URL
    String fetchWithCredsInUrl() {
        // VULNERABLE: Credentials visible
        new URL("https://user:password@api.example.com/data").text
    }

    // Test 6: Unencrypted WebSocket
    String connectWebSocket() {
        // VULNERABLE: Using ws:// instead of wss://
        "ws://example.com/socket"
    }

    // Test 7: No certificate pinning
    String fetchWithoutPinning(String urlString) {
        // VULNERABLE: No certificate pinning
        new URL(urlString).text
    }

    // Test 8: API key in header
    String fetchWithApiKey() {
        def url = new URL("https://api.example.com/data")
        def connection = url.openConnection() as HttpURLConnection
        // VULNERABLE: API key transmitted
        connection.setRequestProperty("X-API-Key", "sk-secret-api-key-12345")
        connection.inputStream.text
    }

    // Test 9: Logging network responses
    String fetchAndLog(URL url) {
        def response = url.text
        // VULNERABLE: Logging potentially sensitive response
        println "Response: ${response}"
        response
    }

    // Test 10: Weak TLS version
    SSLContext configureWeakTls() {
        // VULNERABLE: Using weak TLS version
        SSLContext.getInstance("TLSv1")
    }

    // Test 11: Cleartext traffic
    void sendCleartextData(String host, String data) {
        // VULNERABLE: Unencrypted socket
        def socket = new Socket(host, 80)
        socket.outputStream.write(data.bytes)
        socket.close()
    }

    // Test 12: Basic auth over HTTP
    String basicAuthHttp(String username, String password) {
        // VULNERABLE: Basic auth over HTTP
        def url = new URL("http://api.example.com/secure")
        def connection = url.openConnection() as HttpURLConnection
        def credentials = "${username}:${password}".bytes.encodeBase64().toString()
        connection.setRequestProperty("Authorization", "Basic ${credentials}")
        connection.inputStream.text
    }

    // Test 13: Groovy HTTP Builder insecure
    String httpBuilderInsecure(String targetUrl) {
        // VULNERABLE: HTTP Builder without SSL verification
        "new HTTPBuilder('${targetUrl}').get([:])"
    }
}
