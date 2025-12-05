// Server-Side Request Forgery (SSRF) vulnerabilities in Groovy
package com.example.security

class SsrfVulnerabilities {

    // Test 1: Direct URL fetch
    String fetchUrl(String urlString) {
        // VULNERABLE: User-controlled URL
        new URL(urlString).text
    }

    // Test 2: Image proxy
    byte[] proxyImage(String imageUrl) {
        // VULNERABLE: Fetching arbitrary URLs
        new URL(imageUrl).bytes
    }

    // Test 3: Webhook URL
    int sendWebhook(String webhookUrl, String payload) {
        // VULNERABLE: Webhook destination from user
        def url = new URL(webhookUrl)
        def connection = url.openConnection() as HttpURLConnection
        connection.requestMethod = 'POST'
        connection.doOutput = true
        connection.outputStream.write(payload.bytes)
        connection.responseCode
    }

    // Test 4: Groovy HTTP Builder
    String fetchWithHttpBuilder(String targetUrl) {
        // VULNERABLE: User URL with HTTP Builder
        def http = new groovyx.net.http.HTTPBuilder(targetUrl)
        http.get([:]).toString()
    }

    // Test 5: Partial URL construction
    String fetchFromHost(String hostname) {
        // VULNERABLE: User controls hostname
        def url = new URL("http://${hostname}/api/data")
        url.text
    }

    // Test 6: Port scanning
    boolean checkPort(String host, int port) {
        // VULNERABLE: Port from user
        try {
            def url = new URL("http://${host}:${port}/")
            def connection = url.openConnection() as HttpURLConnection
            connection.connectTimeout = 1000
            connection.connect()
            true
        } catch (Exception e) {
            false
        }
    }

    // Test 7: File protocol SSRF
    String readResource(String uri) {
        // VULNERABLE: Can use file:// protocol
        new URL(uri).text
    }

    // Test 8: Redirect following
    String fetchWithRedirects(String urlString) {
        def url = new URL(urlString)
        def connection = url.openConnection() as HttpURLConnection
        // VULNERABLE: Following redirects to internal
        connection.instanceFollowRedirects = true
        connection.inputStream.text
    }

    // Test 9: DNS rebinding
    String fetchExternal(String domain, String path) {
        // VULNERABLE: DNS can resolve to internal IP
        def url = new URL("http://${domain}/${path}")
        url.text
    }

    // Test 10: REST client
    String restClientRequest(String targetUrl) {
        // VULNERABLE: User URL with REST client
        def client = new groovyx.net.http.RESTClient(targetUrl)
        client.get([:]).data.toString()
    }

    // Test 11: API endpoint construction
    String callExternalApi(String baseUrl, String endpoint) {
        // VULNERABLE: Both from user
        def url = new URL("${baseUrl}/${endpoint}")
        url.text
    }

    // Test 12: withInputStream pattern
    String fetchWithStream(String urlString) {
        // VULNERABLE: User URL
        new URL(urlString).withInputStream { stream ->
            stream.text
        }
    }
}
