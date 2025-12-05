// Information Disclosure vulnerabilities in Groovy
package com.example.security

class InformationDisclosureVulnerabilities {

    // Test 1: Detailed error messages
    Map processRequest(byte[] data) {
        try {
            parseData(data)
        } catch (Exception e) {
            // VULNERABLE: Detailed error to user
            [error: "Parse error: ${e.message}. Stack: ${e.stackTrace.join('\n')}"]
        }
    }

    // Test 2: Stack trace exposure
    Map handleError(Exception error) {
        // VULNERABLE: Stack trace in response
        [
            error: error.message,
            stack: error.stackTrace.collect { it.toString() },
            cause: error.cause?.message
        ]
    }

    // Test 3: Server version disclosure
    Map getServerInfo() {
        // VULNERABLE: Version information
        [
            server: "CustomServer/2.1.3",
            groovy_version: GroovySystem.version,
            java_version: System.getProperty("java.version"),
            os: System.getProperty("os.name")
        ]
    }

    // Test 4: Database error details
    List executeQuery(String sql) {
        // VULNERABLE: SQL and internal details exposed
        throw new RuntimeException("SQL Error: syntax error near '${sql}' at line 42")
    }

    // Test 5: File path disclosure
    String readConfig() {
        def path = "/etc/app/config.json"
        def file = new File(path)
        if (!file.exists()) {
            // VULNERABLE: Full path in error
            throw new FileNotFoundException("Config not found at: ${path}")
        }
        file.text
    }

    // Test 6: Debug mode information
    Map getDebugInfo() {
        // VULNERABLE: Debug info exposed
        [
            memory_used: Runtime.runtime.totalMemory() - Runtime.runtime.freeMemory(),
            environment: System.getenv(),
            properties: System.properties
        ]
    }

    // Test 7: User enumeration
    String checkUser(String email) {
        if (userExists(email)) {
            // VULNERABLE: Reveals user existence
            "User exists, check your password"
        } else {
            "No user found with this email"
        }
    }

    // Test 8: Timing-based information leak
    boolean verifyCredentials(String username, String password) {
        def user = findUser(username)
        if (!user) return false // VULNERABLE: Fast return
        verifyPassword(password, user.passwordHash)
    }

    // Test 9: Internal IP disclosure
    Map getNetworkInfo() {
        // VULNERABLE: Internal network info
        [
            internal_ip: InetAddress.localHost.hostAddress,
            hostname: InetAddress.localHost.hostName
        ]
    }

    // Test 10: Directory listing
    List listDirectory(String path) {
        // VULNERABLE: Listing arbitrary directories
        new File(path).listFiles()*.name
    }

    // Test 11: Verbose response
    Map processTransaction(String transactionId) {
        // VULNERABLE: Internal details in response
        [
            status: "processed",
            internal_id: UUID.randomUUID().toString(),
            server_node: "server-02.internal",
            db_replica: "db-replica-3"
        ]
    }

    // Test 12: Exception type disclosure
    def parseXml(String data) {
        try {
            new XmlSlurper().parseText(data)
        } catch (Exception e) {
            // VULNERABLE: Full exception details
            throw new RuntimeException("XML Error: ${e.class.name} - ${e.message}")
        }
    }

    // Test 13: Grails controller stack trace
    Map grailsErrorHandler(Exception e) {
        // VULNERABLE: Grails stack trace
        [
            error: e.message,
            controller: "UserController",
            action: "save",
            stackTrace: e.stackTrace
        ]
    }

    private Map parseData(byte[] data) { [:] }
    private boolean userExists(String email) { false }
    private Map findUser(String username) { null }
    private boolean verifyPassword(String password, String hash) { false }
}
