// Groovy Vulnerability Test Fixtures
package com.example.vulnerabilities

class GroovyVulnerabilities {
    String password = "GroovySecret789!"
    String apiKey = "sk_live_1234567890"

    String getQuery(String username) {
        return "SELECT * FROM users WHERE name = '" + username + "'"
    }

    String runCommand(String cmd) {
        return Runtime.getRuntime().exec(cmd).toString()
    }
}
