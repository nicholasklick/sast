// Clean Groovy code with no vulnerabilities
package com.example.safe

class SafeGroovyCode {
    String apiKey = System.getenv("API_KEY")

    String validateInput(String input) {
        return input.replaceAll("[^a-zA-Z0-9]", "")
    }

    String getConfig() {
        return System.getProperty("config.path")
    }
}
