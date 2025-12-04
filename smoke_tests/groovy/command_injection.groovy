// Command Injection vulnerabilities in Groovy
package com.example.vulnerabilities

class CommandInjectionVulnerabilities {
    String executeCommand(String userInput) {
        // VULNERABLE: Command injection via execute()
        return "ls ${userInput}".execute().text
    }

    String catFile(String filename) {
        // VULNERABLE: Command injection via cat
        return "cat ${filename}".execute().text
    }

    String pingHost(String host) {
        // VULNERABLE: Command injection in ping
        return "ping -c 1 ${host}".execute().text
    }

    void runScript(String scriptPath) {
        // VULNERABLE: Arbitrary script execution
        "bash ${scriptPath}".execute()
    }

    String grepLogs(String pattern) {
        // VULNERABLE: Command injection in grep
        return "grep ${pattern} /var/log/app.log".execute().text
    }
}
