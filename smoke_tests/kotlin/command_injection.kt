// Command Injection vulnerabilities in Kotlin
import java.lang.Runtime

class CommandInjectionVulnerabilities {
    fun executeCommand(userInput: String): String {
        // VULNERABLE: Command injection via Runtime.exec
        val process = Runtime.getRuntime().exec("ls $userInput")
        return process.inputStream.bufferedReader().readText()
    }

    fun runShellCommand(command: String): String {
        // VULNERABLE: Shell command execution
        val process = ProcessBuilder("sh", "-c", command).start()
        return process.inputStream.bufferedReader().readText()
    }

    fun pingHost(host: String): String {
        // VULNERABLE: Command injection in ping
        val cmd = arrayOf("sh", "-c", "ping -c 1 $host")
        val process = Runtime.getRuntime().exec(cmd)
        return process.inputStream.bufferedReader().readText()
    }

    fun executeScript(scriptPath: String) {
        // VULNERABLE: Arbitrary script execution
        Runtime.getRuntime().exec("bash $scriptPath")
    }

    fun grepLogs(pattern: String): String {
        // VULNERABLE: Command injection in grep
        val process = ProcessBuilder("grep", pattern, "/var/log/app.log").start()
        return process.inputStream.bufferedReader().readText()
    }
}
