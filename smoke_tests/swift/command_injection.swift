// Command Injection vulnerabilities in Swift
import Foundation

class CommandInjectionVulnerabilities {
    func executeCommand(userInput: String) -> String {
        // VULNERABLE: Command injection via Process
        let task = Process()
        task.launchPath = "/bin/sh"
        task.arguments = ["-c", "ls \(userInput)"]
        let pipe = Pipe()
        task.standardOutput = pipe
        task.launch()
        return String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    }

    func runShellCommand(command: String) -> String {
        // VULNERABLE: Shell command execution
        let task = Process()
        task.launchPath = "/bin/bash"
        task.arguments = ["-c", command]
        let pipe = Pipe()
        task.standardOutput = pipe
        task.launch()
        return String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    }

    func pingHost(host: String) -> String {
        // VULNERABLE: Command injection in ping
        let task = Process()
        task.launchPath = "/sbin/ping"
        task.arguments = ["-c", "1", host]
        task.launch()
        return ""
    }

    func executeScript(scriptPath: String) {
        // VULNERABLE: Arbitrary script execution
        let task = Process()
        task.launchPath = "/bin/bash"
        task.arguments = [scriptPath]
        task.launch()
    }
}
