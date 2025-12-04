// Command Injection vulnerabilities in C#
using System;
using System.Diagnostics;

public class CommandInjectionVulnerabilities
{
    public void ExecuteCommandUnsafe(string userInput)
    {
        // VULNERABLE: Command injection via Process.Start
        Process.Start("cmd.exe", "/c " + userInput);
    }

    public string RunPingUnsafe(string host)
    {
        // VULNERABLE: Command injection in ping
        ProcessStartInfo psi = new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = "/c ping " + host,
            RedirectStandardOutput = true
        };
        Process p = Process.Start(psi);
        return p.StandardOutput.ReadToEnd();
    }

    public void ExecuteScriptUnsafe(string scriptPath)
    {
        // VULNERABLE: Arbitrary script execution
        Process.Start("powershell.exe", "-ExecutionPolicy Bypass -File " + scriptPath);
    }

    public void ShellExecuteUnsafe(string command)
    {
        // VULNERABLE: Shell execution with user input
        ProcessStartInfo startInfo = new ProcessStartInfo
        {
            FileName = "/bin/bash",
            Arguments = $"-c \"{command}\"",
            UseShellExecute = false
        };
        Process.Start(startInfo);
    }
}
