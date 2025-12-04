// Command Injection vulnerabilities in TypeScript
import { exec, spawn, execSync } from 'child_process';

class CommandInjectionVulnerabilities {
    executeCommand(userInput: string): void {
        // VULNERABLE: Command injection via exec
        exec(`ls ${userInput}`, (error, stdout, stderr) => {
            console.log(stdout);
        });
    }

    execSyncInjection(filename: string): string {
        // VULNERABLE: Command injection via execSync
        return execSync(`cat ${filename}`).toString();
    }

    spawnInjection(command: string): void {
        // VULNERABLE: Shell spawn with user input
        spawn('sh', ['-c', command]);
    }

    pingHost(host: string): void {
        // VULNERABLE: Command injection in ping
        exec(`ping -c 1 ${host}`);
    }

    executeScript(scriptPath: string): void {
        // VULNERABLE: Arbitrary script execution
        exec(`bash ${scriptPath}`);
    }

    grepLogs(pattern: string): void {
        // VULNERABLE: Command injection in grep
        exec(`grep "${pattern}" /var/log/app.log`);
    }

    evalInjection(code: string): any {
        // VULNERABLE: eval with user input
        return eval(code);
    }
}

export { CommandInjectionVulnerabilities };
