<?php
// Command Injection vulnerabilities in PHP

class CommandInjectionVulnerabilities {
    public function execCommand($userInput) {
        // VULNERABLE: Command injection via exec
        exec("ls " . $userInput);
    }

    public function systemCommand($filename) {
        // VULNERABLE: Command injection via system
        system("cat " . $filename);
    }

    public function shellExecCommand($command) {
        // VULNERABLE: Shell execution
        return shell_exec($command);
    }

    public function passthuCommand($host) {
        // VULNERABLE: Command injection via passthru
        passthru("ping -c 1 " . $host);
    }

    public function backtickCommand($arg) {
        // VULNERABLE: Backtick operator
        return `ls $arg`;
    }

    public function procOpen($cmd) {
        // VULNERABLE: proc_open with user input
        $descriptorspec = array(
            0 => array("pipe", "r"),
            1 => array("pipe", "w"),
        );
        return proc_open($cmd, $descriptorspec, $pipes);
    }

    public function popenCommand($filename) {
        // VULNERABLE: popen with user input
        return popen("cat " . $filename, "r");
    }
}
