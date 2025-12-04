package main

import (
	"fmt"
	"os/exec"
)

func main() {
	// Simulate user input
	scriptName := "nonexistent.sh; echo 'pwned'"

	// --- VULNERABLE CODE ---
	// The command is constructed with user input and passed to a shell.
	// exec.Command is often safe, but not when used this way with a shell.
	// CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
	cmd := exec.Command("/bin/sh", "-c", "sh "+scriptName)
	// -----------------------

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Error:", err)
	}
	fmt.Println("Output:", string(output))
}
