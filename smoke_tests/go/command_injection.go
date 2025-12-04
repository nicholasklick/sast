
package main

import (
	"net/http"
	"os/exec"
)

func vulnerable(w http.ResponseWriter, r *http.Request) {
	cmdStr := r.URL.Query().Get("cmd")
	// Vulnerable to Command Injection
	cmd := exec.Command(cmdStr)
	cmd.Run()
}
