
package main

import (
	"fmt"
	"syscall"
)

func main() {
	// Direct syscalls can be risky and are platform-dependent
	pid, _, _ := syscall.Syscall(syscall.SYS_GETPID, 0, 0, 0)
	fmt.Println("PID:", pid)
}
