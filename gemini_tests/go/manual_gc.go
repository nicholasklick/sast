
package main

import (
	"fmt"
	"runtime"
)

func main() {
	// Calling garbage collector manually can impact performance
	runtime.GC()
	fmt.Println("GC called")
}
