
package main

import (
	"fmt"
	"os"
)

func main() {
	// Deferring os.Exit can lead to unexpected behavior
	defer os.Exit(0)
	fmt.Println("this will be printed")
}
