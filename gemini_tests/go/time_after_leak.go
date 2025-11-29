
package main

import (
	"fmt"
	"time"
)

func main() {
	// Using time.After in a loop can lead to a memory leak
	for {
		select {
		case <-time.After(1 * time.Second):
			fmt.Println("tick")
		}
	}
}
