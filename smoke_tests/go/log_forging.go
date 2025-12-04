
package main

import (
	"fmt"
	"log"
)

func vulnerable(userInput string) {
	// Log forging vulnerability
	log.Printf("User input: %s", userInput)
}
