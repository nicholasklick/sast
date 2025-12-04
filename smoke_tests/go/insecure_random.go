
package main

import (
	"fmt"
	"math/rand"
)

func generateToken() {
	// Use of insecure random number generator
	token := rand.Int()
	fmt.Println(token)
}
