
package main

import (
	"crypto/des"
)

func main() {
	// Use of insecure DES cipher
	_, err := des.NewCipher([]byte("passwrd"))
	if err != nil {
		panic(err)
	}
}
