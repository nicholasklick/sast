
package main

import (
	"crypto/md5"
	"fmt"
)

func hashPassword(password string) {
	// Use of weak hashing algorithm MD5
	hasher := md5.New()
	hasher.Write([]byte(password))
	fmt.Printf("%x", hasher.Sum(nil))
}
