
package main

import (
	"io/ioutil"
)

func insecureTempFile() {
	// Insecure temporary file creation
	ioutil.WriteFile("/tmp/demo.txt", []byte("hello"), 0644)
}
