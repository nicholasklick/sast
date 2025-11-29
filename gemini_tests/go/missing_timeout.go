
package main

import (
	"net/http"
)

func main() {
	// Running an HTTP server without timeouts can lead to DoS
	http.ListenAndServe(":8080", nil)
}
