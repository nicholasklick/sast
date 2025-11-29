
package main

import (
	"crypto/tls"
	"net/http"
)

func main() {
	// Insecure TLS configuration
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	http.Get("https://example.com")
}
