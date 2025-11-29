
package main

import (
	"net/http"
	"net/http/cgi"
)

func main() {
	// Use of CGI can be insecure if not configured properly
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handler := new(cgi.Handler)
		handler.Path = "/usr/local/bin/php-cgi"
		handler.ServeHTTP(w, r)
	})
	http.ListenAndServe(":8080", nil)
}
