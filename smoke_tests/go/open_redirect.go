
package main

import (
	"net/http"
)

func vulnerable(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	// Vulnerable to Open Redirect
	http.Redirect(w, r, url, http.StatusFound)
}
