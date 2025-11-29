
package main

import (
	"io/ioutil"
	"net/http"
)

func vulnerable(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	// Vulnerable to SSRF
	resp, _ := http.Get(url)
	body, _ := ioutil.ReadAll(resp.Body)
	w.Write(body)
}
