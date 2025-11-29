
package main

import (
	"io/ioutil"
	"net/http"
	"path/filepath"
)

func vulnerable(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	// Vulnerable to Path Traversal
	data, _ := ioutil.ReadFile(filepath.Join("/var/www/", filename))
	w.Write(data)
}
