
package main

import (
	"fmt"
	"html/template"
	"net/http"
)

func vulnerable(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// Vulnerable to XSS
	fmt.Fprintf(w, "<h1>Hello, %s</h1>", name)
}

func safe(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// Safe from XSS
	tmpl, _ := template.New("test").Parse("<h1>Hello, {{.}}</h1>")
	tmpl.Execute(w, name)
}
