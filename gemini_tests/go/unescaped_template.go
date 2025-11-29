
package main

import (
	"html/template"
	"os"
)

func main() {
	// Unescaped template can lead to XSS
	t, _ := template.New("foo").Parse(`{{define "T"}}Hello, {{.}}!{{end}}`)
	s := "<script>alert('pwned')</script>"
	t.ExecuteTemplate(os.Stdout, "T", s)
}
