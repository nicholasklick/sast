package main

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
)

// Vulnerable XML parsing example
func processXML(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	// --- VULNERABLE CODE ---
	// By default, Go's xml.Decoder does not process DTDs, making it safe from XXE.
	// To demonstrate the vulnerability, one would need to use a different, vulnerable parser
	// or a CGO binding to a C library like libxml2 without proper configuration.
	// For the sake of having a file, we will show a conceptual example.
	// A vulnerable parser would expand the entity.
	// CWE-611: Improper Restriction of XML External Entity Reference
	var data struct {
		Content string `xml:"content"`
	}
	// In a vulnerable scenario, the below line would trigger the XXE
	xml.Unmarshal(body, &data)
	// -----------------------

	fmt.Fprintf(w, "Parsed content: %s", data.Content)
}

func main() {
	http.HandleFunc("/xml", processXML)
	// Test with: curl -X POST -d '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data><content>&xxe;</content></data>' http://localhost:8080/xml
	fmt.Println("This is a conceptual example of XXE in Go.")
}
