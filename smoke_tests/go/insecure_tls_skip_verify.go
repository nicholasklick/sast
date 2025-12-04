package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
)

func main() {
	// --- VULNERABLE CODE ---
	// Skipping TLS certificate verification. This makes the connection vulnerable
	// to Man-in-the-Middle (MITM) attacks.
	// CWE-295: Improper Certificate Validation
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	// -----------------------

	resp, err := client.Get("https://untrusted-site.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Println("Response status:", resp.Status)
}
