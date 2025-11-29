package main

import "fmt"

// --- VULNERABLE CODE ---
// Another example of hardcoded credentials.
const (
	dbUser = "root"
	dbPass = "s3cr3tP@ssw0rd" // CWE-798: Use of Hard-coded Credentials
)
// -----------------------

func connectToDatabase() {
	connectionString := fmt.Sprintf("user=%s password=%s dbname=prod", dbUser, dbPass)
	fmt.Println("Connecting with:", connectionString)
}

func main() {
	connectToDatabase()
}
