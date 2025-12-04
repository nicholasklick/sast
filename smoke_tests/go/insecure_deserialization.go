package main

import (
	"bytes"
	"encoding/gob"
	"fmt"
)

type User struct {
	Username string
	IsAdmin  bool
}

// --- VULNERABLE CODE ---
// Deserializing data from an untrusted source. An attacker could manipulate
// the serialized data to create an admin user.
// CWE-502: Deserialization of Untrusted Data
func deserializeUser(data []byte) (*User, error) {
	var user User
	decoder := gob.NewDecoder(bytes.NewReader(data))
	err := decoder.Decode(&user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}
// -----------------------

func main() {
	// Attacker creates a payload for an admin user
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	adminUser := User{Username: "attacker", IsAdmin: true}
	encoder.Encode(adminUser)
	maliciousData := buf.Bytes()

	// The application deserializes it
	user, err := deserializeUser(maliciousData)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Deserialized user: %+v\n", user)
	if user.IsAdmin {
		fmt.Println("User is an admin! Potential privilege escalation.")
	}
}

