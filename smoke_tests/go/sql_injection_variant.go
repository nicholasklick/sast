package main

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	db, _ := sql.Open("sqlite3", ":memory:")
	db.Exec("CREATE TABLE items (id INT, name TEXT)")
	db.Exec("INSERT INTO items VALUES (1, 'gadget')")

	// Simulate user input for sorting
	ssortByColumn := "name; --" // Malicious input

	// --- VULNERABLE CODE ---
	// User input is used directly in the ORDER BY clause, which is not parameterizable.
	// This can be exploited, though the impact is often less severe than in a WHERE clause.
	// CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
	query := fmt.Sprintf("SELECT * FROM items ORDER BY %s", sortByColumn)
	rows, err := db.Query(query)
	// -----------------------

	if err != nil {
		fmt.Println("Error:", err)
	} else {
		defer rows.Close()
		for rows.Next() {
			var id int
			var name string
			rows.Scan(&id, &name)
			fmt.Printf("Item: %d, %s\n", id, name)
		}
	}
}
