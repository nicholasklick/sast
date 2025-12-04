
package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

func vulnerable(w http.ResponseWriter, r *http.Request) {
	userId := r.URL.Query().Get("id")
	db, _ := sql.Open("mysql", "user:password@/dbname")
	// Vulnerable to SQL Injection
	query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", userId)
	db.Query(query)
}
