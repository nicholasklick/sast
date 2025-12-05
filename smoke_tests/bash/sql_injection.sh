#!/bin/bash
# SQL Injection vulnerabilities in Bash

# Test 1: MySQL query with string interpolation
vulnerable_mysql() {
    local user_input="$1"
    # VULNERABLE: SQL injection
    mysql -u root -e "SELECT * FROM users WHERE name = '$user_input'"
}

# Test 2: PostgreSQL with user input
vulnerable_psql() {
    local id="$1"
    # VULNERABLE: SQL injection
    psql -c "SELECT * FROM orders WHERE id = $id"
}

# Test 3: SQLite with user input
vulnerable_sqlite() {
    local search="$1"
    # VULNERABLE: SQL injection
    sqlite3 database.db "SELECT * FROM products WHERE name LIKE '%$search%'"
}

# Test 4: MySQL with variable in WHERE
vulnerable_where() {
    local column="$1"
    local value="$2"
    # VULNERABLE: SQL injection in column and value
    mysql -u app -e "SELECT * FROM data WHERE $column = '$value'"
}

# Test 5: Insert with user data
vulnerable_insert() {
    local name="$1"
    local email="$2"
    # VULNERABLE: SQL injection in INSERT
    mysql -u root -e "INSERT INTO users (name, email) VALUES ('$name', '$email')"
}

# Test 6: Update with user input
vulnerable_update() {
    local id="$1"
    local status="$2"
    # VULNERABLE: SQL injection in UPDATE
    mysql -u root -e "UPDATE orders SET status = '$status' WHERE id = $id"
}

# Test 7: Delete with user input
vulnerable_delete() {
    local table="$1"
    local condition="$2"
    # VULNERABLE: SQL injection in DELETE
    mysql -u root -e "DELETE FROM $table WHERE $condition"
}

# Test 8: ORDER BY injection
vulnerable_orderby() {
    local column="$1"
    local direction="$2"
    # VULNERABLE: ORDER BY injection
    mysql -u root -e "SELECT * FROM products ORDER BY $column $direction"
}

# Test 9: LIMIT injection
vulnerable_limit() {
    local offset="$1"
    local count="$2"
    # VULNERABLE: LIMIT injection
    mysql -u root -e "SELECT * FROM items LIMIT $offset, $count"
}

# Test 10: UNION-based injection
vulnerable_union() {
    local search="$1"
    # VULNERABLE: UNION injection
    mysql -u root -e "SELECT id, name FROM users WHERE name = '$search'"
}

# Test 11: Batch queries
vulnerable_batch() {
    local query="$1"
    # VULNERABLE: Multiple statement injection
    mysql -u root -e "$query"
}

# Test 12: Table name injection
vulnerable_table() {
    local table="$1"
    # VULNERABLE: Table name injection
    mysql -u root -e "SELECT * FROM $table"
}

# Test 13: MySQL defaults file with injection
vulnerable_defaults() {
    local password="$1"
    # VULNERABLE: Credential in temp file + potential injection
    echo -e "[client]\npassword=$password" > /tmp/my.cnf
    mysql --defaults-file=/tmp/my.cnf -e "SELECT 1"
}

# Test 14: pg_dump with user input
vulnerable_pgdump() {
    local database="$1"
    local table="$2"
    # VULNERABLE: Command injection via database/table names
    pg_dump -t "$table" "$database"
}

# Test 15: mysqldump with user input
vulnerable_mysqldump() {
    local database="$1"
    # VULNERABLE: Database name injection
    mysqldump "$database" > backup.sql
}

