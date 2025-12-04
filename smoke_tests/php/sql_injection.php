<?php
// SQL Injection vulnerabilities in PHP

class SqlInjectionVulnerabilities {
    private $pdo;
    private $mysqli;

    public function getUserUnsafe($userId) {
        // VULNERABLE: String concatenation in SQL
        $query = "SELECT * FROM users WHERE id = '" . $userId . "'";
        return $this->pdo->query($query);
    }

    public function loginUnsafe($username, $password) {
        // VULNERABLE: SQL injection in login
        $sql = "SELECT * FROM users WHERE username='$username' AND password='$password'";
        return mysqli_query($this->mysqli, $sql);
    }

    public function searchUnsafe($term) {
        // VULNERABLE: SQL injection in search
        $query = "SELECT * FROM products WHERE name LIKE '%$term%'";
        return $this->pdo->query($query);
    }

    public function deleteUnsafe($tableName, $id) {
        // VULNERABLE: Table name injection
        $sql = "DELETE FROM $tableName WHERE id = $id";
        $this->pdo->exec($sql);
    }

    public function executeRaw($query) {
        // VULNERABLE: Direct query execution
        mysql_query($query);
    }

    public function unsafePrepare($column, $value) {
        // VULNERABLE: Column name from user input
        $sql = "SELECT * FROM users WHERE $column = ?";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$value]);
    }
}
