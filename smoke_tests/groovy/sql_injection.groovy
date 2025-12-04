// SQL Injection vulnerabilities in Groovy
package com.example.vulnerabilities

class SqlInjectionVulnerabilities {
    String getUserUnsafe(String userId) {
        // VULNERABLE: String interpolation in SQL
        String query = "SELECT * FROM users WHERE id = '${userId}'"
        return query
    }

    String loginUnsafe(String username, String password) {
        // VULNERABLE: SQL injection in login
        String sql = "SELECT * FROM users WHERE username='${username}' AND password='${password}'"
        return sql
    }

    String searchUnsafe(String term) {
        // VULNERABLE: SQL injection in search
        return "SELECT * FROM products WHERE name LIKE '%${term}%'"
    }

    String deleteUnsafe(String tableName, int id) {
        // VULNERABLE: Table name injection
        return "DELETE FROM ${tableName} WHERE id = ${id}"
    }

    void executeRaw(String query) {
        // VULNERABLE: Direct query execution
        println query
    }
}
