// SQL Injection vulnerabilities in Swift
import Foundation
import SQLite3

class SqlInjectionVulnerabilities {
    var db: OpaquePointer?

    func getUserUnsafe(userId: String) -> String {
        // VULNERABLE: String interpolation in SQL
        let query = "SELECT * FROM users WHERE id = '\(userId)'"
        var stmt: OpaquePointer?
        sqlite3_prepare_v2(db, query, -1, &stmt, nil)
        return ""
    }

    func loginUnsafe(username: String, password: String) -> Bool {
        // VULNERABLE: SQL injection in login
        let sql = "SELECT * FROM users WHERE username='\(username)' AND password='\(password)'"
        var stmt: OpaquePointer?
        sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        return sqlite3_step(stmt) == SQLITE_ROW
    }

    func searchUnsafe(term: String) -> [String] {
        // VULNERABLE: SQL injection in search
        let query = "SELECT * FROM products WHERE name LIKE '%\(term)%'"
        var stmt: OpaquePointer?
        sqlite3_prepare_v2(db, query, -1, &stmt, nil)
        return []
    }

    func deleteUnsafe(tableName: String, id: Int) {
        // VULNERABLE: Table name injection
        let sql = "DELETE FROM \(tableName) WHERE id = \(id)"
        sqlite3_exec(db, sql, nil, nil, nil)
    }

    func executeRaw(query: String) {
        // VULNERABLE: Direct query execution
        sqlite3_exec(db, query, nil, nil, nil)
    }
}
