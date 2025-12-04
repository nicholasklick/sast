// SQL Injection vulnerabilities in Kotlin
import java.sql.Connection
import java.sql.DriverManager

class SqlInjectionVulnerabilities {
    private lateinit var connection: Connection

    fun getUserUnsafe(userId: String): String {
        // VULNERABLE: String interpolation in SQL
        val query = "SELECT * FROM users WHERE id = '$userId'"
        val stmt = connection.createStatement()
        val rs = stmt.executeQuery(query)
        return if (rs.next()) rs.getString("name") else ""
    }

    fun loginUnsafe(username: String, password: String): Boolean {
        // VULNERABLE: SQL injection in login
        val sql = "SELECT * FROM users WHERE username='$username' AND password='$password'"
        val stmt = connection.createStatement()
        return stmt.executeQuery(sql).next()
    }

    fun searchUnsafe(term: String): List<String> {
        // VULNERABLE: SQL injection in search
        val query = "SELECT * FROM products WHERE name LIKE '%$term%'"
        val stmt = connection.createStatement()
        val rs = stmt.executeQuery(query)
        return listOf()
    }

    fun deleteUnsafe(tableName: String, id: Int) {
        // VULNERABLE: Table name injection
        val sql = "DELETE FROM $tableName WHERE id = $id"
        connection.createStatement().executeUpdate(sql)
    }

    fun executeRawQuery(query: String) {
        // VULNERABLE: Direct query execution
        connection.createStatement().execute(query)
    }
}
