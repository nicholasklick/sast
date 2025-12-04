// SQL Injection vulnerabilities in Scala
import java.sql.{Connection, DriverManager}

class SqlInjectionVulnerabilities {
  var connection: Connection = _

  def getUserUnsafe(userId: String): String = {
    // VULNERABLE: String interpolation in SQL
    val query = s"SELECT * FROM users WHERE id = '$userId'"
    val stmt = connection.createStatement()
    val rs = stmt.executeQuery(query)
    if (rs.next()) rs.getString("name") else ""
  }

  def loginUnsafe(username: String, password: String): Boolean = {
    // VULNERABLE: SQL injection in login
    val sql = s"SELECT * FROM users WHERE username='$username' AND password='$password'"
    val stmt = connection.createStatement()
    stmt.executeQuery(sql).next()
  }

  def searchUnsafe(term: String): List[String] = {
    // VULNERABLE: SQL injection in search
    val query = s"SELECT * FROM products WHERE name LIKE '%$term%'"
    val stmt = connection.createStatement()
    stmt.executeQuery(query)
    List.empty
  }

  def deleteUnsafe(tableName: String, id: Int): Unit = {
    // VULNERABLE: Table name injection
    val sql = s"DELETE FROM $tableName WHERE id = $id"
    connection.createStatement().executeUpdate(sql)
  }

  def executeRaw(query: String): Unit = {
    // VULNERABLE: Direct query execution
    connection.createStatement().execute(query)
  }
}
