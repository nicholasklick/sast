// SQL Injection vulnerabilities in C#
using System;
using System.Data.SqlClient;

public class SqlInjectionVulnerabilities
{
    private SqlConnection connection;

    public void GetUserUnsafe(string userId)
    {
        // VULNERABLE: String concatenation in SQL
        string query = "SELECT * FROM Users WHERE Id = '" + userId + "'";
        SqlCommand cmd = new SqlCommand(query, connection);
        cmd.ExecuteReader();
    }

    public void LoginUnsafe(string username, string password)
    {
        // VULNERABLE: SQL injection in login
        string sql = $"SELECT * FROM Users WHERE Username='{username}' AND Password='{password}'";
        SqlCommand cmd = new SqlCommand(sql, connection);
        cmd.ExecuteNonQuery();
    }

    public void SearchUnsafe(string searchTerm)
    {
        // VULNERABLE: SQL injection in search
        string query = "SELECT * FROM Products WHERE Name LIKE '%" + searchTerm + "%'";
        SqlCommand cmd = new SqlCommand(query, connection);
        cmd.ExecuteReader();
    }

    public void DeleteUnsafe(string tableName, int id)
    {
        // VULNERABLE: Table name injection
        string sql = $"DELETE FROM {tableName} WHERE Id = {id}";
        SqlCommand cmd = new SqlCommand(sql, connection);
        cmd.ExecuteNonQuery();
    }

    public void ExecuteStoredProcUnsafe(string procName, string param)
    {
        // VULNERABLE: Dynamic stored procedure name
        string sql = $"EXEC {procName} '{param}'";
        SqlCommand cmd = new SqlCommand(sql, connection);
        cmd.ExecuteNonQuery();
    }
}
