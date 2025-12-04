// SQL Injection vulnerabilities in C++
#include <iostream>
#include <string>
#include <mysql/mysql.h>

class Database {
    MYSQL* conn;

public:
    std::string get_user(const std::string& user_id) {
        // VULNERABLE: SQL injection via string concatenation
        std::string query = "SELECT * FROM users WHERE id = '" + user_id + "'";
        mysql_query(conn, query.c_str());
        return "";
    }

    bool login(const std::string& username, const std::string& password) {
        // VULNERABLE: SQL injection in login
        std::string sql = "SELECT * FROM users WHERE username='" + username +
                         "' AND password='" + password + "'";
        mysql_query(conn, sql.c_str());
        return true;
    }

    void search(const std::string& term) {
        // VULNERABLE: SQL injection in search
        char query[1024];
        sprintf(query, "SELECT * FROM products WHERE name LIKE '%%%s%%'", term.c_str());
        mysql_query(conn, query);
    }

    void delete_record(int id, const std::string& table) {
        // VULNERABLE: Table name injection
        std::string sql = "DELETE FROM " + table + " WHERE id = " + std::to_string(id);
        mysql_query(conn, sql.c_str());
    }
};
