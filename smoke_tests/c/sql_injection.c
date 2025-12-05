// SQL Injection Test Cases

#include <stdio.h>
#include <string.h>
#include <sqlite3.h>

// Test 1: Direct string concatenation in SQL query
void get_user_by_username(sqlite3 *db, const char *username) {
    char query[256];
    // VULNERABLE: SQL injection via string concatenation
    sprintf(query, "SELECT * FROM users WHERE username = '%s'", username);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

// Test 2: Authentication bypass
int authenticate_user(sqlite3 *db, const char *user, const char *pass) {
    char query[512];
    // VULNERABLE: user or pass could contain ' OR '1'='1
    sprintf(query, "SELECT * FROM users WHERE username='%s' AND password='%s'", user, pass);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
    int result = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return result == SQLITE_ROW;
}

// Test 3: Format string SQL injection
void search_products(sqlite3 *db, const char *search_term) {
    char query[512];
    // VULNERABLE: Unsanitized search term
    snprintf(query, sizeof(query), "SELECT * FROM products WHERE name LIKE '%%%s%%'", search_term);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

// Test 4: Dynamic table/column name
void get_data_from_table(sqlite3 *db, const char *table_name, const char *column) {
    char query[256];
    // VULNERABLE: Table and column names from user input
    sprintf(query, "SELECT %s FROM %s", column, table_name);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

// Test 5: ORDER BY injection
void get_users_sorted(sqlite3 *db, const char *sort_by) {
    char query[256];
    // VULNERABLE: sort_by could inject malicious SQL
    sprintf(query, "SELECT * FROM users ORDER BY %s", sort_by);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        // Process results
    }
    sqlite3_finalize(stmt);
}
