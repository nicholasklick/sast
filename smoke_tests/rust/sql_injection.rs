// SQL Injection vulnerability in Rust
use rusqlite::Connection;

fn get_user_unsafe(conn: &Connection, user_id: &str) -> Result<String, rusqlite::Error> {
    // VULNERABLE: String concatenation in SQL query
    let query = format!("SELECT name FROM users WHERE id = '{}'", user_id);
    let mut stmt = conn.prepare(&query)?;
    let name: String = stmt.query_row([], |row| row.get(0))?;
    Ok(name)
}

fn search_users_unsafe(conn: &Connection, search_term: &str) -> Result<Vec<String>, rusqlite::Error> {
    // VULNERABLE: Direct string interpolation
    let sql = format!("SELECT * FROM users WHERE name LIKE '%{}%'", search_term);
    let mut stmt = conn.prepare(&sql)?;
    let names = stmt.query_map([], |row| row.get(0))?;
    names.collect()
}
