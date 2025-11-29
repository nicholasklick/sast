# Example of vulnerable code with SQL injection
import sqlite3

def get_user(user_id):
    # VULNERABLE: User input directly in query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(query)  # This will be flagged by Gittera
    return cursor.fetchone()

def get_user_safe(user_id):
    # SAFE: Using parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(query, (user_id,))
    return cursor.fetchone()
