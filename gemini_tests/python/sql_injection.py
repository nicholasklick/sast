import sqlite3

# Simulate user input
user_id = "1' OR '1'='1"
user_pass = "password"

# Connect to an in-memory database for the example
db = sqlite3.connect(':memory:')
cursor = db.cursor()
cursor.execute("CREATE TABLE users (id TEXT, password TEXT)")
cursor.execute("INSERT INTO users VALUES ('1', 'secret')")

# --- VULNERABLE CODE ---
# Building a query with string formatting is dangerous
query = f"SELECT * FROM users WHERE id = '{user_id}' AND password = '{user_pass}'"
cursor.execute(query) # CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
# -----------------------

for row in cursor.fetchall():
    print(f"Logged in as: {row}")

db.close()
