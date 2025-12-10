# SQL Injection via Collection Operations
# Tests that taint flows through list.append(), list.pop(), dict[k] = v

import sqlite3
from flask import Flask, request

app = Flask(__name__)

# Connect to in-memory database
db = sqlite3.connect(':memory:')
cursor = db.cursor()
cursor.execute("CREATE TABLE users (id TEXT, name TEXT)")

@app.route('/list_append')
def list_append_vuln():
    """Taint through list.append() and list access"""
    user_input = request.args.get('id')  # Source

    query_parts = []
    query_parts.append("SELECT * FROM users WHERE id = '")
    query_parts.append(user_input)  # Tainted append
    query_parts.append("'")

    query = "".join(query_parts)
    cursor.execute(query)  # SQL Injection - taint flows through list
    return "ok"

@app.route('/list_pop')
def list_pop_vuln():
    """Taint through list operations with pop()"""
    user_input = request.args.get('id')  # Source

    stack = []
    stack.append(user_input)  # Tainted value at index 0
    stack.append("safe")       # Safe value at index 1

    # Pop tainted value back out
    tainted = stack.pop(0)  # Gets tainted value
    query = f"SELECT * FROM users WHERE id = '{tainted}'"
    cursor.execute(query)  # SQL Injection - taint from popped value
    return "ok"

@app.route('/dict_access')
def dict_access_vuln():
    """Taint through dict[key] = value and dict[key] access"""
    user_input = request.args.get('name')  # Source

    params = {}
    params['user'] = user_input  # Tainted dict value
    params['safe'] = "constant"

    query = f"SELECT * FROM users WHERE name = '{params['user']}'"
    cursor.execute(query)  # SQL Injection - taint from dict access
    return "ok"

@app.route('/list_insert')
def list_insert_vuln():
    """Taint through list.insert()"""
    user_input = request.args.get('id')  # Source

    parts = ["safe1", "safe2"]
    parts.insert(1, user_input)  # Insert tainted at index 1

    query = f"SELECT * FROM users WHERE id = '{parts[1]}'"
    cursor.execute(query)  # SQL Injection - taint from inserted element
    return "ok"

# --- FALSE POSITIVE TESTS (should NOT flag) ---

@app.route('/safe_pop_safe_index')
def safe_pop_safe_index():
    """Pop from safe index - should NOT be flagged"""
    user_input = request.args.get('id')  # Source

    stack = []
    stack.append("safe_first")  # Index 0 - safe
    stack.append(user_input)    # Index 1 - tainted

    # Pop safe value
    safe_val = stack.pop(0)  # Gets safe value at index 0
    query = f"SELECT * FROM users WHERE id = '{safe_val}'"
    cursor.execute(query)  # Should NOT flag - popped safe value
    return "ok"

@app.route('/safe_dict_key')
def safe_dict_key():
    """Access safe dict key - should NOT be flagged"""
    user_input = request.args.get('name')  # Source

    params = {}
    params['tainted'] = user_input  # Tainted
    params['safe'] = "constant"     # Safe

    query = f"SELECT * FROM users WHERE name = '{params['safe']}'"
    cursor.execute(query)  # Should NOT flag - accessed safe key
    return "ok"

if __name__ == '__main__':
    app.run()
