
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    db = sqlite3.connect('database.db')
    cursor = db.cursor()
    # Vulnerable to SQL Injection
    cursor.execute("SELECT * FROM users WHERE id = '" + user_id + "'")
    user = cursor.fetchone()
    return str(user)

if __name__ == '__main__':
    app.run()
