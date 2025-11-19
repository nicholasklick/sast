# Python vulnerabilities test file
import os
import pickle
import hashlib
import random
import subprocess
import sqlite3
from flask import Flask, request

class VulnerablePythonCode:
    # 1. SQL Injection - String formatting
    def get_user_by_id_unsafe(self, user_id):
        conn = sqlite3.connect('database.db')
        query = f"SELECT * FROM users WHERE id = '{user_id}'"
        return conn.execute(query).fetchone()

    # 2. Command Injection
    def execute_command(self, user_input):
        return os.system(f"ls -la {user_input}")

    # 3. Path Traversal
    def read_file(self, filename):
        with open(f"/var/data/{filename}", 'r') as f:
            return f.read()

    # 4. Hardcoded Credentials
    api_key = "sk-1234567890abcdef"
    password = "admin123"

    # 5. Weak Cryptography - MD5
    def hash_password(self, password):
        return hashlib.md5(password.encode()).hexdigest()

    # 6. Insecure Deserialization
    def load_data(self, data):
        return pickle.loads(data)

    # 7. eval() usage
    def evaluate_expression(self, expr):
        return eval(expr)

    # 8. Insecure Random
    def generate_token(self):
        return str(random.random())

    # 9. YAML Unsafe Load
    def parse_yaml(self, yaml_string):
        import yaml
        return yaml.load(yaml_string)

    # 10. XXE Vulnerability
    def parse_xml(self, xml_string):
        import xml.etree.ElementTree as ET
        return ET.fromstring(xml_string)

    # 11. SSRF - Unvalidated URL
    def fetch_url(self, url):
        import urllib.request
        return urllib.request.urlopen(url).read()

    # 12. assert for Security Checks
    def check_admin(self, user):
        assert user.is_admin, "Not admin"  # assert can be disabled with -O
        return True

    # 13. Shell Injection via subprocess
    def run_command(self, cmd):
        return subprocess.call(cmd, shell=True)

    # 14. Weak Crypto - DES
    def encrypt_des(self, data, key):
        from Crypto.Cipher import DES
        cipher = DES.new(key, DES.MODE_ECB)
        return cipher.encrypt(data)

    # 15. Flask Debug Mode
    app = Flask(__name__)
    app.config['DEBUG'] = True  # Should be False in production

    # 16. SQL Injection with % formatting
    def find_users(self, role):
        conn = sqlite3.connect('database.db')
        query = "SELECT * FROM users WHERE role = '%s'" % role
        return conn.execute(query).fetchall()

    # 17. Open Redirect
    @app.route('/redirect')
    def redirect_user():
        url = request.args.get('url')
        return redirect(url)  # No validation

    # 18. Code Injection via exec
    def execute_code(self, code):
        exec(code)

    # 19. Temp File Race Condition
    def create_temp_file(self):
        import tempfile
        filename = "/tmp/myfile.txt"
        with open(filename, 'w') as f:
            f.write("sensitive data")
        return filename

    # 20. NoSQL Injection
    def find_user(self, username):
        from pymongo import MongoClient
        client = MongoClient()
        db = client['mydb']
        return db.users.find_one({'username': username})
