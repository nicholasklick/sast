import os
from flask import Flask, request

app = Flask(__name__)

@app.route('/get-file')
def get_file():
    # Simulate user input for a filename
    filename = request.args.get('filename') # e.g., "../../../../../etc/passwd"

    # --- VULNERABLE CODE ---
    # The filename is not sanitized before being used in a file path
    # This allows an attacker to access files outside the intended directory
    base_path = "/var/www/uploads"
    file_path = os.path.join(base_path, filename) # CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

    try:
        with open(file_path, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return "File not found", 404
    except Exception as e:
        return str(e), 500
# -----------------------

if __name__ == '__main__':
    print("This is a Flask app demonstrating Path Traversal. Not meant to be run directly in tests.")
