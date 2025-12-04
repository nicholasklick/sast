
import os
from flask import Flask, request

app = Flask(__name__)
BASE_DIR = '/var/www/html'

@app.route('/get_file')
def get_file():
    filename = request.args.get('filename')
    # Vulnerable to Path Traversal
    with open(os.path.join(BASE_DIR, filename), 'r') as f:
        return f.read()

if __name__ == '__main__':
    app.run()
