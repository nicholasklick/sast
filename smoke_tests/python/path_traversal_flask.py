
from flask import Flask, request, send_from_directory

app = Flask(__name__)
UPLOAD_FOLDER = '/uploads'

@app.route('/uploads/<path:filename>')
def download_file(filename):
    # Vulnerable to Path Traversal if not properly configured
    # send_from_directory can be safe, but misconfiguration is common
    return send_from_directory(UPLOAD_FOLDER, filename)

if __name__ == '__main__':
    app.run()
