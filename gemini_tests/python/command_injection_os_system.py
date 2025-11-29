
import os
from flask import Flask, request

app = Flask(__name__)

@app.route('/list_files')
def list_files():
    directory = request.args.get('dir')
    # Vulnerable to Command Injection
    os.system('ls ' + directory)
    return "Command executed"

if __name__ == '__main__':
    app.run()
