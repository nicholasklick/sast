
import pickle
import base64
from flask import Flask, request

app = Flask(__name__)

@app.route('/load_session')
def load_session():
    session_data = request.cookies.get('session')
    if session_data:
        # Vulnerable to Insecure Deserialization
        user_data = pickle.loads(base64.b64decode(session_data))
        return f"Welcome back, {user_data['username']}"
    return "No session found."

if __name__ == '__main__':
    app.run()
