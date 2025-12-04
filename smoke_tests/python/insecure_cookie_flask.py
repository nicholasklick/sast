
from flask import Flask, make_response

app = Flask(__name__)

@app.route('/login')
def login():
    resp = make_response("Logged in")
    # Cookie without HttpOnly or Secure flags
    resp.set_cookie('session_id', 'some_secret_value')
    return resp

if __name__ == '__main__':
    app.run()
