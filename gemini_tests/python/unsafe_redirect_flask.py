
from flask import Flask, request, redirect

app = Flask(__name__)

@app.route('/redirect')
def do_redirect():
    url = request.args.get('url')
    # Vulnerable to Open Redirect
    return redirect(url)

if __name__ == '__main__':
    app.run()
