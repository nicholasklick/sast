
import requests
from flask import Flask, request

app = Flask(__name__)

@app.route('/proxy')
def proxy():
    url = request.args.get('url')
    # Vulnerable to SSRF
    response = requests.get(url)
    return response.text

if __name__ == '__main__':
    app.run()
