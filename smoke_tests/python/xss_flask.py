
from flask import Flask, request, make_response

app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Vulnerable to Reflected XSS
    response = make_response(f"<h1>Search results for: {query}</h1>")
    return response

if __name__ == '__main__':
    app.run()
