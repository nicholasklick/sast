
from flask import Flask, request

app = Flask(__name__)

@app.route('/calculate')
def calculate():
    expression = request.args.get('expr')
    # Vulnerable to code injection via eval
    result = eval(expression)
    return str(result)

if __name__ == '__main__':
    app.run()
