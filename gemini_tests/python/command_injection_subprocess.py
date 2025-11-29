
import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route('/dns_lookup')
def dns_lookup():
    domain = request.args.get('domain')
    # Vulnerable to Command Injection
    subprocess.call('nslookup ' + domain, shell=True)
    return "Lookup complete"

if __name__ == '__main__':
    app.run()
