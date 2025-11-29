
import yaml
from flask import Flask, request

app = Flask(__name__)

@app.route('/load_config')
def load_config():
    config_data = request.files['config'].read()
    # Vulnerable to Insecure Deserialization with yaml.load
    config = yaml.load(config_data)
    return f"Config loaded: {config}"

if __name__ == '__main__':
    app.run()
