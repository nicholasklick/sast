
from flask import Flask

app = Flask(__name__)

# Running Flask in debug mode in a production environment is a security risk
app.run(debug=True)
