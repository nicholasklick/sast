
from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db = SQLAlchemy(app)

@app.route('/products')
def get_products():
    category = request.args.get('category')
    # Vulnerable to SQL Injection
    products = db.session.execute(text(f"SELECT * FROM products WHERE category = '{category}'")).fetchall()
    return str(products)

if __name__ == '__main__':
    app.run()
