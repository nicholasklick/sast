
const express = require('express');
const mysql = require('mysql');
const app = express();

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password',
  database: 'db'
});

app.get('/user', (req, res) => {
  const userId = req.query.id;
  // Vulnerable to SQL Injection
  const query = "SELECT * FROM users WHERE id = '" + userId + "'";
  connection.query(query, (err, results) => {
    res.send(results);
  });
});

app.listen(3000);
