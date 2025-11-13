const express = require('express');
const app = express();
const db = require('./database');

// Real SQL injection vulnerability
app.get('/api/users/:id', (req, res) => {
    const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
    db.query(query, (err, results) => {
        res.json(results);
    });
});

// Real XSS vulnerability
app.get('/profile', (req, res) => {
    const username = req.query.name;
    res.send(`<h1>Welcome ${username}!</h1>`);
});
