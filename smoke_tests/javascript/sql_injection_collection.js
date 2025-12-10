// SQL Injection via Collection Operations
// Tests that taint flows through arr.push(), arr.pop(), obj[k] = v

const express = require('express');
const mysql = require('mysql');

const app = express();
const db = mysql.createConnection({ host: 'localhost', database: 'test' });

// --- VULNERABLE: Array push() ---
app.get('/array_push', (req, res) => {
    const userId = req.query.id;  // Source

    const queryParts = [];
    queryParts.push("SELECT * FROM users WHERE id = '");
    queryParts.push(userId);  // Tainted push
    queryParts.push("'");

    const query = queryParts.join('');
    db.query(query);  // SQL Injection - taint flows through array
    res.send('ok');
});

// --- VULNERABLE: Array pop() ---
app.get('/array_pop', (req, res) => {
    const userId = req.query.id;  // Source

    const stack = [];
    stack.push(userId);   // Tainted at index 0
    stack.push('safe');   // Safe at index 1

    // Pop from end gets safe value, shift from front gets tainted
    const tainted = stack.shift();  // Gets tainted value
    const query = `SELECT * FROM users WHERE id = '${tainted}'`;
    db.query(query);  // SQL Injection - taint from shifted value
    res.send('ok');
});

// --- VULNERABLE: Object property assignment ---
app.get('/object_property', (req, res) => {
    const userName = req.query.name;  // Source

    const params = {};
    params['user'] = userName;  // Tainted object property
    params['safe'] = 'constant';

    const query = `SELECT * FROM users WHERE name = '${params['user']}'`;
    db.query(query);  // SQL Injection - taint from object property
    res.send('ok');
});

// --- VULNERABLE: Array unshift() ---
app.get('/array_unshift', (req, res) => {
    const userId = req.query.id;  // Source

    const parts = ['safe1', 'safe2'];
    parts.unshift(userId);  // Insert tainted at front (index 0)

    const query = `SELECT * FROM users WHERE id = '${parts[0]}'`;
    db.query(query);  // SQL Injection - taint from unshifted element
    res.send('ok');
});

// --- VULNERABLE: Array splice insert ---
app.get('/array_splice_insert', (req, res) => {
    const userId = req.query.id;  // Source

    const parts = ['safe1', 'safe2'];
    parts.splice(1, 0, userId);  // Insert tainted at index 1

    const query = `SELECT * FROM users WHERE id = '${parts[1]}'`;
    db.query(query);  // SQL Injection - taint from spliced element
    res.send('ok');
});

// --- FALSE POSITIVE TESTS (should NOT flag) ---

app.get('/safe_shift_safe_index', (req, res) => {
    const userId = req.query.id;  // Source

    const stack = [];
    stack.push('safe_first');  // Index 0 - safe
    stack.push(userId);        // Index 1 - tainted

    // Shift gets safe value from front
    const safeVal = stack.pop();  // Gets value from end (tainted in this case)
    // Actually we want to pop safe value
    stack.length = 0;
    stack.push('safe');
    stack.push(userId);
    const realSafe = stack.shift();  // Gets 'safe' from front

    const query = `SELECT * FROM users WHERE id = '${realSafe}'`;
    db.query(query);  // Should NOT flag - shifted safe value
    res.send('ok');
});

app.get('/safe_object_key', (req, res) => {
    const userName = req.query.name;  // Source

    const params = {};
    params['tainted'] = userName;  // Tainted
    params['safe'] = 'constant';   // Safe

    const query = `SELECT * FROM users WHERE name = '${params['safe']}'`;
    db.query(query);  // Should NOT flag - accessed safe key
    res.send('ok');
});

app.listen(3000);
