const express = require('express');
const app = express();
const bodyParser = require('body-parser');

// This is a mock MongoDB client for demonstration purposes.
const db = {
  users: {
    findOne: function(query, callback) {
      console.log('Database query:', JSON.stringify(query));
      // In a real app, this would query MongoDB.
      // Example: db.collection('users').findOne(query, callback);

      // If the query is {'username': 'admin', 'password': {'$ne': null}}, it might match.
      if (query.username === 'admin' && query.password && query.password.$ne) {
        callback(null, { username: 'admin', role: 'admin' });
      } else {
        callback(null, null);
      }
    }
  }
};

app.use(bodyParser.json());

// Simulate user input from a login form
// Attacker sends: {"username": "admin", "password": {"$ne": null}}
// This bypasses a simple password check.
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // --- VULNERABLE CODE ---
  // The user input is passed directly into the database query.
  // An attacker can inject MongoDB operators like `$ne` (not equal).
  db.users.findOne({
    username: username,
    password: password
  }, (err, user) => { // CWE-943: Improper Neutralization of Special Elements in Data Query Logic
    if (err) {
      return res.status(500).send('Error');
    }
    if (user) {
      res.send(`Welcome, ${user.username}!`);
    } else {
      res.status(401).send('Login failed');
    }
  });
  // -----------------------
});

// This is an Express app, not meant to be run directly in tests.
// It demonstrates the vulnerability.
console.log('This is an Express app demonstrating NoSQL injection.');