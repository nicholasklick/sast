
const express = require('express');
const app = express();

app.get('/search', (req, res) => {
  const query = req.query.q;
  // Vulnerable to reflected XSS
  res.send('<h1>Search results for: ' + query + '</h1>');
});

app.listen(3000);
