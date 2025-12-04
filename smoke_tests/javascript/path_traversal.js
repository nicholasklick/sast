
const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();

app.get('/file', (req, res) => {
  const filename = req.query.name;
  // Vulnerable to Path Traversal
  const filepath = path.join(__dirname, '/files/', filename);
  fs.readFile(filepath, (err, data) => {
    res.send(data);
  });
});

app.listen(3000);
