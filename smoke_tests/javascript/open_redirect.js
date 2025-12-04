
const express = require('express');
const app = express();

app.get('/redirect', (req, res) => {
    const url = req.query.url;
    // Vulnerable to Open Redirect
    res.redirect(url);
});

app.listen(3000);
