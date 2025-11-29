
const express = require('express');
const app = express();

// Allowing all origins is a security risk
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    next();
});

app.listen(3000);
