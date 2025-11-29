
const express = require('express');
const app = express();

app.use((req, res, next) => {
    // Missing security headers like X-XSS-Protection
    res.removeHeader('X-Powered-By');
    next();
});

app.listen(3000);
