
const express = require('express');
const app = express();

app.get('/eval', (req, res) => {
    const code = req.query.code;
    // Use of eval is dangerous
    eval(code);
    res.send('Eval executed');
});

app.listen(3000);
