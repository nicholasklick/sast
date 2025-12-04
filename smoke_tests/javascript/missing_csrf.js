
const express = require('express');
const app = express();

// Missing CSRF protection
app.post('/update-profile', (req, res) => {
    // ...
});

app.listen(3000);
