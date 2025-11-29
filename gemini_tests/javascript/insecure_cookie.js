
const express = require('express');
const session = require('express-session');
const app = express();

app.use(session({
  secret: 'keyboard cat',
  // Insecure cookie settings
  cookie: { secure: false, httpOnly: false }
}));

app.listen(3000);
