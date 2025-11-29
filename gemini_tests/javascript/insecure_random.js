
const crypto = require('crypto');

// Use of insecure random bytes generation
const token = crypto.randomBytes(16).toString('hex');
