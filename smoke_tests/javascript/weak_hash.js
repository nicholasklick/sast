
const crypto = require('crypto');

function hashPassword(password) {
    // Use of weak hashing algorithm MD5
    return crypto.createHash('md5').update(password).digest('hex');
}
