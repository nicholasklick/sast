
const cipher = crypto.createCipher('des', 'a_secret');
// Use of insecure DES cipher
let encrypted = cipher.update('some clear text data', 'utf8', 'hex');
encrypted += cipher.final('hex');
