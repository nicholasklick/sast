// Real SQL injection
const query = "SELECT * FROM users WHERE id = " + userId;
db.execute(query);

// Real command injection  
exec('rm -rf ' + userInput);

// Real XSS
element.innerHTML = userInput;

// Real hardcoded password
const password = "admin123";

// Real weak crypto
const hash = crypto.createHash('md5');
const cipher = crypto.createCipher('des', 'key');
