// Authentication vulnerabilities in JavaScript/Node.js
const crypto = require('crypto');
const bcrypt = require('bcrypt');

// Test 1: Plaintext password storage
async function registerPlaintext(req, res, db) {
    const { username, password } = req.body;
    // VULNERABLE: Storing plaintext password
    await db.query('INSERT INTO users (username, password) VALUES ($1, $2)',
        [username, password]);
    res.json({ success: true });
}

// Test 2: MD5 password hashing
function registerMd5(req, res, db) {
    const { username, password } = req.body;
    // VULNERABLE: MD5 is too weak
    const hash = crypto.createHash('md5').update(password).digest('hex');
    db.query('INSERT INTO users (username, password_hash) VALUES ($1, $2)',
        [username, hash]);
    res.json({ success: true });
}

// Test 3: SHA1 without salt
function registerSha1(req, res, db) {
    const { username, password } = req.body;
    // VULNERABLE: Unsalted SHA1
    const hash = crypto.createHash('sha1').update(password).digest('hex');
    db.query('INSERT INTO users (username, password_hash) VALUES ($1, $2)',
        [username, hash]);
    res.json({ success: true });
}

// Test 4: Hardcoded credentials
function adminLogin(req, res) {
    const { username, password } = req.body;
    // VULNERABLE: Hardcoded credentials
    if (username === 'admin' && password === 'admin123') {
        req.session.admin = true;
        res.json({ success: true });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
}

// Test 5: Timing attack in comparison
function loginTiming(req, res, db) {
    const { username, password } = req.body;
    const user = db.query('SELECT * FROM users WHERE username = $1', [username]);
    // VULNERABLE: String comparison leaks timing
    if (user && user.password_hash === crypto.createHash('sha256').update(password).digest('hex')) {
        req.session.userId = user.id;
        res.json({ success: true });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
}

// Test 6: No account lockout
async function loginNoLockout(req, res, db) {
    const { username, password } = req.body;
    // VULNERABLE: No failed attempt tracking
    const user = await db.query('SELECT * FROM users WHERE username = $1', [username]);
    if (user && await bcrypt.compare(password, user.password_hash)) {
        req.session.userId = user.id;
        res.json({ success: true });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
}

// Test 7: Password in URL (GET request)
function loginGet(req, res) {
    const { username, password } = req.query;
    // VULNERABLE: GET request with credentials
    authenticateUser(username, password, res);
}

// Test 8: Password logged
function loginWithLogging(req, res) {
    const { username, password } = req.body;
    // VULNERABLE: Password in logs
    console.log(`Login attempt: ${username}/${password}`);
    authenticateUser(username, password, res);
}

// Test 9: Weak session configuration
function createSession(req, res) {
    // VULNERABLE: Insecure cookie settings
    res.cookie('sessionId', generateSessionId(), {
        httpOnly: false,  // XSS vulnerable
        secure: false     // Sent over HTTP
    });
    res.json({ success: true });
}

// Test 10: Insufficient password requirements
function setPassword(req, res) {
    const { password } = req.body;
    // VULNERABLE: No complexity check
    if (password.length >= 4) {  // Too short
        updatePassword(password);
        res.json({ success: true });
    } else {
        res.status(400).json({ error: 'Password too short' });
    }
}

// Test 11: JWT with weak secret
const jwt = require('jsonwebtoken');

function generateToken(user) {
    // VULNERABLE: Weak secret
    return jwt.sign({ userId: user.id }, 'secret', { expiresIn: '1h' });
}

// Test 12: JWT without algorithm verification
function verifyToken(token) {
    // VULNERABLE: Algorithm none attack possible
    return jwt.decode(token);  // Should use jwt.verify with algorithm specified
}

// Test 13: Session fixation
function loginNoRegenerate(req, res) {
    // VULNERABLE: Session not regenerated after login
    req.session.userId = getUserId(req.body.username);
    res.json({ success: true });
}

// Helper functions
function authenticateUser(username, password, res) {}
function generateSessionId() { return crypto.randomBytes(16).toString('hex'); }
function updatePassword(password) {}
function getUserId(username) { return 1; }

module.exports = {
    registerPlaintext,
    registerMd5,
    registerSha1,
    adminLogin,
    loginTiming,
    loginNoLockout,
    loginGet,
    loginWithLogging,
    createSession,
    setPassword,
    generateToken,
    verifyToken,
    loginNoRegenerate
};
