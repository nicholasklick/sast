// Sensitive Data Exposure vulnerabilities in JavaScript/Node.js
const fs = require('fs');

// Test 1: Exception details exposed
function showError(req, res) {
    try {
        throw new Error('Database connection failed');
    } catch (e) {
        // VULNERABLE: Stack trace exposed
        res.status(500).json({
            error: e.message,
            stack: e.stack
        });
    }
}

// Test 2: Debug info in response
function getData(req, res) {
    const data = loadData();
    // VULNERABLE: Debug information exposed
    res.json({
        data,
        debug: {
            server: process.env.HOSTNAME,
            nodeVersion: process.version,
            cwd: process.cwd()
        }
    });
}

// Test 3: Logging sensitive data
function processPayment(req, res) {
    const { cardNumber, cvv } = req.body;
    // VULNERABLE: Credit card data logged
    console.log(`Processing card: ${cardNumber}, CVV: ${cvv}`);
    doPayment(cardNumber, cvv);
    res.json({ success: true });
}

// Test 4: Sensitive data in URL
function showAccount(req, res) {
    const { ssn, accountNumber } = req.query;
    // VULNERABLE: SSN and account in URL (logged, cached)
    const user = getUserBySsn(ssn);
    res.json(user);
}

// Test 5: Caching sensitive responses
function getUserDetails(req, res) {
    // VULNERABLE: Sensitive data being cached
    res.set('Cache-Control', 'public, max-age=3600');
    res.json({
        userId: req.session.userId,
        email: getUserEmail(),
        ssn: getUserSsn()
    });
}

// Test 6: Unencrypted sensitive storage
function storeSsn(req, res) {
    const { ssn } = req.body;
    // VULNERABLE: SSN stored unencrypted
    fs.writeFileSync('/data/user.txt', ssn);
    res.json({ success: true });
}

// Test 7: API key in response
function getConfig(req, res) {
    // VULNERABLE: API keys exposed
    res.json({
        apiEndpoint: 'https://api.example.com',
        apiKey: 'sk-12345-secret-key',
        dbPassword: 'secret123'
    });
}

// Test 8: Missing security headers
function securePage(req, res) {
    // VULNERABLE: No security headers
    // Missing: X-Content-Type-Options, X-Frame-Options, CSP
    res.send('<html>Content</html>');
}

// Test 9: HTTP for sensitive data
function redirectToPayment(req, res) {
    // VULNERABLE: HTTP for payment page
    res.redirect('http://payment.example.com/checkout');
}

// Test 10: Environment variables exposed
function envInfo(req, res) {
    // VULNERABLE: Environment variables exposed
    res.json({
        env: process.env
    });
}

// Test 11: Source maps in production
// webpack.config.js with devtool: 'source-map' in production
// VULNERABLE: Source code exposed via source maps

// Test 12: Error handler with details
function errorHandler(err, req, res, next) {
    // VULNERABLE: Full error details in production
    res.status(500).json({
        message: err.message,
        stack: err.stack,
        code: err.code
    });
}

// Test 13: Verbose GraphQL errors
const graphqlConfig = {
    // VULNERABLE: Detailed errors in production
    formatError: (error) => ({
        message: error.message,
        locations: error.locations,
        path: error.path,
        stack: error.stack
    })
};

// Test 14: PII in logs
function logRequest(req, res, next) {
    // VULNERABLE: PII logged
    console.log(`Request from ${req.ip}: ${JSON.stringify(req.body)}`);
    next();
}

// Helper functions
function loadData() { return {}; }
function doPayment(card, cvv) {}
function getUserBySsn(ssn) { return {}; }
function getUserEmail() { return 'user@example.com'; }
function getUserSsn() { return '123-45-6789'; }

module.exports = {
    showError,
    getData,
    processPayment,
    showAccount,
    getUserDetails,
    storeSsn,
    getConfig,
    securePage,
    redirectToPayment,
    envInfo,
    errorHandler,
    graphqlConfig,
    logRequest
};
