// Log Injection vulnerabilities in JavaScript/Node.js
const winston = require('winston');
const pino = require('pino');
const bunyan = require('bunyan');
const fs = require('fs');

// Test 1: console.log with user input
function consoleLog(req, res) {
    const username = req.query.username;
    // VULNERABLE: Can inject newlines to forge log entries
    console.log(`[INFO] User ${username} logged in`);
}

// Test 2: winston logging with user input
const winstonLogger = winston.createLogger({
    transports: [new winston.transports.Console()]
});

function winstonLog(req, res) {
    const message = req.body.message;
    // VULNERABLE: User input in log message
    winstonLogger.info(`User action: ${message}`);
}

// Test 3: pino logging with user input
const pinoLogger = pino();

function pinoLog(req, res) {
    const data = req.body.data;
    // VULNERABLE: User input in structured log
    pinoLogger.info({ data }, 'Processing request');
}

// Test 4: bunyan logging
const bunyanLogger = bunyan.createLogger({ name: 'myapp' });

function bunyanLog(req, res) {
    const event = req.query.event;
    // VULNERABLE: Event from user input
    bunyanLogger.info(`Event occurred: ${event}`);
}

// Test 5: File-based logging
function fileLog(req, res) {
    const message = req.body.message;
    const timestamp = new Date().toISOString();
    // VULNERABLE: Message can contain CRLF
    fs.appendFileSync('/var/log/app.log', `[${timestamp}] ${message}\n`);
}

// Test 6: JSON log format breaking
function jsonLog(req, res) {
    const message = req.query.msg;
    // VULNERABLE: Can break JSON structure
    const logEntry = JSON.stringify({
        timestamp: Date.now(),
        message: message
    });
    fs.appendFileSync('/var/log/json.log', logEntry + '\n');
}

// Test 7: process.stdout.write
function stdoutLog(req, res) {
    const data = req.body.data;
    // VULNERABLE: Direct stdout write
    process.stdout.write(`Processing: ${data}\n`);
}

// Test 8: Error object logging
function errorLog(req, res) {
    try {
        throw new Error(req.query.error);
    } catch (e) {
        // VULNERABLE: Error message from user
        console.error(`Exception caught: ${e.message}`);
    }
}

// Test 9: Audit log manipulation
function auditLog(req, res) {
    const user = req.body.user;
    const action = req.body.action;
    const result = req.body.result;
    // VULNERABLE: Multiple fields can contain newlines
    const audit = `User: ${user}\nAction: ${action}\nResult: ${result}\n---`;
    fs.appendFileSync('/var/log/audit.log', audit + '\n');
}

// Test 10: Debug logging in production
function debugLog(req, res) {
    const debugData = req.body.debug;
    // VULNERABLE: Debug data in production
    console.debug(`Debug: ${debugData}`);
}

// Test 11: morgan with custom format
const morgan = require('morgan');
// VULNERABLE: Custom format with user-controlled data
// app.use(morgan(':method :url :status - :user-agent'));

// Test 12: Stream-based logging
function streamLog(req, res) {
    const input = req.body.input;
    const stream = fs.createWriteStream('/var/log/stream.log', { flags: 'a' });
    // VULNERABLE: User input to stream
    stream.write(`Input: ${input}\n`);
    stream.end();
}

module.exports = {
    consoleLog,
    winstonLog,
    pinoLog,
    bunyanLog,
    fileLog,
    jsonLog,
    stdoutLog,
    errorLog,
    auditLog,
    debugLog,
    streamLog
};
