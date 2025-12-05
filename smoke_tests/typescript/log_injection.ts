// Log Injection Test Cases

// Test 1: Direct user input in log
function logUserAction(username: string, action: string): void {
    // VULNERABLE: username could contain newlines to inject fake log entries
    console.log(`User ${username} performed action: ${action}`);
}

// Test 2: Logging user input without sanitization
function logLoginAttempt(email: string, ipAddress: string, success: boolean): void {
    // VULNERABLE: email could be "admin\nSUCCESS: User admin logged in"
    console.log(`Login attempt - Email: ${email}, IP: ${ipAddress}, Success: ${success}`);
}

// Test 3: Error logging with user data
function logError(userId: string, errorMessage: string): void {
    // VULNERABLE: errorMessage could contain ANSI codes or newlines
    console.error(`[ERROR] User ${userId}: ${errorMessage}`);
}

// Test 4: Structured logging with user input
function logEvent(eventType: string, userAgent: string, details: any): void {
    // VULNERABLE: userAgent could inject malicious log entries
    const logEntry = {
        timestamp: new Date().toISOString(),
        type: eventType,
        userAgent: userAgent,
        details: details
    };
    console.log(JSON.stringify(logEntry));
}

// Test 5: File logging with user input
function writeToLogFile(fs: any, username: string, message: string): void {
    const timestamp = new Date().toISOString();
    // VULNERABLE: Both username and message could contain injection attacks
    const logLine = `${timestamp} - ${username}: ${message}\n`;
    fs.appendFileSync('/var/log/app.log', logLine);
}
