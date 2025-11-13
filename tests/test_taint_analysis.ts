// Test file for taint analysis

// Example 1: Simple SQL injection
function vulnerableQuery() {
    const userInput = getUserInput();  // SOURCE
    const query = "SELECT * FROM users WHERE id = " + userInput;
    database.execute(query);  // SINK - Should detect SQL injection
}

// Example 2: Taint propagation through assignment
function propagatedTaint() {
    const input = request.body.username;  // SOURCE
    const data = input;  // Propagate taint
    const query = "DELETE FROM users WHERE name = '" + data + "'";
    db.query(query);  // SINK - Should detect
}

// Example 3: Command injection
function commandInjection() {
    const filename = request.params.file;  // SOURCE
    const command = "cat " + filename;
    exec(command);  // SINK - Should detect command injection
}

// Example 4: Sanitized (should NOT detect)
function sanitizedQuery() {
    const userInput = getUserInput();  // SOURCE
    const clean = escape(userInput);   // SANITIZER
    const query = "SELECT * FROM users WHERE id = " + clean;
    database.execute(query);  // SINK - Should NOT detect (sanitized)
}

// Example 5: Multiple propagations
function multiplePropagations() {
    const input = stdin();  // SOURCE
    const a = input;        // Propagate
    const b = a;            // Propagate
    const c = b;            // Propagate
    eval(c);                // SINK - Should detect
}

// Example 6: XSS vulnerability
function xssVulnerability() {
    const userComment = request.body.comment;  // SOURCE
    document.innerHTML = userComment;  // SINK - Should detect XSS
}

// Example 7: Path traversal
function pathTraversal() {
    const filename = request.query.file;  // SOURCE
    const content = readFile(filename);   // SINK - Should detect path traversal
}

// Example 8: Safe - no taint flow
function safeFunction() {
    const hardcoded = "SELECT * FROM users WHERE id = 1";
    database.execute(hardcoded);  // SINK - Should NOT detect (no tainted input)
}

// Example 9: Taint through function return
function getTaintedData() {
    return getUserInput();  // SOURCE
}

function usesTaintedData() {
    const data = getTaintedData();
    execute(data);  // SINK - Should detect (inter-procedural)
}

// Example 10: Multiple sources converge
function multipleSources() {
    const input1 = request.body.username;  // SOURCE
    const input2 = request.query.id;       // SOURCE
    const query = "SELECT * FROM users WHERE name = '" + input1 + "' AND id = " + input2;
    db.execute(query);  // SINK - Should detect (multiple tainted inputs)
}
