// Clean JavaScript file with no vulnerabilities

function calculateSum(a, b) {
    return a + b;
}

function processUserData(userId) {
    // Properly parameterized query
    const query = db.prepare('SELECT * FROM users WHERE id = ?');
    return query.execute([userId]);
}

function sanitizeInput(userInput) {
    // Proper sanitization
    return escapeHtml(userInput);
}

function displayData(data) {
    // Safe DOM manipulation
    const element = document.getElementById('output');
    element.textContent = data;  // Using textContent instead of innerHTML
}

module.exports = {
    calculateSum,
    processUserData,
    sanitizeInput,
    displayData
};
