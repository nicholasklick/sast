// Utility functions with XSS and path traversal

export function renderUserContent(content: string) {
    // XSS vulnerability
    document.getElementById('output').innerHTML = content;
}

export function loadFile(userPath: string) {
    // Path traversal
    const fs = require('fs');
    return fs.readFile(`./uploads/${userPath}`, 'utf8');
}

export function redirectUser(targetUrl: string) {
    // Unsafe redirect
    response.redirect(targetUrl);
}
