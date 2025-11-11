// API handlers with SSRF and command injection

export function fetchExternalData(url: string) {
    // SSRF vulnerability
    return fetch(url).then(res => res.json());
}

export function executeCommand(filename: string) {
    // Command injection
    const { exec } = require('child_process');
    exec(`cat ${filename}`, (error, stdout) => {
        console.log(stdout);
    });
}

export function renderTemplate(userTemplate: string) {
    // Template injection
    const ejs = require('ejs');
    return ejs.render(userTemplate, { data: 'value' });
}
