// Missing Security Headers Test Cases

import { Request, Response } from 'express';

// Test 1: Missing X-Frame-Options
function servePageWithoutFrameOptions(req: Request, res: Response): void {
    // VULNERABLE: No X-Frame-Options header - vulnerable to clickjacking
    res.send('<html><body>Content</body></html>');
}

// Test 2: Missing Content-Security-Policy
function servePageWithoutCSP(req: Request, res: Response): void {
    // VULNERABLE: No CSP header - vulnerable to XSS
    res.send('<html><body><script>...</script></body></html>');
}

// Test 3: Missing X-Content-Type-Options
function serveFileWithoutContentTypeOptions(req: Request, res: Response): void {
    // VULNERABLE: No X-Content-Type-Options - MIME sniffing enabled
    res.sendFile('/path/to/file.txt');
}

// Test 4: Missing Strict-Transport-Security
function serveSecurePageWithoutHSTS(req: Request, res: Response): void {
    // VULNERABLE: No HSTS header - vulnerable to downgrade attacks
    res.send('Secure content');
}

// Test 5: Missing multiple security headers
function serveWithNoSecurityHeaders(req: Request, res: Response): void {
    // VULNERABLE: No security headers at all
    const html = `
        <!DOCTYPE html>
        <html>
        <head><title>Insecure Page</title></head>
        <body>
            <h1>Welcome</h1>
            <div id="content"></div>
        </body>
        </html>
    `;
    res.send(html);
}
