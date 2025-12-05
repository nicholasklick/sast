// Insecure Cookie Test Cases

import { Request, Response } from 'express';

// Test 1: Cookie without Secure flag
function setInsecureCookie(res: Response): void {
    // VULNERABLE: Missing Secure flag - can be sent over HTTP
    res.cookie('session', 'abc123', { httpOnly: true });
}

// Test 2: Cookie without HttpOnly flag
function setJavaScriptAccessibleCookie(res: Response): void {
    // VULNERABLE: Missing HttpOnly - accessible via JavaScript
    res.cookie('authToken', 'xyz789', { secure: true });
}

// Test 3: Cookie without SameSite attribute
function setCookieWithoutSameSite(res: Response): void {
    // VULNERABLE: Missing SameSite - vulnerable to CSRF
    res.cookie('user', 'john', { secure: true, httpOnly: true });
}

// Test 4: Set-Cookie header directly without security flags
function setRawCookie(res: Response): void {
    // VULNERABLE: No security flags in raw Set-Cookie header
    res.setHeader('Set-Cookie', 'sessionId=secret123; Path=/');
}

// Test 5: Cookie with SameSite=None without Secure
function setSameSiteNoneCookie(res: Response): void {
    // VULNERABLE: SameSite=None requires Secure flag
    res.cookie('tracking', '12345', {
        sameSite: 'none',
        httpOnly: true
    });
}
