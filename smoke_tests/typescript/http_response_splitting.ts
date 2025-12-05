// HTTP Response Splitting Test Cases

import { Request, Response } from 'express';

// Test 1: Setting header with unsanitized user input
function setCustomHeader(req: Request, res: Response): void {
    const userValue = req.query.value as string;
    // VULNERABLE: userValue could contain \r\n to inject headers
    res.setHeader('X-Custom-Header', userValue);
    res.send('OK');
}

// Test 2: Location header with user input
function redirectWithUserInput(req: Request, res: Response): void {
    const target = req.query.target as string;
    // VULNERABLE: target could contain \r\n\r\n<script>alert(1)</script>
    res.setHeader('Location', target);
    res.status(302).end();
}

// Test 3: Set-Cookie with user-controlled value
function setUserCookie(req: Request, res: Response): void {
    const cookieValue = req.query.value as string;
    // VULNERABLE: cookieValue could inject additional headers
    res.setHeader('Set-Cookie', `user=${cookieValue}; Path=/`);
    res.send('Cookie set');
}

// Test 4: Multiple headers from user input
function setMultipleHeaders(req: Request, res: Response): void {
    const headerName = req.query.name as string;
    const headerValue = req.query.value as string;
    // VULNERABLE: Both name and value could contain CRLF
    res.setHeader(headerName, headerValue);
    res.send('Headers set');
}

// Test 5: Content-Type header injection
function serveContent(req: Request, res: Response): void {
    const contentType = req.query.type as string;
    // VULNERABLE: contentType could inject headers or response body
    res.setHeader('Content-Type', contentType);
    res.send('Content here');
}
