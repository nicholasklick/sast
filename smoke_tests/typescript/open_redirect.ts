// Open Redirect Test Cases

import { Request, Response } from 'express';

// Test 1: Direct redirect to user-provided URL
function redirectToUrl(req: Request, res: Response): void {
    const url = req.query.url as string;
    // VULNERABLE: Redirecting to unvalidated URL
    res.redirect(url);
}

// Test 2: Redirect with return parameter
function handleLogin(req: Request, res: Response): void {
    const returnUrl = req.query.return as string;
    // Authenticate user...
    // VULNERABLE: Redirecting to user-controlled URL after login
    res.redirect(returnUrl);
}

// Test 3: Location header with user input
function redirectViaHeader(req: Request, res: Response): void {
    const destination = req.query.dest as string;
    // VULNERABLE: Setting Location header with user input
    res.setHeader('Location', destination);
    res.status(302).send();
}

// Test 4: Redirect using template string
function redirectWithTemplate(req: Request, res: Response): void {
    const target = req.query.target as string;
    // VULNERABLE: User input in redirect URL
    res.redirect(`${target}`);
}

// Test 5: Window location assignment
function clientSideRedirect(userUrl: string): string {
    // VULNERABLE: Client-side redirect with user input
    return `<script>window.location = '${userUrl}';</script>`;
}
