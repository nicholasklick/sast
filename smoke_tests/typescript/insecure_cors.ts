// Insecure CORS Test Cases

import { Request, Response } from 'express';

// Test 1: Wildcard CORS with credentials
function setWildcardCORS(req: Request, res: Response): void {
    // VULNERABLE: Wildcard origin with credentials is not allowed
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
}

// Test 2: Reflecting origin without validation
function reflectOrigin(req: Request, res: Response): void {
    const origin = req.headers.origin;
    // VULNERABLE: Reflecting origin without validation
    res.setHeader('Access-Control-Allow-Origin', origin || '');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
}

// Test 3: Null origin allowed
function allowNullOrigin(req: Request, res: Response): void {
    // VULNERABLE: null origin can be exploited
    res.setHeader('Access-Control-Allow-Origin', 'null');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
}

// Test 4: Overly permissive CORS headers
function setPermissiveCORS(req: Request, res: Response): void {
    // VULNERABLE: Allowing all origins without proper validation
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.setHeader('Access-Control-Allow-Methods', '*');
    res.setHeader('Access-Control-Allow-Headers', '*');
}

// Test 5: Trusting subdomain without proper validation
function trustSubdomainWithRegex(req: Request, res: Response): void {
    const origin = req.headers.origin || '';
    // VULNERABLE: Weak regex can be bypassed (e.g., evilexample.com)
    if (origin.match(/example\.com/)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
}
