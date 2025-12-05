// Missing CSRF Protection Test Cases

import { Request, Response } from 'express';

// Test 1: State-changing POST without CSRF token
function updateUserProfile(req: Request, res: Response): void {
    const { email, phone } = req.body;
    // VULNERABLE: No CSRF token validation
    // Update user profile in database
    res.json({ success: true });
}

// Test 2: DELETE endpoint without CSRF protection
function deleteAccount(req: Request, res: Response): void {
    const userId = req.params.id;
    // VULNERABLE: Destructive action without CSRF token
    // Delete user account
    res.json({ deleted: true });
}

// Test 3: Money transfer without CSRF token
function transferFunds(req: Request, res: Response): void {
    const { fromAccount, toAccount, amount } = req.body;
    // VULNERABLE: Financial transaction without CSRF protection
    // Process transfer
    res.json({ transferred: amount });
}

// Test 4: Password change without CSRF token
function changePassword(req: Request, res: Response): void {
    const { oldPassword, newPassword } = req.body;
    // VULNERABLE: Security-critical action without CSRF token
    // Change password
    res.json({ success: true });
}

// Test 5: Admin action without CSRF protection
function promoteToAdmin(req: Request, res: Response): void {
    const userId = req.body.userId;
    // VULNERABLE: Privilege escalation without CSRF token
    // Promote user to admin
    res.json({ promoted: true });
}
