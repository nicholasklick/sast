// Authorization vulnerabilities in JavaScript/Node.js
const express = require('express');

// Test 1: Missing authorization middleware
function adminDashboard(req, res, db) {
    // VULNERABLE: No authorization check
    const users = db.query('SELECT * FROM users');
    res.json({ users });
}

// Test 2: IDOR - Insecure Direct Object Reference
function viewDocument(req, res, db) {
    const documentId = req.params.id;
    // VULNERABLE: No ownership check
    const document = db.query('SELECT * FROM documents WHERE id = $1', [documentId]);
    res.json(document);
}

// Test 3: Horizontal privilege escalation
function viewProfile(req, res, db) {
    const userId = req.params.userId;
    // VULNERABLE: Can view any user's profile
    const profile = db.query('SELECT * FROM profiles WHERE user_id = $1', [userId]);
    res.json(profile);
}

// Test 4: Vertical privilege escalation
function deleteUser(req, res, db) {
    // VULNERABLE: No admin check
    const userId = req.body.userId;
    db.query('DELETE FROM users WHERE id = $1', [userId]);
    res.json({ deleted: true });
}

// Test 5: Client-side authorization
function getSecretData(req, res) {
    // VULNERABLE: Relying on frontend for authorization
    res.json({ secret: 'sensitive data' });
}

// Test 6: Predictable resource IDs
function getOrder(req, res, db) {
    const orderId = req.params.id;
    // VULNERABLE: Sequential IDs allow enumeration
    const order = db.query('SELECT * FROM orders WHERE id = $1', [orderId]);
    res.json(order);
}

// Test 7: Missing function level access control
function executeFunction(req, res) {
    const functionName = req.body.function;
    // VULNERABLE: No permission check
    const func = adminFunctions[functionName];
    if (func) {
        func();
    }
    res.json({ executed: true });
}

// Test 8: Path-based authorization bypass
function adminApi(req, res) {
    const path = req.path;
    // VULNERABLE: Can bypass with case or encoding
    if (path.toLowerCase().startsWith('/admin')) {
        res.json({ data: 'admin data' });
    } else {
        res.status(401).end();
    }
}

// Test 9: Check after action
async function updateSettings(req, res, db) {
    const settings = req.body.settings;
    // VULNERABLE: Action happens before authorization
    await db.query('UPDATE settings SET data = $1', [settings]);

    if (!req.user.isAdmin) {
        res.status(401).end();
        return;
    }
    res.json({ success: true });
}

// Test 10: Trusting user-provided role
function actionWithRole(req, res) {
    const role = req.headers['x-user-role'];
    // VULNERABLE: Trusting client header
    if (role === 'admin') {
        res.json({ adminData: true });
    } else {
        res.status(403).end();
    }
}

// Test 11: Cached authorization
function cachedAdminPage(req, res) {
    // VULNERABLE: Cached page served to non-admins
    res.set('Cache-Control', 'public, max-age=3600');
    res.json({ adminContent: 'sensitive' });
}

// Test 12: GraphQL authorization bypass
const graphqlResolvers = {
    Query: {
        // VULNERABLE: No authorization in resolver
        users: (parent, args, context) => {
            return context.db.query('SELECT * FROM users');
        },
        // VULNERABLE: IDOR in GraphQL
        user: (parent, { id }, context) => {
            return context.db.query('SELECT * FROM users WHERE id = $1', [id]);
        }
    }
};

// Test 13: Express route without middleware
// VULNERABLE: No auth middleware
// app.get('/api/admin/users', adminDashboard);
// app.delete('/api/users/:id', deleteUser);

const adminFunctions = {
    resetDatabase: () => {},
    exportData: () => {}
};

module.exports = {
    adminDashboard,
    viewDocument,
    viewProfile,
    deleteUser,
    getSecretData,
    getOrder,
    executeFunction,
    adminApi,
    updateSettings,
    actionWithRole,
    cachedAdminPage,
    graphqlResolvers
};
