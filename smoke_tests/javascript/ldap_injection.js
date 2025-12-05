// LDAP Injection vulnerabilities in JavaScript/Node.js
const ldap = require('ldapjs');

const LDAP_URL = 'ldap://ldap.example.com';
const LDAP_BASE = 'dc=example,dc=com';

// Test 1: Authentication bypass
async function authenticate(req, res) {
    const username = req.body.username;
    const password = req.body.password;

    const client = ldap.createClient({ url: LDAP_URL });
    // VULNERABLE: User input in LDAP filter
    const filter = `(&(uid=${username})(userPassword=${password}))`;

    const opts = {
        filter: filter,
        scope: 'sub',
        baseDN: LDAP_BASE
    };

    client.search(LDAP_BASE, opts, (err, result) => {
        result.on('searchEntry', (entry) => {
            res.json({ authenticated: true });
        });
        result.on('end', () => {
            res.json({ authenticated: false });
        });
    });
}

// Test 2: User search injection
function searchUser(req, res) {
    const query = req.query.query;
    const client = ldap.createClient({ url: LDAP_URL });

    // VULNERABLE: Search query from user
    const filter = `(|(cn=*${query}*)(mail=*${query}*))`;

    client.search(LDAP_BASE, { filter, scope: 'sub' }, (err, result) => {
        const entries = [];
        result.on('searchEntry', (entry) => entries.push(entry.object));
        result.on('end', () => res.json(entries));
    });
}

// Test 3: Group membership check
function checkGroup(req, res) {
    const user = req.query.user;
    const group = req.query.group;
    const client = ldap.createClient({ url: LDAP_URL });

    // VULNERABLE: Both parameters from user
    const filter = `(&(member=${user})(cn=${group}))`;

    client.search(LDAP_BASE, { filter, scope: 'sub' }, (err, result) => {
        let found = false;
        result.on('searchEntry', () => { found = true; });
        result.on('end', () => res.json({ member: found }));
    });
}

// Test 4: Email lookup
function findByEmail(req, res) {
    const email = req.query.email;
    const client = ldap.createClient({ url: LDAP_URL });

    // VULNERABLE: Email from user
    const filter = `(mail=${email})`;

    client.search(LDAP_BASE, { filter, scope: 'sub' }, (err, result) => {
        const entries = [];
        result.on('searchEntry', (entry) => entries.push(entry.object));
        result.on('end', () => res.json(entries));
    });
}

// Test 5: Wildcard injection
function wildcardSearch(req, res) {
    const prefix = req.query.prefix;
    const client = ldap.createClient({ url: LDAP_URL });

    // VULNERABLE: Wildcard with user input
    const filter = `(cn=${prefix}*)`;

    client.search(LDAP_BASE, { filter, scope: 'sub' }, (err, result) => {
        let count = 0;
        result.on('searchEntry', () => count++);
        result.on('end', () => res.json({ count }));
    });
}

// Test 6: DN manipulation
function getEntry(req, res) {
    const dn = req.query.dn;
    const client = ldap.createClient({ url: LDAP_URL });

    // VULNERABLE: DN from user input
    client.search(dn, { scope: 'base' }, (err, result) => {
        result.on('searchEntry', (entry) => res.json(entry.object));
        result.on('end', () => res.status(404).end());
    });
}

// Test 7: OR clause injection
function multiSearch(req, res) {
    const term = req.query.term;
    const client = ldap.createClient({ url: LDAP_URL });

    // VULNERABLE: Term in OR filter
    const filter = `(|(cn=${term})(sn=${term})(mail=${term}))`;

    client.search(LDAP_BASE, { filter, scope: 'sub' }, (err, result) => {
        let count = 0;
        result.on('searchEntry', () => count++);
        result.on('end', () => res.json({ count }));
    });
}

// Test 8: Bind with user credentials
function bindUser(req, res) {
    const username = req.body.username;
    const password = req.body.password;
    const client = ldap.createClient({ url: LDAP_URL });

    // VULNERABLE: DN constructed from user input
    const dn = `cn=${username},${LDAP_BASE}`;

    client.bind(dn, password, (err) => {
        if (err) {
            res.json({ success: false });
        } else {
            res.json({ success: true });
        }
    });
}

// Test 9: Multiple filter parameters
function advancedSearch(req, res) {
    const name = req.query.name;
    const role = req.query.role;
    const status = req.query.status;
    const client = ldap.createClient({ url: LDAP_URL });

    // VULNERABLE: Multiple injection points
    const filter = `(&(cn=${name})(role=${role})(status=${status}))`;

    client.search(LDAP_BASE, { filter, scope: 'sub' }, (err, result) => {
        const entries = [];
        result.on('searchEntry', (entry) => entries.push(entry.object));
        result.on('end', () => res.json(entries));
    });
}

module.exports = {
    authenticate,
    searchUser,
    checkGroup,
    findByEmail,
    wildcardSearch,
    getEntry,
    multiSearch,
    bindUser,
    advancedSearch
};
