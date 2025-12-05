// LDAP Injection Test Cases

// Test 1: LDAP search with unsanitized user input
function searchUserByUsername(ldapClient: any, username: string): Promise<any> {
    // VULNERABLE: username could contain LDAP special characters like *, (, ), \, etc.
    const filter = `(uid=${username})`;
    return ldapClient.search('ou=users,dc=example,dc=com', { filter });
}

// Test 2: LDAP authentication bypass
function authenticateUser(ldapClient: any, username: string, password: string): Promise<boolean> {
    // VULNERABLE: username could be "admin)(&(1=1" to bypass auth
    const dn = `uid=${username},ou=users,dc=example,dc=com`;
    return ldapClient.bind(dn, password);
}

// Test 3: Complex LDAP filter with user input
function findUsers(ldapClient: any, searchTerm: string, department: string): Promise<any> {
    // VULNERABLE: Both searchTerm and department are unsanitized
    const filter = `(&(cn=*${searchTerm}*)(department=${department}))`;
    return ldapClient.search('ou=users,dc=example,dc=com', { filter });
}

// Test 4: LDAP DN construction
function getUserDN(username: string, domain: string): string {
    // VULNERABLE: username could contain DN special characters
    return `cn=${username},dc=${domain},dc=com`;
}

// Test 5: LDAP modify operation
function updateUserAttribute(ldapClient: any, userId: string, email: string): Promise<void> {
    const dn = `uid=${userId},ou=users,dc=example,dc=com`;
    // VULNERABLE: email could contain LDAP injection
    const changes = {
        mail: email
    };
    return ldapClient.modify(dn, changes);
}
