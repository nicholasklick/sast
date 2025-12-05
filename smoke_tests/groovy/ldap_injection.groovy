// LDAP Injection vulnerabilities in Groovy
package com.example.security

import javax.naming.directory.InitialDirContext
import javax.naming.directory.SearchControls
import javax.naming.Context

class LdapInjectionVulnerabilities {

    String ldapUrl = "ldap://directory.example.com:389"
    String baseDn = "dc=example,dc=com"

    // Test 1: User search with unescaped input
    List findUser(String username) {
        // VULNERABLE: Username in filter
        def filter = "(uid=${username})"
        executeLdapSearch(filter)
    }

    // Test 2: Authentication with LDAP
    boolean authenticateUser(String username, String password) {
        // VULNERABLE: Credentials in LDAP bind
        def dn = "uid=${username},ou=users,${baseDn}"
        ldapBind(dn, password)
    }

    // Test 3: Group membership check
    boolean isUserInGroup(String username, String group) {
        // VULNERABLE: Both parameters unescaped
        def filter = "(&(uid=${username})(memberOf=cn=${group},ou=groups,${baseDn}))"
        !executeLdapSearch(filter).isEmpty()
    }

    // Test 4: Email lookup
    List findByEmail(String email) {
        // VULNERABLE: Email in filter
        def filter = "(mail=${email})"
        executeLdapSearch(filter)
    }

    // Test 5: Complex search
    List searchUsers(String firstName, String lastName, String department) {
        // VULNERABLE: Multiple unescaped fields
        def filter = "(&(givenName=${firstName})(sn=${lastName})(department=${department}))"
        executeLdapSearch(filter)
    }

    // Test 6: Wildcard search
    List searchByPartialName(String partial) {
        // VULNERABLE: Wildcard with user input
        def filter = "(cn=*${partial}*)"
        executeLdapSearch(filter)
    }

    // Test 7: DN construction
    String getUserDn(String username, String orgUnit) {
        // VULNERABLE: DN injection
        "uid=${username},ou=${orgUnit},${baseDn}"
    }

    // Test 8: Role-based query
    List getUsersWithRole(String role) {
        // VULNERABLE: Role from user
        def filter = "(role=${role})"
        executeLdapSearch(filter)
    }

    // Test 9: Attribute value injection
    List findByAttribute(String attribute, String value) {
        // VULNERABLE: Both from user
        def filter = "(${attribute}=${value})"
        executeLdapSearch(filter)
    }

    // Test 10: User modification
    void updateUserAttribute(String username, String attribute, String value) {
        // VULNERABLE: All parameters from user
        def dn = "uid=${username},ou=users,${baseDn}"
        ldapModify(dn, attribute, value)
    }

    // Test 11: Search base manipulation
    List searchInOu(String ouName, String filter) {
        // VULNERABLE: OU from user
        def searchBase = "ou=${ouName},${baseDn}"
        executeLdapSearchWithBase(searchBase, filter)
    }

    // Test 12: Nested group query
    List findNestedGroupMembers(String groupName) {
        // VULNERABLE: Group name injection
        def filter = "(memberOf:1.2.840.113556.1.4.1941:=cn=${groupName},ou=groups,${baseDn})"
        executeLdapSearch(filter)
    }

    private List executeLdapSearch(String filter) {
        def env = new Hashtable()
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
        env.put(Context.PROVIDER_URL, ldapUrl)
        def ctx = new InitialDirContext(env)
        def controls = new SearchControls()
        controls.searchScope = SearchControls.SUBTREE_SCOPE
        def results = ctx.search(baseDn, filter, controls)
        def list = []
        while (results.hasMore()) {
            list.add(results.next().nameInNamespace)
        }
        list
    }

    private List executeLdapSearchWithBase(String base, String filter) { [] }
    private boolean ldapBind(String dn, String password) { false }
    private void ldapModify(String dn, String attribute, String value) {}
}
