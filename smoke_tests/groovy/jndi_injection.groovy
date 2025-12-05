// JNDI Injection vulnerabilities in Groovy
package com.example.security

import javax.naming.*

class JndiInjectionVulnerabilities {

    // Test 1: Direct JNDI lookup with user input
    Object lookupResource(String resourceName) {
        // VULNERABLE: User-controlled JNDI name
        def ctx = new InitialContext()
        ctx.lookup(resourceName)
    }

    // Test 2: LDAP URL lookup
    Object ldapLookup(String ldapUrl) {
        // VULNERABLE: User-controlled LDAP URL
        def ctx = new InitialContext()
        ctx.lookup("ldap://${ldapUrl}")
    }

    // Test 3: RMI URL lookup
    Object rmiLookup(String rmiUrl) {
        // VULNERABLE: User-controlled RMI URL
        def ctx = new InitialContext()
        ctx.lookup("rmi://${rmiUrl}")
    }

    // Test 4: JNDI with environment
    Object lookupWithEnv(String name, Map env) {
        // VULNERABLE: Both name and env from user
        def ctx = new InitialContext(new Hashtable(env))
        ctx.lookup(name)
    }

    // Test 5: DataSource lookup
    def getDataSource(String dsName) {
        // VULNERABLE: DataSource name from user
        def ctx = new InitialContext()
        ctx.lookup("java:comp/env/jdbc/${dsName}")
    }

    // Test 6: EJB lookup
    Object lookupEjb(String ejbName) {
        // VULNERABLE: EJB name from user
        def ctx = new InitialContext()
        ctx.lookup("java:global/app/${ejbName}")
    }

    // Test 7: JMS destination lookup
    def lookupQueue(String queueName) {
        // VULNERABLE: Queue name from user
        def ctx = new InitialContext()
        ctx.lookup("java:/jms/queue/${queueName}")
    }

    // Test 8: Mail session lookup
    def lookupMailSession(String sessionName) {
        // VULNERABLE: Mail session from user
        def ctx = new InitialContext()
        ctx.lookup("java:comp/env/mail/${sessionName}")
    }

    // Test 9: DirContext lookup
    Object dirContextLookup(String name) {
        // VULNERABLE: DirContext with user input
        def ctx = new InitialDirContext()
        ctx.lookup(name)
    }

    // Test 10: Composite name lookup
    Object compositeLookup(String[] parts) {
        // VULNERABLE: Name parts from user
        def ctx = new InitialContext()
        def name = new CompositeName()
        parts.each { name.add(it) }
        ctx.lookup(name)
    }

    // Test 11: Context bind (reverse JNDI)
    void bindObject(String name, Object obj) {
        // VULNERABLE: Binding user-controlled name
        def ctx = new InitialContext()
        ctx.bind(name, obj)
    }

    // Test 12: Rebind with user input
    void rebindResource(String name, Object obj) {
        // VULNERABLE: Rebinding with user name
        def ctx = new InitialContext()
        ctx.rebind(name, obj)
    }

    // Test 13: CORBA lookup
    Object corbaLookup(String corbaName) {
        // VULNERABLE: CORBA name from user
        def ctx = new InitialContext()
        ctx.lookup("corbaname:${corbaName}")
    }
}
