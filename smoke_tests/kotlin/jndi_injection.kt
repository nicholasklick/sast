// JNDI Injection vulnerabilities in Kotlin
package com.example.security

import javax.naming.Context
import javax.naming.InitialContext
import java.util.Hashtable

class JndiInjectionVulnerabilities {

    // Test 1: Direct JNDI lookup with user input
    fun lookupResource(resourceName: String): Any? {
        // VULNERABLE: User-controlled JNDI name
        val ctx = InitialContext()
        return ctx.lookup(resourceName)
    }

    // Test 2: JNDI lookup with URL
    fun lookupByUrl(jndiUrl: String): Any? {
        // VULNERABLE: URL from user (can be rmi://, ldap://)
        val env = Hashtable<String, String>()
        env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.rmi.registry.RegistryContextFactory"
        env[Context.PROVIDER_URL] = jndiUrl
        val ctx = InitialContext(env)
        return ctx.lookup("name")
    }

    // Test 3: DataSource lookup
    fun getDataSource(dsName: String): javax.sql.DataSource? {
        // VULNERABLE: DataSource name from user
        val ctx = InitialContext()
        return ctx.lookup("java:comp/env/jdbc/$dsName") as? javax.sql.DataSource
    }

    // Test 4: JMS destination lookup
    fun getDestination(destName: String): Any? {
        // VULNERABLE: Destination from user
        val ctx = InitialContext()
        return ctx.lookup("jms/$destName")
    }

    // Test 5: Environment lookup
    fun getEnvValue(envName: String): Any? {
        // VULNERABLE: Environment name from user
        val ctx = InitialContext()
        return ctx.lookup("java:comp/env/$envName")
    }

    // Test 6: Remote object lookup
    fun getRemoteObject(serviceName: String): Any? {
        // VULNERABLE: Service name injection
        val env = Hashtable<String, String>()
        env[Context.PROVIDER_URL] = "rmi://localhost:1099"
        val ctx = InitialContext(env)
        return ctx.lookup(serviceName)
    }

    // Test 7: LDAP JNDI lookup
    fun ldapLookup(ldapUrl: String, baseDn: String): Any? {
        // VULNERABLE: LDAP URL from user
        val env = Hashtable<String, String>()
        env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
        env[Context.PROVIDER_URL] = ldapUrl
        val ctx = InitialContext(env)
        return ctx.lookup(baseDn)
    }

    // Test 8: Log4j style JNDI (Log4Shell pattern)
    fun logMessage(message: String) {
        // VULNERABLE: Message could contain ${jndi:ldap://...}
        val logger = org.slf4j.LoggerFactory.getLogger(this::class.java)
        logger.info(message)
    }

    // Test 9: Object factory lookup
    fun getObjectFromFactory(factoryName: String): Any? {
        // VULNERABLE: Factory name from user
        val ctx = InitialContext()
        return ctx.lookup("java:global/$factoryName")
    }

    // Test 10: Composite name lookup
    fun compositeLookup(parts: List<String>): Any? {
        // VULNERABLE: Parts from user
        val ctx = InitialContext()
        val name = javax.naming.CompositeName()
        parts.forEach { name.add(it) }
        return ctx.lookup(name)
    }

    // Test 11: EJB lookup
    fun lookupEjb(ejbName: String): Any? {
        // VULNERABLE: EJB name from user
        val ctx = InitialContext()
        return ctx.lookup("java:global/app/$ejbName")
    }

    // Test 12: Connection factory lookup
    fun getConnectionFactory(cfName: String): Any? {
        // VULNERABLE: Factory name from user
        val ctx = InitialContext()
        return ctx.lookup("java:/ConnectionFactory/$cfName")
    }
}
