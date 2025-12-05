// JNDI Injection vulnerabilities in Scala
package com.example.security

import javax.naming.{Context, InitialContext}
import java.util.Hashtable

class JndiInjectionVulnerabilities {

  // Test 1: Direct JNDI lookup with user input
  def lookupResource(resourceName: String): Any = {
    // VULNERABLE: User-controlled JNDI name
    val ctx = new InitialContext()
    ctx.lookup(resourceName)
  }

  // Test 2: JNDI lookup with URL
  def lookupByUrl(jndiUrl: String): Any = {
    // VULNERABLE: URL from user (can be rmi://, ldap://)
    val env = new Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.rmi.registry.RegistryContextFactory")
    env.put(Context.PROVIDER_URL, jndiUrl)
    val ctx = new InitialContext(env)
    ctx.lookup("name")
  }

  // Test 3: DataSource lookup
  def getDataSource(dsName: String): javax.sql.DataSource = {
    // VULNERABLE: DataSource name from user
    val ctx = new InitialContext()
    ctx.lookup(s"java:comp/env/jdbc/$dsName").asInstanceOf[javax.sql.DataSource]
  }

  // Test 4: JMS destination lookup
  def getDestination(destName: String): Any = {
    // VULNERABLE: Destination from user
    val ctx = new InitialContext()
    ctx.lookup(s"jms/$destName")
  }

  // Test 5: Environment lookup
  def getEnvValue(envName: String): Any = {
    // VULNERABLE: Environment name from user
    val ctx = new InitialContext()
    ctx.lookup(s"java:comp/env/$envName")
  }

  // Test 6: Remote object lookup
  def getRemoteObject(serviceName: String): Any = {
    // VULNERABLE: Service name injection
    val env = new Hashtable[String, String]()
    env.put(Context.PROVIDER_URL, "rmi://localhost:1099")
    val ctx = new InitialContext(env)
    ctx.lookup(serviceName)
  }

  // Test 7: LDAP JNDI lookup
  def ldapLookup(ldapUrl: String, baseDn: String): Any = {
    // VULNERABLE: LDAP URL from user
    val env = new Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, ldapUrl)
    val ctx = new InitialContext(env)
    ctx.lookup(baseDn)
  }

  // Test 8: Log4j style JNDI (Log4Shell pattern)
  def logMessage(message: String): Unit = {
    // VULNERABLE: Message could contain ${jndi:ldap://...}
    val logger = org.slf4j.LoggerFactory.getLogger(getClass)
    logger.info(message)
  }

  // Test 9: Object factory lookup
  def getObjectFromFactory(factoryName: String): Any = {
    // VULNERABLE: Factory name from user
    val ctx = new InitialContext()
    ctx.lookup(s"java:global/$factoryName")
  }

  // Test 10: Composite name lookup
  def compositeLookup(parts: List[String]): Any = {
    // VULNERABLE: Parts from user
    val ctx = new InitialContext()
    val name = new javax.naming.CompositeName()
    parts.foreach(name.add)
    ctx.lookup(name)
  }

  // Test 11: EJB lookup
  def lookupEjb(ejbName: String): Any = {
    // VULNERABLE: EJB name from user
    val ctx = new InitialContext()
    ctx.lookup(s"java:global/app/$ejbName")
  }

  // Test 12: Play Framework configuration lookup
  def playConfigLookup(key: String): Any = {
    // VULNERABLE: Config key from user
    val ctx = new InitialContext()
    ctx.lookup(s"java:comp/env/config/$key")
  }
}
