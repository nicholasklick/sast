// LDAP Injection vulnerabilities in Scala
package com.example.security

import javax.naming.directory.{InitialDirContext, SearchControls}
import javax.naming.Context
import java.util.Hashtable

class LdapInjectionVulnerabilities {

  private val ldapUrl = "ldap://directory.example.com:389"
  private val baseDn = "dc=example,dc=com"

  // Test 1: User search with unescaped input
  def findUser(username: String): List[String] = {
    // VULNERABLE: Username in filter
    val filter = s"(uid=$username)"
    executeLdapSearch(filter)
  }

  // Test 2: Authentication with LDAP
  def authenticateUser(username: String, password: String): Boolean = {
    // VULNERABLE: Credentials in LDAP bind
    val dn = s"uid=$username,ou=users,$baseDn"
    ldapBind(dn, password)
  }

  // Test 3: Group membership check
  def isUserInGroup(username: String, group: String): Boolean = {
    // VULNERABLE: Both parameters unescaped
    val filter = s"(&(uid=$username)(memberOf=cn=$group,ou=groups,$baseDn))"
    executeLdapSearch(filter).nonEmpty
  }

  // Test 4: Email lookup
  def findByEmail(email: String): List[String] = {
    // VULNERABLE: Email in filter
    val filter = s"(mail=$email)"
    executeLdapSearch(filter)
  }

  // Test 5: Complex search
  def searchUsers(firstName: String, lastName: String, department: String): List[String] = {
    // VULNERABLE: Multiple unescaped fields
    val filter = s"(&(givenName=$firstName)(sn=$lastName)(department=$department))"
    executeLdapSearch(filter)
  }

  // Test 6: Wildcard search
  def searchByPartialName(partial: String): List[String] = {
    // VULNERABLE: Wildcard with user input
    val filter = s"(cn=*$partial*)"
    executeLdapSearch(filter)
  }

  // Test 7: DN construction
  def getUserDn(username: String, orgUnit: String): String = {
    // VULNERABLE: DN injection
    s"uid=$username,ou=$orgUnit,$baseDn"
  }

  // Test 8: Role-based query
  def getUsersWithRole(role: String): List[String] = {
    // VULNERABLE: Role from user
    val filter = s"(role=$role)"
    executeLdapSearch(filter)
  }

  // Test 9: Attribute value injection
  def findByAttribute(attribute: String, value: String): List[String] = {
    // VULNERABLE: Both from user
    val filter = s"($attribute=$value)"
    executeLdapSearch(filter)
  }

  // Test 10: User modification
  def updateUserAttribute(username: String, attribute: String, value: String): Unit = {
    // VULNERABLE: All parameters from user
    val dn = s"uid=$username,ou=users,$baseDn"
    ldapModify(dn, attribute, value)
  }

  // Test 11: Search base manipulation
  def searchInOu(ouName: String, filter: String): List[String] = {
    // VULNERABLE: OU from user
    val searchBase = s"ou=$ouName,$baseDn"
    executeLdapSearchWithBase(searchBase, filter)
  }

  // Test 12: Nested group query
  def findNestedGroupMembers(groupName: String): List[String] = {
    // VULNERABLE: Group name injection
    val filter = s"(memberOf:1.2.840.113556.1.4.1941:=cn=$groupName,ou=groups,$baseDn)"
    executeLdapSearch(filter)
  }

  private def executeLdapSearch(filter: String): List[String] = {
    val env = new Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, ldapUrl)
    val ctx = new InitialDirContext(env)
    val controls = new SearchControls()
    controls.setSearchScope(SearchControls.SUBTREE_SCOPE)
    val results = ctx.search(baseDn, filter, controls)
    Iterator.continually(results).takeWhile(_.hasMore).map(_.next().getNameInNamespace).toList
  }

  private def executeLdapSearchWithBase(base: String, filter: String): List[String] = Nil
  private def ldapBind(dn: String, password: String): Boolean = false
  private def ldapModify(dn: String, attribute: String, value: String): Unit = ()
}
