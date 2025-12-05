// Authorization and Access Control vulnerabilities in Scala
package com.example.security

class AuthorizationVulnerabilities {

  // Test 1: Missing authorization check
  def deleteUser(userId: Int): Unit = {
    // VULNERABLE: No authorization check
    userRepository.delete(userId)
  }

  // Test 2: Insecure Direct Object Reference (IDOR)
  def getUserData(userId: Int): Option[User] = {
    // VULNERABLE: No ownership verification
    userRepository.findById(userId)
  }

  // Test 3: Horizontal privilege escalation
  def updateProfile(userId: Int, data: Map[String, Any]): Unit = {
    // VULNERABLE: Can update any user's profile
    userRepository.update(userId, data)
  }

  // Test 4: Vertical privilege escalation
  def setUserRole(userId: Int, role: String): Unit = {
    // VULNERABLE: No admin check
    userRepository.setRole(userId, role)
  }

  // Test 5: Client-side authorization
  def viewAdminPanel(isAdmin: Boolean): String = {
    // VULNERABLE: Trust client-side flag
    if (isAdmin) "Admin Panel" else "Access Denied"
  }

  // Test 6: Parameter tampering
  def accessResource(resourceId: String, userId: Int): Option[Any] = {
    // VULNERABLE: userId from request, not session
    resourceRepository.get(resourceId, userId)
  }

  // Test 7: Missing function-level access control
  def adminFunction(action: String): Unit = {
    // VULNERABLE: No role check
    action match {
      case "deleteAll" => userRepository.deleteAll()
      case "export" => exportAllData()
      case "resetSystem" => resetSystem()
    }
  }

  // Test 8: Path-based authorization bypass
  def accessFile(path: String): Array[Byte] = {
    // VULNERABLE: No path authorization
    scala.io.Source.fromFile(s"/uploads/$path").mkString.getBytes
  }

  // Test 9: Broken access control in API
  def handleApiRequest(endpoint: String, userId: Int): Any = {
    // VULNERABLE: No authorization
    endpoint match {
      case "/users" => userRepository.findAll()
      case "/admin/settings" => getAdminSettings()
      case s"/user/$id" => userRepository.findById(id.toInt)
      case _ => Map("error" -> "Not found")
    }
  }

  // Test 10: Mass assignment with role
  def updateUser(userId: Int, params: Map[String, Any]): Unit = {
    userRepository.findById(userId).foreach { user =>
      // VULNERABLE: Can set isAdmin via params
      params.get("isAdmin").foreach(v => user.isAdmin = v.asInstanceOf[Boolean])
      params.get("role").foreach(v => user.role = v.asInstanceOf[String])
      userRepository.save(user)
    }
  }

  // Test 11: Token validation bypass
  def validateToken(token: String): Boolean = {
    // VULNERABLE: Debug backdoor
    if (token == "debug") return true
    if (token.isEmpty) return false
    tokenValidator.validate(token)
  }

  // Test 12: Cached authorization
  private val permissionCache = scala.collection.mutable.Map[String, Boolean]()

  def checkPermission(userId: Int, resource: String): Boolean = {
    val key = s"$userId-$resource"
    // VULNERABLE: Cached permissions may be stale
    permissionCache.getOrElseUpdate(key, checkActualPermission(userId, resource))
  }

  private def exportAllData(): Unit = ()
  private def resetSystem(): Unit = ()
  private def getAdminSettings(): Map[String, Any] = Map.empty
  private def checkActualPermission(userId: Int, resource: String): Boolean = false
  private val tokenValidator = new { def validate(token: String): Boolean = false }
  private val userRepository = new UserRepository()
  private val resourceRepository = new { def get(id: String, userId: Int): Option[Any] = None }
}

class User(var isAdmin: Boolean = false, var role: String = "user")

class UserRepository {
  def delete(id: Int): Unit = ()
  def findById(id: Int): Option[User] = None
  def findAll(): List[User] = Nil
  def update(id: Int, data: Map[String, Any]): Unit = ()
  def setRole(id: Int, role: String): Unit = ()
  def deleteAll(): Unit = ()
  def save(user: User): Unit = ()
}
