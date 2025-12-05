// Mass Assignment vulnerabilities in Scala
package com.example.security

import scala.collection.mutable

class MassAssignmentVulnerabilities {

  // Test 1: Direct map assignment
  def updateUser(userId: Int, params: Map[String, Any]): Unit = {
    val user = getUser(userId)
    // VULNERABLE: All params assigned
    params.foreach { case (key, value) =>
      setUserProperty(user, key, value)
    }
    saveUser(user)
  }

  // Test 2: Case class copy with spread
  def patchUser(userId: Int, updates: Map[String, Any]): User = {
    val user = getUser(userId)
    // VULNERABLE: Copying with untrusted updates
    user.copy(
      name = updates.getOrElse("name", user.name).asInstanceOf[String],
      email = updates.getOrElse("email", user.email).asInstanceOf[String],
      isAdmin = updates.getOrElse("isAdmin", user.isAdmin).asInstanceOf[Boolean], // VULNERABLE
      role = updates.getOrElse("role", user.role).asInstanceOf[String] // VULNERABLE
    )
  }

  // Test 3: Reflection-based assignment
  def updateObject(obj: AnyRef, params: Map[String, Any]): Unit = {
    // VULNERABLE: Setting arbitrary properties
    params.foreach { case (key, value) =>
      val field = obj.getClass.getDeclaredField(key)
      field.setAccessible(true)
      field.set(obj, value)
    }
  }

  // Test 4: Play JSON binding (conceptual)
  def handleJsonRequest(json: String): User = {
    // VULNERABLE: All fields from JSON
    import play.api.libs.json._
    implicit val userReads: Reads[User] = Json.reads[User]
    Json.parse(json).as[User]
  }

  // Test 5: Form data binding
  def handleFormSubmission(formData: Map[String, String]): Profile = {
    // VULNERABLE: All form fields accepted
    Profile(
      name = formData.getOrElse("name", ""),
      bio = formData.getOrElse("bio", ""),
      isVerified = formData.get("isVerified").exists(_.toBoolean), // VULNERABLE
      permissions = formData.getOrElse("permissions", "") // VULNERABLE
    )
  }

  // Test 6: Circe JSON decode
  def decodeWithCirce(json: String): User = {
    // VULNERABLE: Decoding all fields
    import io.circe.parser._
    import io.circe.generic.auto._
    decode[User](json).getOrElse(throw new Exception("Parse failed"))
  }

  // Test 7: Merge maps
  def mergeUserData(userId: Int, newData: Map[String, Any]): Map[String, Any] = {
    val existingData = getUserData(userId)
    // VULNERABLE: Merging untrusted data
    existingData ++ newData
  }

  // Test 8: Spray JSON format
  def sprayJsonFormat(json: String): User = {
    // VULNERABLE: All fields deserialized
    import spray.json._
    import DefaultJsonProtocol._
    implicit val userFormat: RootJsonFormat[User] = jsonFormat4(User.apply)
    json.parseJson.convertTo[User]
  }

  // Test 9: Argonaut decode
  def argonautDecode(json: String): User = {
    // VULNERABLE: Full object decode
    import argonaut._, Argonaut._
    json.decodeOption[User].get
  }

  // Test 10: Builder pattern abuse
  def buildFromParams(params: Map[String, Any]): User = {
    // VULNERABLE: Builder accepts all params
    UserBuilder()
      .id(params.getOrElse("id", 0).asInstanceOf[Int])
      .name(params.getOrElse("name", "").asInstanceOf[String])
      .isAdmin(params.getOrElse("isAdmin", false).asInstanceOf[Boolean]) // VULNERABLE
      .build()
  }

  // Test 11: Mutable object update
  def updateMutableUser(user: MutableUser, params: Map[String, Any]): Unit = {
    // VULNERABLE: All params used
    params.get("name").foreach(v => user.name = v.asInstanceOf[String])
    params.get("isAdmin").foreach(v => user.isAdmin = v.asInstanceOf[Boolean])
    params.get("role").foreach(v => user.role = v.asInstanceOf[String])
  }

  // Test 12: Slick entity update (conceptual)
  def slickUpdate(userId: Int, values: Map[String, Any]): Unit = {
    // VULNERABLE: All columns from map
    val updates = values.map { case (k, v) => s"$k = $v" }.mkString(", ")
    s"UPDATE users SET $updates WHERE id = $userId"
  }

  private def getUser(userId: Int): User = User(userId, "", "", false, "user")
  private def setUserProperty(user: User, key: String, value: Any): Unit = ()
  private def saveUser(user: User): Unit = ()
  private def getUserData(userId: Int): Map[String, Any] = Map.empty
}

case class User(id: Int, name: String, email: String, isAdmin: Boolean, role: String)

case class Profile(name: String, bio: String, isVerified: Boolean, permissions: String)

class MutableUser {
  var name: String = ""
  var isAdmin: Boolean = false
  var role: String = "user"
}

case class UserBuilder(
  id: Int = 0,
  name: String = "",
  isAdmin: Boolean = false
) {
  def id(v: Int): UserBuilder = copy(id = v)
  def name(v: String): UserBuilder = copy(name = v)
  def isAdmin(v: Boolean): UserBuilder = copy(isAdmin = v)
  def build(): User = User(id, name, "", isAdmin, "user")
}
