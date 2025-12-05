// Null Safety vulnerabilities in Scala
package com.example.security

class NullSafetyVulnerabilities {

  // Test 1: Option.get without check
  def getUserName(userId: Int): String = {
    val user = findUser(userId)
    // VULNERABLE: get on Option can throw
    user.get.name
  }

  // Test 2: Unsafe pattern matching
  def processOption(opt: Option[String]): String = opt match {
    // VULNERABLE: Missing None case
    case Some(value) => value
    // No None case - will throw MatchError
  }

  // Test 3: Java interop null
  def processJavaObject(obj: JavaObject): String = {
    // VULNERABLE: Java method might return null
    obj.getName.toUpperCase
  }

  // Test 4: head on empty collection
  def getFirstUser(users: List[User]): User = {
    // VULNERABLE: head throws on empty list
    users.head
  }

  // Test 5: last on empty collection
  def getLastItem[T](items: Seq[T]): T = {
    // VULNERABLE: last throws on empty seq
    items.last
  }

  // Test 6: Array index without bounds check
  def getItem(items: Array[String], index: Int): String = {
    // VULNERABLE: No bounds check
    items(index)
  }

  // Test 7: Map apply without contains check
  def getConfig(key: String): String = {
    val config = loadConfig()
    // VULNERABLE: apply throws if key missing
    config(key)
  }

  // Test 8: reduce on empty collection
  def sumItems(items: List[Int]): Int = {
    // VULNERABLE: reduce throws on empty
    items.reduce(_ + _)
  }

  // Test 9: Unsafe cast
  def processResponse(data: Any): Map[String, Any] = {
    // VULNERABLE: Cast can fail
    data.asInstanceOf[Map[String, Any]]
  }

  // Test 10: Pattern match with null
  def matchNull(value: String): String = value match {
    case "test" => "found"
    // VULNERABLE: null not handled
    case other => other.toUpperCase
  }

  // Test 11: orNull usage
  def getNullable(opt: Option[String]): String = {
    // VULNERABLE: Returning null in Scala
    opt.orNull
  }

  // Test 12: Try.get without recovery
  def parseNumber(s: String): Int = {
    import scala.util.Try
    // VULNERABLE: get on Try can throw
    Try(s.toInt).get
  }

  // Test 13: Either.right.get
  def getValue(either: Either[String, Int]): Int = {
    // VULNERABLE: get on Right projection can throw
    either.toOption.get
  }

  // Test 14: regex match without check
  def extractNumber(input: String): String = {
    val regex = "(\\d+)".r
    input match {
      // VULNERABLE: Pattern might not match
      case regex(num) => num
    }
  }

  // Test 15: Iterator.next without hasNext
  def getNext(items: Iterator[String]): String = {
    // VULNERABLE: No hasNext check
    items.next()
  }

  private def findUser(userId: Int): Option[User] = None
  private def loadConfig(): Map[String, String] = Map.empty
}

case class User(name: String)

trait JavaObject {
  def getName: String
}
