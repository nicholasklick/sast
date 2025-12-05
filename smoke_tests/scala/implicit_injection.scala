// Implicit Injection and Type Safety vulnerabilities in Scala
package com.example.security

import scala.language.implicitConversions

class ImplicitInjectionVulnerabilities {

  // Test 1: Dangerous implicit conversion
  implicit def stringToInt(s: String): Int = {
    // VULNERABLE: Silent conversion can mask errors
    s.toInt
  }

  def processNumber(value: Int): Int = value * 2

  def useImplicit(): Int = {
    // VULNERABLE: String silently converted
    processNumber("not_a_number")
  }

  // Test 2: Type erasure vulnerability
  def process[T](items: List[T]): Unit = {
    items match {
      // VULNERABLE: Type erasure makes this always match
      case _: List[String] => println("strings")
      case _: List[Int] => println("ints")
    }
  }

  // Test 3: Implicit parameter injection
  implicit val dangerousConfig: Config = Config(adminMode = true)

  def privilegedAction()(implicit config: Config): Unit = {
    // VULNERABLE: Implicit config can be injected
    if (config.adminMode) {
      performAdminAction()
    }
  }

  // Test 4: Variance annotation abuse
  class Container[+T](val value: T)

  def unsafeVariance(): Unit = {
    val stringContainer: Container[String] = new Container("safe")
    // VULNERABLE: Variance allows unsafe assignment
    val anyContainer: Container[Any] = stringContainer
  }

  // Test 5: Structural type with reflection
  def callMethod(obj: { def execute(): Unit }): Unit = {
    // VULNERABLE: Uses reflection, can fail at runtime
    obj.execute()
  }

  // Test 6: Manifest-based type check
  def checkType[T: Manifest](value: Any): Boolean = {
    // VULNERABLE: Manifest can be forged
    value.isInstanceOf[T]
  }

  // Test 7: Implicit class privilege escalation
  implicit class StringOps(val s: String) {
    def toAdmin: Admin = {
      // VULNERABLE: Implicit conversion to privileged type
      Admin(s)
    }
  }

  def processAdmin(admin: Admin): Unit = {
    admin.delete()
  }

  // Test 8: View bound (deprecated but still compilable)
  def process[T <% Ordered[T]](items: Seq[T]): T = {
    // VULNERABLE: Implicit conversion may have side effects
    items.sorted.head
  }

  // Test 9: Context bound exploitation
  def serialize[T: Serializer](value: T): String = {
    // VULNERABLE: Serializer could be malicious
    implicitly[Serializer[T]].serialize(value)
  }

  // Test 10: Implicit resolution hijacking
  object MaliciousImplicits {
    implicit val injectedExecutor: scala.concurrent.ExecutionContext =
      // VULNERABLE: Malicious execution context
      scala.concurrent.ExecutionContext.global
  }

  // Test 11: Type class instance injection
  trait JsonEncoder[T] {
    def encode(value: T): String
  }

  def toJson[T: JsonEncoder](value: T): String = {
    // VULNERABLE: Encoder instance can be injected
    implicitly[JsonEncoder[T]].encode(value)
  }

  // Test 12: Macro-based implicit materialization
  def materialize[T](implicit m: Materializer[T]): T = {
    // VULNERABLE: Implicit materialization
    m.materialize()
  }

  // Test 13: Path-dependent type confusion
  class Outer {
    class Inner
    def process(inner: Inner): Unit = ()
  }

  def pathDependent(outer1: Outer, outer2: Outer): Unit = {
    val inner = new outer1.Inner
    // VULNERABLE: Type system allows this but semantically wrong
    // outer2.process(inner) // Would fail at runtime
  }

  private def performAdminAction(): Unit = ()
}

case class Config(adminMode: Boolean)
case class Admin(name: String) {
  def delete(): Unit = ()
}
trait Serializer[T] {
  def serialize(value: T): String
}
trait Materializer[T] {
  def materialize(): T
}
