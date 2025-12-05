// Race Condition vulnerabilities in Scala
package com.example.security

import scala.collection.mutable

class RaceConditionVulnerabilities {

  private var balance = 1000
  private val inventory = mutable.Map("item1" -> 10)
  private val usedCoupons = mutable.Set[String]()

  // Test 1: TOCTOU in balance check
  def withdraw(amount: Int): Boolean = {
    // VULNERABLE: Check and update not atomic
    if (balance >= amount) {
      Thread.sleep(1) // Race window
      balance -= amount
      true
    } else {
      false
    }
  }

  // Test 2: Double-spend on inventory
  def purchaseItem(itemId: String): Boolean = {
    // VULNERABLE: Check and decrement not atomic
    inventory.get(itemId) match {
      case Some(count) if count > 0 =>
        inventory(itemId) = count - 1
        true
      case _ => false
    }
  }

  // Test 3: Coupon reuse race
  def applyCoupon(code: String): Boolean = {
    // VULNERABLE: Check and add not atomic
    if (usedCoupons.contains(code)) {
      false
    } else {
      Thread.sleep(1) // Race window
      usedCoupons += code
      true
    }
  }

  // Test 4: File write race
  def writeToFile(path: String, content: String): Unit = {
    // VULNERABLE: No file locking
    import java.io._
    val writer = new FileWriter(path)
    writer.write(content)
    writer.close()
  }

  // Test 5: Counter increment race
  private var counter = 0

  def incrementCounter(): Unit = {
    // VULNERABLE: Not thread-safe
    val current = counter
    counter = current + 1
  }

  // Test 6: Lazy val in multi-threaded context
  // Note: Scala lazy val is actually thread-safe, but this pattern shows the concept
  @volatile private var _singleton: Option[ExpensiveObject] = None

  def getSingleton: ExpensiveObject = {
    // VULNERABLE: Race in lazy init (if not using lazy val)
    if (_singleton.isEmpty) {
      _singleton = Some(new ExpensiveObject())
    }
    _singleton.get
  }

  // Test 7: Token refresh race
  private var accessToken = ""
  private var isRefreshing = false

  def getToken: String = {
    // VULNERABLE: Multiple threads may refresh
    if (accessToken.isEmpty && !isRefreshing) {
      isRefreshing = true
      accessToken = refreshToken()
      isRefreshing = false
    }
    accessToken
  }

  // Test 8: Cache stampede
  private val cache = mutable.Map[String, Any]()

  def getCachedValue(key: String): Any = {
    // VULNERABLE: Multiple threads regenerate
    cache.getOrElseUpdate(key, expensiveComputation(key))
  }

  // Test 9: Akka actor state (conceptual)
  private var actorState = 0

  def unsafeActorBehavior(value: Int): Unit = {
    // VULNERABLE: Modifying state outside actor context
    actorState = value
  }

  // Test 10: Rate limit bypass
  private val requestCounts = mutable.Map[String, Int]()
  private val rateLimit = 100

  def checkRateLimit(clientId: String): Boolean = {
    // VULNERABLE: Race allows exceeding limit
    val count = requestCounts.getOrElse(clientId, 0)
    if (count >= rateLimit) {
      false
    } else {
      requestCounts(clientId) = count + 1
      true
    }
  }

  // Test 11: Future composition race
  def futureRace(): scala.concurrent.Future[Int] = {
    import scala.concurrent.ExecutionContext.Implicits.global
    import scala.concurrent.Future
    var result = 0
    // VULNERABLE: Shared mutable state in futures
    Future { result = 1 }
    Future { result = 2 }
    Future { result }
  }

  // Test 12: Collection modification during iteration
  def unsafeIteration(): Unit = {
    val items = mutable.ListBuffer(1, 2, 3)
    // VULNERABLE: ConcurrentModificationException risk
    items.foreach { item =>
      if (item == 2) items -= item
    }
  }

  private def refreshToken(): String = "new_token"
  private def expensiveComputation(key: String): Any = ""
}

class ExpensiveObject {
  Thread.sleep(100)
}
