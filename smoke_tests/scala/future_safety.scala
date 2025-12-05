// Future and Async Safety vulnerabilities in Scala
package com.example.security

import scala.concurrent.{Future, ExecutionContext, Await}
import scala.concurrent.duration._

class FutureSafetyVulnerabilities {

  implicit val ec: ExecutionContext = ExecutionContext.global

  // Test 1: Blocking in Future
  def blockingFuture(url: String): Future[String] = {
    Future {
      // VULNERABLE: Blocking in default execution context
      val result = Await.result(fetchData(url), 30.seconds)
      result
    }
  }

  // Test 2: Shared mutable state
  private var counter = 0

  def incrementAsync(): Future[Int] = {
    Future {
      // VULNERABLE: Race condition on shared state
      counter += 1
      counter
    }
  }

  // Test 3: Unhandled exception in Future
  def riskyFuture(): Future[Int] = {
    // VULNERABLE: No error handling
    Future {
      1 / 0
    }
  }

  // Test 4: Fire and forget without recovery
  def fireAndForget(data: String): Unit = {
    // VULNERABLE: Exceptions silently swallowed
    Future {
      processData(data)
    }
  }

  // Test 5: Await.result blocking main thread
  def blockingCall(f: Future[String]): String = {
    // VULNERABLE: Can cause deadlock
    Await.result(f, Duration.Inf)
  }

  // Test 6: Collection with race condition
  private val items = scala.collection.mutable.ListBuffer[String]()

  def addItemAsync(item: String): Future[Unit] = {
    Future {
      // VULNERABLE: Non-thread-safe collection
      items += item
    }
  }

  // Test 7: Promise completion race
  def racePromise(): Future[Int] = {
    import scala.concurrent.Promise
    val promise = Promise[Int]()
    // VULNERABLE: Multiple completions
    Future { promise.success(1) }
    Future { promise.success(2) }
    promise.future
  }

  // Test 8: Resource leak in Future
  def resourceLeakFuture(path: String): Future[String] = {
    Future {
      val source = scala.io.Source.fromFile(path)
      // VULNERABLE: Source not closed on exception
      val content = source.mkString
      source.close()
      content
    }
  }

  // Test 9: Unbounded parallelism
  def unboundedParallel(items: Seq[String]): Future[Seq[String]] = {
    // VULNERABLE: Can exhaust thread pool
    Future.sequence(items.map(item => Future {
      expensiveOperation(item)
    }))
  }

  // Test 10: Side effect in map
  def sideEffectInMap(f: Future[Int]): Future[Int] = {
    f.map { value =>
      // VULNERABLE: Side effect in transformation
      println(s"Processing: $value")
      database.write(value)
      value
    }
  }

  // Test 11: Nested Futures without flatten
  def nestedFutures(): Future[Future[Int]] = {
    // VULNERABLE: Confusing nested structure
    Future {
      Future {
        42
      }
    }
  }

  // Test 12: Timeout not handled
  def longRunning(): Future[String] = {
    Future {
      // VULNERABLE: No timeout protection
      Thread.sleep(Long.MaxValue)
      "done"
    }
  }

  // Test 13: ExecutionContext.global for blocking
  def wrongContext(): Future[String] = {
    // VULNERABLE: Using global EC for blocking ops
    Future {
      Thread.sleep(5000)
      blockingIo()
    }(ExecutionContext.global)
  }

  private def fetchData(url: String): Future[String] = Future.successful("")
  private def processData(data: String): Unit = ()
  private def expensiveOperation(item: String): String = item
  private def blockingIo(): String = ""
  private val database = new { def write(v: Int): Unit = () }
}
