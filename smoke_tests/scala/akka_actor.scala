// Akka Actor Security vulnerabilities in Scala
package com.example.security

import akka.actor._

class AkkaActorVulnerabilities {

  // Test 1: Untyped actor message injection
  class UntypedHandler extends Actor {
    // VULNERABLE: Processing any message type
    def receive: Receive = {
      case cmd: String => executeCommand(cmd)
      case _ => ()
    }

    private def executeCommand(cmd: String): Unit = {
      // VULNERABLE: Executing arbitrary command
      Runtime.getRuntime.exec(cmd)
    }
  }

  // Test 2: Actor selection with user input
  def sendToActor(system: ActorSystem, path: String, message: Any): Unit = {
    // VULNERABLE: Actor path from user
    system.actorSelection(path) ! message
  }

  // Test 3: Remote actor message
  def sendRemote(system: ActorSystem, host: String, port: Int, message: Any): Unit = {
    // VULNERABLE: Remote address from user
    val remotePath = s"akka://system@$host:$port/user/target"
    system.actorSelection(remotePath) ! message
  }

  // Test 4: Serialized message deserialization
  class DeserializingActor extends Actor {
    def receive: Receive = {
      case data: Array[Byte] =>
        // VULNERABLE: Deserializing untrusted bytes
        val ois = new java.io.ObjectInputStream(new java.io.ByteArrayInputStream(data))
        val obj = ois.readObject()
        processObject(obj)
      case _ => ()
    }

    private def processObject(obj: Any): Unit = ()
  }

  // Test 5: Actor state exposed
  class StatefulActor extends Actor {
    private var sensitiveData: String = "secret"

    def receive: Receive = {
      case "getState" =>
        // VULNERABLE: Exposing internal state
        sender() ! sensitiveData
      case s: String =>
        sensitiveData = s
    }
  }

  // Test 6: Unvalidated Props creation
  def createActor(system: ActorSystem, className: String): ActorRef = {
    // VULNERABLE: Class name from user
    val clazz = Class.forName(className)
    system.actorOf(Props(clazz))
  }

  // Test 7: Ask pattern timeout DoS
  def askWithTimeout(actor: ActorRef, message: Any, timeoutMs: Long): Any = {
    import akka.pattern.ask
    import scala.concurrent.duration._
    import scala.concurrent.Await
    // VULNERABLE: User-controlled timeout
    implicit val timeout: akka.util.Timeout = timeoutMs.milliseconds
    Await.result(actor ? message, timeout.duration)
  }

  // Test 8: Supervisor strategy bypass
  class UnsupervisedActor extends Actor {
    // VULNERABLE: No proper supervision
    override val supervisorStrategy: SupervisorStrategy = SupervisorStrategy.stoppingStrategy

    def receive: Receive = {
      case msg => processUnsafe(msg)
    }

    private def processUnsafe(msg: Any): Unit = ()
  }

  // Test 9: Actor name injection
  def createNamedActor(system: ActorSystem, name: String): ActorRef = {
    // VULNERABLE: Name from user could conflict or leak info
    system.actorOf(Props[SimpleActor](), name)
  }

  // Test 10: Cluster message broadcast
  def broadcastToCluster(message: Any): Unit = {
    // VULNERABLE: Broadcasting arbitrary messages to cluster
    // ClusterSingleton.send(message)
  }

  // Test 11: Persistence replay injection
  class PersistentVulnerable extends Actor {
    var state: List[String] = Nil

    def receive: Receive = {
      case cmd: String =>
        // VULNERABLE: Persisting user input without validation
        state = cmd :: state
    }
  }

  // Test 12: Router configuration injection
  def createRouter(system: ActorSystem, routees: Int): ActorRef = {
    // VULNERABLE: Number of routees from user (resource exhaustion)
    import akka.routing.RoundRobinPool
    system.actorOf(RoundRobinPool(routees).props(Props[SimpleActor]()))
  }

  // Test 13: Actor scheduling DoS
  def scheduleActor(system: ActorSystem, intervalMs: Long): Cancellable = {
    import scala.concurrent.duration._
    // VULNERABLE: User-controlled interval
    system.scheduler.scheduleWithFixedDelay(
      0.milliseconds,
      intervalMs.milliseconds,
      system.actorOf(Props[SimpleActor]()),
      "tick"
    )(system.dispatcher)
  }
}

class SimpleActor extends Actor {
  def receive: Receive = { case _ => () }
}
