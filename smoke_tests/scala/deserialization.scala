// Insecure Deserialization vulnerabilities in Scala
package com.example.security

import java.io._
import java.util.Base64

class DeserializationVulnerabilities {

  // Test 1: Java ObjectInputStream
  def deserializeObject(data: Array[Byte]): Any = {
    // VULNERABLE: Deserializing untrusted data
    val bis = new ByteArrayInputStream(data)
    val ois = new ObjectInputStream(bis)
    ois.readObject()
  }

  // Test 2: Base64 encoded serialized object
  def deserializeBase64(encoded: String): Any = {
    val data = Base64.getDecoder.decode(encoded)
    // VULNERABLE: Base64 decoded deserialization
    val bis = new ByteArrayInputStream(data)
    val ois = new ObjectInputStream(bis)
    ois.readObject()
  }

  // Test 3: File-based deserialization
  def loadObjectFromFile(path: String): Any = {
    // VULNERABLE: File could be tampered
    val fis = new FileInputStream(path)
    val ois = new ObjectInputStream(fis)
    ois.readObject()
  }

  // Test 4: Network deserialization
  def receiveObject(socket: java.net.Socket): Any = {
    // VULNERABLE: Network data deserialization
    val ois = new ObjectInputStream(socket.getInputStream)
    ois.readObject()
  }

  // Test 5: Kryo deserialization
  def deserializeKryo(data: Array[Byte]): Any = {
    // VULNERABLE: No class registration in Kryo
    val kryo = new com.esotericsoftware.kryo.Kryo()
    kryo.setRegistrationRequired(false)
    val input = new com.esotericsoftware.kryo.io.Input(data)
    kryo.readClassAndObject(input)
  }

  // Test 6: Play JSON with type info
  def deserializePlayJson(json: String): Any = {
    // VULNERABLE: Type from JSON
    import play.api.libs.json._
    val parsed = Json.parse(json)
    val className = (parsed \ "type").as[String]
    val clazz = Class.forName(className)
    // Deserialize with type
    parsed
  }

  // Test 7: Pickle deserialization
  def deserializePickle(data: Array[Byte]): Any = {
    // VULNERABLE: Scala pickling
    // scala.pickling.Unpickle[Any].fromBytes(data)
    deserializeObject(data)
  }

  // Test 8: Akka serialization
  def deserializeAkka(data: Array[Byte]): Any = {
    // VULNERABLE: Akka serialization from untrusted source
    // system.serialization.deserialize(data, classOf[Any])
    deserializeObject(data)
  }

  // Test 9: Cookie deserialization
  def deserializeCookie(cookieValue: String): Any = {
    val data = Base64.getDecoder.decode(cookieValue)
    // VULNERABLE: Cookie data from client
    val bis = new ByteArrayInputStream(data)
    val ois = new ObjectInputStream(bis)
    ois.readObject()
  }

  // Test 10: Message queue deserialization
  def processMessage(messageBody: Array[Byte]): Any = {
    // VULNERABLE: Message from queue
    val bis = new ByteArrayInputStream(messageBody)
    val ois = new ObjectInputStream(bis)
    ois.readObject()
  }

  // Test 11: Cache deserialization
  def getCachedObject(key: String): Any = {
    val cachedData = getFromCache(key)
    // VULNERABLE: Cache could be poisoned
    val bis = new ByteArrayInputStream(cachedData)
    val ois = new ObjectInputStream(bis)
    ois.readObject()
  }

  // Test 12: circe JSON with runtime types
  def deserializeCirce(json: String, typeName: String): Any = {
    // VULNERABLE: Type name from user
    val clazz = Class.forName(typeName)
    // io.circe.parser.decode(json)(decoder)
    json
  }

  private def getFromCache(key: String): Array[Byte] = Array.empty
}
