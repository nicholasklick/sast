// Insecure Deserialization vulnerabilities in Kotlin
package com.example.security

import java.io.*
import java.util.Base64
import com.fasterxml.jackson.databind.ObjectMapper
import com.google.gson.Gson

class DeserializationVulnerabilities {

    private val objectMapper = ObjectMapper()
    private val gson = Gson()

    // Test 1: Java ObjectInputStream
    fun deserializeObject(data: ByteArray): Any? {
        // VULNERABLE: Deserializing untrusted data
        val bis = ByteArrayInputStream(data)
        val ois = ObjectInputStream(bis)
        return ois.readObject()
    }

    // Test 2: Base64 encoded serialized object
    fun deserializeBase64(encoded: String): Any? {
        val data = Base64.getDecoder().decode(encoded)
        // VULNERABLE: Base64 decoded deserialization
        val bis = ByteArrayInputStream(data)
        val ois = ObjectInputStream(bis)
        return ois.readObject()
    }

    // Test 3: File-based deserialization
    fun loadObjectFromFile(path: String): Any? {
        // VULNERABLE: File could be tampered
        val fis = FileInputStream(path)
        val ois = ObjectInputStream(fis)
        return ois.readObject()
    }

    // Test 4: Network deserialization
    fun receiveObject(socket: java.net.Socket): Any? {
        // VULNERABLE: Network data deserialization
        val ois = ObjectInputStream(socket.getInputStream())
        return ois.readObject()
    }

    // Test 5: Jackson with type info
    fun deserializeJson(json: String): Any {
        // VULNERABLE: Default typing enabled
        objectMapper.enableDefaultTyping()
        return objectMapper.readValue(json, Any::class.java)
    }

    // Test 6: Jackson polymorphic
    fun deserializePolymorphic(json: String, typeField: String): Any {
        // VULNERABLE: Type from JSON
        val node = objectMapper.readTree(json)
        val className = node.get(typeField).asText()
        val clazz = Class.forName(className)
        return objectMapper.readValue(json, clazz)
    }

    // Test 7: YAML deserialization
    fun deserializeYaml(yaml: String): Any {
        // VULNERABLE: YAML can deserialize arbitrary objects
        val yamlParser = org.yaml.snakeyaml.Yaml()
        return yamlParser.load(yaml)
    }

    // Test 8: XML deserialization with XStream
    fun deserializeXml(xml: String): Any {
        // VULNERABLE: XStream default allows arbitrary types
        val xstream = com.thoughtworks.xstream.XStream()
        return xstream.fromXML(xml)
    }

    // Test 9: Cookie deserialization
    fun deserializeCookie(cookieValue: String): Any? {
        val data = Base64.getDecoder().decode(cookieValue)
        // VULNERABLE: Cookie data from client
        val bis = ByteArrayInputStream(data)
        val ois = ObjectInputStream(bis)
        return ois.readObject()
    }

    // Test 10: Session deserialization
    fun deserializeSession(sessionData: ByteArray): Map<String, Any>? {
        // VULNERABLE: Session data could be manipulated
        val bis = ByteArrayInputStream(sessionData)
        val ois = ObjectInputStream(bis)
        @Suppress("UNCHECKED_CAST")
        return ois.readObject() as? Map<String, Any>
    }

    // Test 11: Message queue deserialization
    fun processMessage(messageBody: ByteArray): Any? {
        // VULNERABLE: Message from queue
        val bis = ByteArrayInputStream(messageBody)
        val ois = ObjectInputStream(bis)
        return ois.readObject()
    }

    // Test 12: Kryo deserialization
    fun deserializeKryo(data: ByteArray): Any {
        val kryo = com.esotericsoftware.kryo.Kryo()
        // VULNERABLE: No class registration
        kryo.isRegistrationRequired = false
        val input = com.esotericsoftware.kryo.io.Input(data)
        return kryo.readClassAndObject(input)
    }

    // Test 13: Cache deserialization
    fun getCachedObject(key: String): Any? {
        val cachedData = getFromCache(key)
        // VULNERABLE: Cache could be poisoned
        val bis = ByteArrayInputStream(cachedData)
        val ois = ObjectInputStream(bis)
        return ois.readObject()
    }

    private fun getFromCache(key: String): ByteArray = byteArrayOf()
}
