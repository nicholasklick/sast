// Insecure Deserialization vulnerabilities in Groovy
package com.example.security

import java.io.*

class DeserializationVulnerabilities {

    // Test 1: Java ObjectInputStream
    def deserializeObject(byte[] data) {
        // VULNERABLE: Deserializing untrusted data
        def bis = new ByteArrayInputStream(data)
        def ois = new ObjectInputStream(bis)
        ois.readObject()
    }

    // Test 2: Base64 encoded serialized object
    def deserializeBase64(String encoded) {
        def data = encoded.decodeBase64()
        // VULNERABLE: Base64 decoded deserialization
        def bis = new ByteArrayInputStream(data)
        def ois = new ObjectInputStream(bis)
        ois.readObject()
    }

    // Test 3: File-based deserialization
    def loadObjectFromFile(String path) {
        // VULNERABLE: File could be tampered
        def fis = new FileInputStream(path)
        def ois = new ObjectInputStream(fis)
        ois.readObject()
    }

    // Test 4: Network deserialization
    def receiveObject(Socket socket) {
        // VULNERABLE: Network data deserialization
        def ois = new ObjectInputStream(socket.inputStream)
        ois.readObject()
    }

    // Test 5: Groovy evaluate (code injection)
    def evaluateCode(String code) {
        // VULNERABLE: Arbitrary code execution
        Eval.me(code)
    }

    // Test 6: GroovyShell evaluate
    def shellEvaluate(String script) {
        // VULNERABLE: Script from user
        def shell = new GroovyShell()
        shell.evaluate(script)
    }

    // Test 7: GroovyClassLoader
    def loadClass(String className, String code) {
        // VULNERABLE: Loading user-defined class
        def loader = new GroovyClassLoader()
        loader.parseClass(code)
    }

    // Test 8: Cookie deserialization
    def deserializeCookie(String cookieValue) {
        def data = cookieValue.decodeBase64()
        // VULNERABLE: Cookie data from client
        def bis = new ByteArrayInputStream(data)
        def ois = new ObjectInputStream(bis)
        ois.readObject()
    }

    // Test 9: JSON with type info
    def deserializeJson(String json) {
        // VULNERABLE: Type from JSON
        def slurper = new groovy.json.JsonSlurper()
        def parsed = slurper.parseText(json)
        if (parsed.type) {
            def clazz = Class.forName(parsed.type)
            clazz.newInstance(parsed.data)
        }
    }

    // Test 10: Message queue deserialization
    def processMessage(byte[] messageBody) {
        // VULNERABLE: Message from queue
        def bis = new ByteArrayInputStream(messageBody)
        def ois = new ObjectInputStream(bis)
        ois.readObject()
    }

    // Test 11: YAML deserialization
    def deserializeYaml(String yaml) {
        // VULNERABLE: YAML can deserialize arbitrary objects
        def yamlParser = new org.yaml.snakeyaml.Yaml()
        yamlParser.load(yaml)
    }

    // Test 12: Cache deserialization
    def getCachedObject(String key) {
        def cachedData = getFromCache(key)
        // VULNERABLE: Cache could be poisoned
        def bis = new ByteArrayInputStream(cachedData)
        def ois = new ObjectInputStream(bis)
        ois.readObject()
    }

    // Test 13: ConfigSlurper with user input
    def loadConfig(String configScript) {
        // VULNERABLE: ConfigSlurper executes Groovy
        def config = new ConfigSlurper()
        config.parse(configScript)
    }

    private byte[] getFromCache(String key) { new byte[0] }
}
