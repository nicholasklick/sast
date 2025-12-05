// Unsafe Reflection vulnerabilities in Groovy
package com.example.security

class UnsafeReflectionVulnerabilities {

    // Test 1: Class.forName with user input
    def instantiateClass(String className) {
        // VULNERABLE: Class name from user
        def clazz = Class.forName(className)
        clazz.getDeclaredConstructor().newInstance()
    }

    // Test 2: Method invocation by name
    def invokeMethod(Object obj, String methodName) {
        // VULNERABLE: Method name from user
        obj."${methodName}"()
    }

    // Test 3: Groovy dynamic method call
    def dynamicCall(Object obj, String method, Object[] args) {
        // VULNERABLE: Method and args from user
        obj.invokeMethod(method, args)
    }

    // Test 4: Property access via name
    def getProperty(Object obj, String propertyName) {
        // VULNERABLE: Property name from user
        obj."${propertyName}"
    }

    // Test 5: Set property via name
    void setProperty(Object obj, String propertyName, Object value) {
        // VULNERABLE: Setting arbitrary properties
        obj."${propertyName}" = value
    }

    // Test 6: MetaClass manipulation
    void addMethod(Object obj, String methodName, Closure impl) {
        // VULNERABLE: Adding methods dynamically
        obj.metaClass."${methodName}" = impl
    }

    // Test 7: GroovyClassLoader
    def loadClass(String className, String code) {
        // VULNERABLE: Loading user-defined class
        def loader = new GroovyClassLoader()
        loader.parseClass(code)
    }

    // Test 8: Dynamic handler creation
    def createHandler(String handlerType) {
        // VULNERABLE: Handler type from config
        def fullClassName = "com.example.handlers.${handlerType}Handler"
        Class.forName(fullClassName).getDeclaredConstructor().newInstance()
    }

    // Test 9: GPath expression
    def evaluateGPath(Object root, String path) {
        // VULNERABLE: Path from user
        Eval.x(root, "x.${path}")
    }

    // Test 10: Closure.call with user method
    def closureCall(Object obj, String methodName) {
        // VULNERABLE: Method closure from user
        def closure = obj.&"${methodName}"
        closure.call()
    }

    // Test 11: Static method invocation
    def invokeStatic(String className, String methodName) {
        // VULNERABLE: Both from user
        def clazz = Class.forName(className)
        clazz."${methodName}"()
    }

    // Test 12: Grails domain class (conceptual)
    def findByDynamicMethod(String domainClass, String property, Object value) {
        // VULNERABLE: Dynamic finder method
        def clazz = Class.forName("com.example.domain.${domainClass}")
        clazz."findBy${property.capitalize()}"(value)
    }

    // Test 13: Builder pattern with user class
    def buildObject(String builderClass, Map properties) {
        // VULNERABLE: Builder class from user
        def builder = Class.forName(builderClass).getDeclaredConstructor().newInstance()
        properties.each { key, value ->
            builder."${key}"(value)
        }
        builder.build()
    }
}
