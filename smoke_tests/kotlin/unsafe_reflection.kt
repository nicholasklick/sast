// Unsafe Reflection vulnerabilities in Kotlin
package com.example.security

import java.lang.reflect.Method

class UnsafeReflectionVulnerabilities {

    // Test 1: Class.forName with user input
    fun instantiateClass(className: String): Any? {
        // VULNERABLE: Class name from user
        val clazz = Class.forName(className)
        return clazz.getDeclaredConstructor().newInstance()
    }

    // Test 2: Method invocation by name
    fun invokeMethod(obj: Any, methodName: String): Any? {
        // VULNERABLE: Method name from user
        val method = obj.javaClass.getMethod(methodName)
        return method.invoke(obj)
    }

    // Test 3: Dynamic handler creation
    fun createHandler(handlerType: String): RequestHandler? {
        // VULNERABLE: Handler type from config
        val fullClassName = "com.example.handlers.${handlerType}Handler"
        val clazz = Class.forName(fullClassName)
        return clazz.getDeclaredConstructor().newInstance() as? RequestHandler
    }

    // Test 4: Property access via reflection
    fun getProperty(obj: Any, propertyName: String): Any? {
        // VULNERABLE: Property name from user
        val field = obj.javaClass.getDeclaredField(propertyName)
        field.isAccessible = true
        return field.get(obj)
    }

    // Test 5: Set property via reflection
    fun setProperty(obj: Any, propertyName: String, value: Any) {
        // VULNERABLE: Setting arbitrary properties
        val field = obj.javaClass.getDeclaredField(propertyName)
        field.isAccessible = true
        field.set(obj, value)
    }

    // Test 6: Method with arguments
    fun invokeMethodWithArgs(obj: Any, methodName: String, vararg args: Any): Any? {
        // VULNERABLE: Method and args from user
        val paramTypes = args.map { it.javaClass }.toTypedArray()
        val method = obj.javaClass.getMethod(methodName, *paramTypes)
        return method.invoke(obj, *args)
    }

    // Test 7: Dynamic module loading
    fun loadPlugin(pluginName: String) {
        // VULNERABLE: Plugin name from user
        val className = "com.example.plugins.$pluginName"
        val clazz = Class.forName(className)
        val plugin = clazz.getDeclaredConstructor().newInstance() as Plugin
        plugin.initialize()
    }

    // Test 8: Annotation-based instantiation
    fun createFromAnnotation(annotationValue: String): Any? {
        // VULNERABLE: Class from annotation value
        return Class.forName(annotationValue).getDeclaredConstructor().newInstance()
    }

    // Test 9: Service loader bypass
    fun loadService(serviceName: String): Any? {
        // VULNERABLE: Service name from user
        val serviceClass = Class.forName(serviceName)
        return java.util.ServiceLoader.load(serviceClass).firstOrNull()
    }

    // Test 10: Private method access
    fun invokePrivateMethod(obj: Any, methodName: String): Any? {
        // VULNERABLE: Bypassing access control
        val method = obj.javaClass.getDeclaredMethod(methodName)
        method.isAccessible = true
        return method.invoke(obj)
    }

    // Test 11: Constructor injection
    fun createWithConstructor(className: String, vararg args: Any): Any? {
        // VULNERABLE: Class and args from user
        val clazz = Class.forName(className)
        val paramTypes = args.map { it.javaClass }.toTypedArray()
        val constructor = clazz.getConstructor(*paramTypes)
        return constructor.newInstance(*args)
    }

    // Test 12: Static method invocation
    fun invokeStatic(className: String, methodName: String): Any? {
        // VULNERABLE: Both from user
        val clazz = Class.forName(className)
        val method = clazz.getMethod(methodName)
        return method.invoke(null)
    }

    // Test 13: Kotlin reflection
    fun getKotlinProperty(obj: Any, propertyName: String): Any? {
        // VULNERABLE: Property name from user
        val kClass = obj::class
        val property = kClass.members.find { it.name == propertyName }
        return property?.call(obj)
    }
}

interface RequestHandler
interface Plugin {
    fun initialize()
}
