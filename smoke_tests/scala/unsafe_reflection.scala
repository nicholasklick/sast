// Unsafe Reflection vulnerabilities in Scala
package com.example.security

import scala.reflect.runtime.universe._

class UnsafeReflectionVulnerabilities {

  // Test 1: Class.forName with user input
  def instantiateClass(className: String): Any = {
    // VULNERABLE: Class name from user
    val clazz = Class.forName(className)
    clazz.getDeclaredConstructor().newInstance()
  }

  // Test 2: Method invocation by name
  def invokeMethod(obj: Any, methodName: String): Any = {
    // VULNERABLE: Method name from user
    val method = obj.getClass.getMethod(methodName)
    method.invoke(obj)
  }

  // Test 3: Dynamic handler creation
  def createHandler(handlerType: String): RequestHandler = {
    // VULNERABLE: Handler type from config
    val fullClassName = s"com.example.handlers.${handlerType}Handler"
    val clazz = Class.forName(fullClassName)
    clazz.getDeclaredConstructor().newInstance().asInstanceOf[RequestHandler]
  }

  // Test 4: Property access via reflection
  def getProperty(obj: Any, propertyName: String): Any = {
    // VULNERABLE: Property name from user
    val field = obj.getClass.getDeclaredField(propertyName)
    field.setAccessible(true)
    field.get(obj)
  }

  // Test 5: Set property via reflection
  def setProperty(obj: Any, propertyName: String, value: Any): Unit = {
    // VULNERABLE: Setting arbitrary properties
    val field = obj.getClass.getDeclaredField(propertyName)
    field.setAccessible(true)
    field.set(obj, value)
  }

  // Test 6: Scala reflection with TypeTag
  def instantiateWithTypeTag[T: TypeTag](className: String): Any = {
    // VULNERABLE: Class from user with type info
    val mirror = runtimeMirror(getClass.getClassLoader)
    val clazz = Class.forName(className)
    clazz.getDeclaredConstructor().newInstance()
  }

  // Test 7: Dynamic module loading
  def loadPlugin(pluginName: String): Unit = {
    // VULNERABLE: Plugin name from user
    val className = s"com.example.plugins.$pluginName"
    val clazz = Class.forName(className)
    val plugin = clazz.getDeclaredConstructor().newInstance().asInstanceOf[Plugin]
    plugin.initialize()
  }

  // Test 8: Method with arguments
  def invokeMethodWithArgs(obj: Any, methodName: String, args: Array[Any]): Any = {
    // VULNERABLE: Method and args from user
    val paramTypes = args.map(_.getClass)
    val method = obj.getClass.getMethod(methodName, paramTypes: _*)
    method.invoke(obj, args.map(_.asInstanceOf[AnyRef]): _*)
  }

  // Test 9: Private method access
  def invokePrivateMethod(obj: Any, methodName: String): Any = {
    // VULNERABLE: Bypassing access control
    val method = obj.getClass.getDeclaredMethod(methodName)
    method.setAccessible(true)
    method.invoke(obj)
  }

  // Test 10: Constructor injection
  def createWithConstructor(className: String, args: Array[Any]): Any = {
    // VULNERABLE: Class and args from user
    val clazz = Class.forName(className)
    val paramTypes = args.map(_.getClass)
    val constructor = clazz.getConstructor(paramTypes: _*)
    constructor.newInstance(args.map(_.asInstanceOf[AnyRef]): _*)
  }

  // Test 11: Static method invocation
  def invokeStatic(className: String, methodName: String): Any = {
    // VULNERABLE: Both from user
    val clazz = Class.forName(className)
    val method = clazz.getMethod(methodName)
    method.invoke(null)
  }

  // Test 12: Scala structural type reflection
  def callStructural(obj: Any, methodName: String): Any = {
    // VULNERABLE: Structural type with user method
    val method = obj.getClass.getMethod(methodName)
    method.invoke(obj)
  }

  // Test 13: Macro-based reflection (conceptual)
  def macroReflection(typeName: String): Any = {
    // VULNERABLE: Type from user in macro context
    Class.forName(typeName).getDeclaredConstructor().newInstance()
  }
}

trait RequestHandler
trait Plugin {
  def initialize(): Unit
}
