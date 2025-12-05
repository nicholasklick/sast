// Unsafe Reflection vulnerabilities in Swift
import Foundation

class UnsafeReflectionVulnerabilities {

    // Test 1: NSClassFromString with user input
    func instantiateClass(className: String) -> AnyObject? {
        // VULNERABLE: Class name from user
        guard let classType = NSClassFromString(className) as? NSObject.Type else {
            return nil
        }
        return classType.init()
    }

    // Test 2: Selector from string
    func callMethod(object: NSObject, methodName: String) {
        // VULNERABLE: Selector from user input
        let selector = NSSelectorFromString(methodName)
        if object.responds(to: selector) {
            object.perform(selector)
        }
    }

    // Test 3: Dynamic type instantiation
    func createHandler(handlerType: String) -> RequestHandler? {
        // VULNERABLE: Handler type from config/user
        let fullClassName = "App.\(handlerType)Handler"
        guard let classType = NSClassFromString(fullClassName) as? RequestHandler.Type else {
            return nil
        }
        return classType.init()
    }

    // Test 4: Property access via key path
    func getProperty(object: NSObject, propertyName: String) -> Any? {
        // VULNERABLE: Property name from user
        return object.value(forKey: propertyName)
    }

    // Test 5: Set property via key path
    func setProperty(object: NSObject, propertyName: String, value: Any) {
        // VULNERABLE: Setting arbitrary properties
        object.setValue(value, forKey: propertyName)
    }

    // Test 6: KVC key path traversal
    func getNestedValue(object: NSObject, keyPath: String) -> Any? {
        // VULNERABLE: Key path from user
        return object.value(forKeyPath: keyPath)
    }

    // Test 7: Dynamic module loading
    func loadModule(moduleName: String) {
        // VULNERABLE: Module name from user
        let bundlePath = Bundle.main.bundlePath + "/\(moduleName).bundle"
        if let bundle = Bundle(path: bundlePath) {
            bundle.load()
        }
    }

    // Test 8: Protocol conformance check
    func checkConformance(className: String, protocolName: String) -> Bool {
        // VULNERABLE: Both from user
        guard let classType = NSClassFromString(className),
              let proto = NSProtocolFromString(protocolName) else {
            return false
        }
        return classType.conforms(to: proto)
    }

    // Test 9: Method invocation with arguments
    func invokeMethod(object: NSObject, method: String, arg: Any) -> Any? {
        // VULNERABLE: Method from user
        let selector = NSSelectorFromString(method)
        if object.responds(to: selector) {
            return object.perform(selector, with: arg)?.takeUnretainedValue()
        }
        return nil
    }

    // Test 10: Factory pattern with user type
    func createObject(typeName: String) -> Any? {
        // VULNERABLE: Type from request parameter
        let types: [String: () -> Any] = [
            "User": { User() },
            "Admin": { Admin() }
        ]
        // Attacker might try: ../../../etc/passwd
        return types[typeName]?()
    }

    // Test 11: Runtime method addition
    func addMethod(className: String, methodName: String, implementation: IMP) {
        // VULNERABLE: Adding methods dynamically
        guard let classType = NSClassFromString(className) else { return }
        let selector = NSSelectorFromString(methodName)
        class_addMethod(classType, selector, implementation, "v@:")
    }

    // Test 12: Swizzling with user input
    func swizzleMethod(className: String, original: String, replacement: String) {
        // VULNERABLE: Swizzling arbitrary methods
        guard let classType = NSClassFromString(className) else { return }
        let originalSelector = NSSelectorFromString(original)
        let replacementSelector = NSSelectorFromString(replacement)

        if let originalMethod = class_getInstanceMethod(classType, originalSelector),
           let replacementMethod = class_getInstanceMethod(classType, replacementSelector) {
            method_exchangeImplementations(originalMethod, replacementMethod)
        }
    }
}

class RequestHandler: NSObject {
    required override init() {
        super.init()
    }
}

class User {}
class Admin {}
