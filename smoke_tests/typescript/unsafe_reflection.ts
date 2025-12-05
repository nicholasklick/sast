// Unsafe Reflection Test Cases

// Test 1: Dynamic property access with user input
function getObjectProperty(obj: any, propertyName: string): any {
    // VULNERABLE: propertyName could be "__proto__" or "constructor"
    return obj[propertyName];
}

// Test 2: Dynamic method invocation
function invokeMethod(obj: any, methodName: string, args: any[]): any {
    // VULNERABLE: methodName is user-controlled
    return obj[methodName](...args);
}

// Test 3: Dynamic require/import
function loadModule(moduleName: string): any {
    // VULNERABLE: moduleName could load arbitrary modules
    return require(moduleName);
}

// Test 4: Dynamic class instantiation
function createInstance(className: string, args: any[]): any {
    // VULNERABLE: className could reference any global constructor
    const Constructor = (global as any)[className];
    return new Constructor(...args);
}

// Test 5: Accessing nested properties via path
function getNestedProperty(obj: any, path: string): any {
    const parts = path.split('.');
    let current = obj;
    // VULNERABLE: path could traverse to dangerous properties
    for (const part of parts) {
        current = current[part];
    }
    return current;
}
