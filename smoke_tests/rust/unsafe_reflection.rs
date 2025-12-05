// Unsafe Reflection Test Cases

use std::collections::HashMap;

// Test 1: Dynamic property access with user input
fn get_object_property(obj: &HashMap<String, String>, property_name: &str) -> Option<&String> {
    // VULNERABLE: property_name is user-controlled
    obj.get(property_name)
}

// Test 2: Dynamic method invocation using function pointers
fn invoke_method(method_name: &str) -> Result<(), String> {
    // VULNERABLE: method_name is user-controlled
    match method_name {
        "safe_method" => Ok(()),
        "dangerous_method" => Ok(()), // Could execute dangerous code
        _ => Err("Unknown method".to_string())
    }
}

// Test 3: Dynamic module loading
fn load_library(lib_name: &str) -> Result<(), String> {
    use libloading::Library;

    // VULNERABLE: lib_name could load arbitrary shared libraries
    unsafe {
        let _lib = Library::new(lib_name)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

// Test 4: Dynamic type construction
fn create_instance(type_name: &str) -> Box<dyn std::any::Any> {
    // VULNERABLE: type_name could reference any type
    match type_name {
        "String" => Box::new(String::new()),
        "Vec" => Box::new(Vec::<i32>::new()),
        _ => Box::new(())
    }
}

// Test 5: Accessing nested properties via path
fn get_nested_property(obj: &serde_json::Value, path: &str) -> Option<&serde_json::Value> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = obj;

    // VULNERABLE: path could traverse to dangerous properties
    for part in parts {
        current = current.get(part)?;
    }

    Some(current)
}
