<?php
// Unsafe Reflection vulnerabilities in PHP

// Test 1: Dynamic class instantiation
function load_class() {
    $class_name = $_GET['class'];
    // VULNERABLE: User controls class instantiation
    $instance = new $class_name();
    return $instance;
}

// Test 2: ReflectionClass with user input
function reflect_class() {
    $class_name = $_GET['class'];
    // VULNERABLE: User controls reflection
    $reflection = new ReflectionClass($class_name);
    return $reflection->getMethods();
}

// Test 3: Dynamic method call
function invoke_method() {
    $class = $_POST['class'];
    $method = $_POST['method'];

    $instance = new $class();
    // VULNERABLE: User controls method invocation
    return $instance->$method();
}

// Test 4: call_user_func with user input
function call_function() {
    $callback = $_GET['callback'];
    $args = $_GET['args'] ?? [];
    // VULNERABLE: User controls function call
    return call_user_func($callback, ...$args);
}

// Test 5: call_user_func_array
function call_function_array() {
    $function = $_POST['function'];
    $arguments = $_POST['arguments'];
    // VULNERABLE: User controls function and args
    return call_user_func_array($function, $arguments);
}

// Test 6: ReflectionMethod invoke
function reflect_invoke() {
    $class = $_GET['class'];
    $method = $_GET['method'];

    $instance = new $class();
    $reflection = new ReflectionMethod($class, $method);
    // VULNERABLE: Invoking user-specified method
    return $reflection->invoke($instance);
}

// Test 7: Property access by name
function get_property() {
    $class = $_GET['class'];
    $property = $_GET['property'];

    $instance = new $class();
    // VULNERABLE: User controls property access
    return $instance->$property;
}

// Test 8: ReflectionProperty access
function reflect_property() {
    $class = $_GET['class'];
    $property = $_GET['property'];

    $instance = new $class();
    $reflection = new ReflectionProperty($class, $property);
    $reflection->setAccessible(true);
    // VULNERABLE: Accessing private properties
    return $reflection->getValue($instance);
}

// Test 9: class_exists check bypass
function create_instance() {
    $class = $_GET['class'];
    // VULNERABLE: class_exists doesn't prevent malicious instantiation
    if (class_exists($class)) {
        return new $class();
    }
}

// Test 10: Forward static call
function static_call() {
    $class = $_POST['class'];
    $method = $_POST['method'];
    $args = $_POST['args'] ?? [];
    // VULNERABLE: User controls static method call
    return forward_static_call([$class, $method], ...$args);
}

// Test 11: Variable function call
function variable_function() {
    $func = $_GET['func'];
    // VULNERABLE: User controls function execution
    return $func();
}

// Test 12: Create function (deprecated but still risky)
function create_func() {
    $code = $_POST['code'];
    // VULNERABLE: Code execution
    // $func = create_function('$x', $code);  // Deprecated
    // return $func(1);
}

// Test 13: Instantiate with constructor args
function create_with_args() {
    $class = $_GET['class'];
    $args = $_GET['args'] ?? [];
    // VULNERABLE: User controls class and constructor
    $reflection = new ReflectionClass($class);
    return $reflection->newInstanceArgs($args);
}
?>
