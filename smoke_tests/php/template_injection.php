<?php
// Template Injection vulnerabilities in PHP

// Test 1: eval with user input
function eval_template() {
    $code = $_GET['code'];
    // VULNERABLE: Direct code execution
    eval($code);
}

// Test 2: Twig without sandbox
function twig_render() {
    $template = $_POST['template'];
    $loader = new \Twig\Loader\ArrayLoader([
        'template' => $template
    ]);
    $twig = new \Twig\Environment($loader);
    // VULNERABLE: User controls template
    echo $twig->render('template');
}

// Test 3: Blade template injection
function blade_render() {
    $template = $_POST['template'];
    // VULNERABLE: If template contains {{}} or @php directives
    // return view()->make('template', ['content' => $template]);
    // Pseudo-code - actual implementation depends on Laravel
}

// Test 4: Smarty template injection
function smarty_render() {
    $template = $_POST['template'];
    $smarty = new Smarty();
    // VULNERABLE: User controls template with {php} tags
    $smarty->display("string:$template");
}

// Test 5: preg_replace with /e modifier (deprecated)
function preg_e_modifier() {
    $input = $_GET['input'];
    $pattern = $_GET['pattern'];
    $replacement = $_GET['replacement'];
    // VULNERABLE: /e modifier executes replacement as code
    // echo preg_replace("/$pattern/e", $replacement, $input);  // Deprecated
}

// Test 6: create_function (deprecated)
function dynamic_function() {
    $body = $_POST['body'];
    // VULNERABLE: Code execution
    // $func = create_function('$x', $body);  // Deprecated
    // return $func(1);
}

// Test 7: Variable variable injection
function variable_injection() {
    $name = $_GET['name'];
    $value = $_GET['value'];
    // VULNERABLE: Can overwrite any variable
    $$name = $value;
}

// Test 8: extract() with user data
function extract_injection() {
    // VULNERABLE: Can overwrite any variable
    extract($_POST);
    // Variables from POST are now in scope
}

// Test 9: assert with user input (deprecated behavior)
function assert_injection() {
    $assertion = $_GET['assertion'];
    // VULNERABLE: Code execution in older PHP
    // assert($assertion);  // Can execute code in PHP < 7
}

// Test 10: sprintf format injection
function sprintf_injection() {
    $format = $_GET['format'];
    $data = ['secret' => 'password123'];
    // VULNERABLE: %s$s can leak data
    printf($format, ...$data);
}

// Test 11: Mustache template injection
function mustache_render() {
    $template = $_POST['template'];
    $data = ['user' => 'admin'];
    $mustache = new Mustache_Engine();
    // Mustache is generally safe, but showing for completeness
    echo $mustache->render($template, $data);
}

// Test 12: PHP include as template
function php_template() {
    $template = $_GET['template'];
    // VULNERABLE: User controls included PHP file
    include("templates/$template.php");
}

// Test 13: sprintf with user format string
function format_string() {
    $format = $_POST['format'];
    $args = $_POST['args'];
    // VULNERABLE: Format string vulnerabilities
    vprintf($format, $args);
}

// Test 14: Output buffering with eval
function buffer_eval() {
    $code = $_POST['code'];
    ob_start();
    // VULNERABLE: Code execution
    eval("echo $code;");
    return ob_get_clean();
}
?>
