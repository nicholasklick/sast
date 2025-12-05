<?php
// Open Redirect vulnerabilities in PHP

// Test 1: Direct redirect from parameter
function redirect_unsafe() {
    $url = $_GET['url'];
    // VULNERABLE: Unvalidated redirect
    header("Location: $url");
    exit;
}

// Test 2: Redirect after login
function login_redirect() {
    // Authenticate user...
    $return_url = $_GET['return'];
    // VULNERABLE: Can redirect to external site
    header("Location: $return_url");
    exit;
}

// Test 3: Partial validation bypass
function safe_redirect() {
    $url = $_GET['url'];
    // VULNERABLE: Can bypass with //evil.com
    if (strpos($url, '/') === 0) {
        header("Location: $url");
        exit;
    }
}

// Test 4: Cookie-based redirect
function cookie_redirect() {
    $target = $_COOKIE['redirect_target'];
    // VULNERABLE: Cookie can be manipulated
    if (!empty($target)) {
        header("Location: $target");
        exit;
    }
}

// Test 5: Header-based redirect
function referer_redirect() {
    $referer = $_SERVER['HTTP_X_RETURN_URL'];
    // VULNERABLE: Header from client
    if ($referer) {
        header("Location: $referer");
        exit;
    }
}

// Test 6: Domain validation bypass
function domain_check() {
    $url = $_GET['url'];
    // VULNERABLE: evil.example.com contains example.com
    if (strpos($url, 'example.com') !== false) {
        header("Location: $url");
        exit;
    }
}

// Test 7: JavaScript redirect
function js_redirect() {
    $url = $_GET['url'];
    // VULNERABLE: JavaScript redirect
    echo "<script>window.location='{$url}';</script>";
}

// Test 8: Meta refresh redirect
function meta_redirect() {
    $target = $_GET['target'];
    // VULNERABLE: Meta refresh with user URL
    echo "<meta http-equiv='refresh' content='0;url={$target}'>";
}

// Test 9: URL from database
function dynamic_redirect() {
    $name = $_GET['name'];
    // Assume $url comes from database based on user input
    $url = get_redirect_url_from_db($name);
    // VULNERABLE: If database value came from user input
    header("Location: $url");
    exit;
}

// Test 10: PHP header with newlines
function header_injection() {
    $url = $_GET['url'];
    // VULNERABLE: URL can contain CRLF
    header("Location: " . $url);
    exit;
}

// Test 11: URL encoding bypass
function encoded_redirect() {
    $url = urldecode($_GET['url']);
    // VULNERABLE: Double encoding bypass
    if (strpos($url, '/') === 0) {
        header("Location: $url");
        exit;
    }
}

// Test 12: WordPress-style redirect
function wp_redirect() {
    $location = $_GET['redirect_to'];
    // VULNERABLE: Like wp_redirect without validation
    if (!empty($location)) {
        header("Location: $location", true, 302);
        exit;
    }
}

function get_redirect_url_from_db($name) {
    // Placeholder
    return '/default';
}
?>
