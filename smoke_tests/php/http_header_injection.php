<?php
// HTTP Header Injection vulnerabilities in PHP

// Test 1: Header injection via Location
function redirect_header() {
    $target = $_GET['target'];
    // VULNERABLE: CRLF can inject headers
    header("Location: $target");
    exit;
}

// Test 2: Cookie value injection
function set_cookie_value() {
    $value = $_GET['value'];
    // VULNERABLE: Value can contain CRLF
    setcookie('session', $value);
}

// Test 3: Content-Disposition header
function download_filename() {
    $filename = $_GET['filename'];
    // VULNERABLE: Filename can contain CRLF
    header("Content-Disposition: attachment; filename=\"$filename\"");
    echo "content";
}

// Test 4: Custom header
function custom_header() {
    $header_value = $_GET['header'];
    // VULNERABLE: User controls header value
    header("X-Custom-Header: $header_value");
}

// Test 5: Cache-Control injection
function set_cache() {
    $directive = $_GET['cache'];
    // VULNERABLE: User controls caching
    header("Cache-Control: $directive");
}

// Test 6: CORS header injection
function cors_response() {
    $origin = $_SERVER['HTTP_ORIGIN'];
    // VULNERABLE: Reflecting origin without validation
    header("Access-Control-Allow-Origin: $origin");
    header("Access-Control-Allow-Credentials: true");
    echo json_encode(['data' => 'sensitive']);
}

// Test 7: WWW-Authenticate header
function require_auth() {
    $realm = $_GET['realm'];
    // VULNERABLE: Realm from user input
    header("WWW-Authenticate: Basic realm=\"$realm\"");
    http_response_code(401);
}

// Test 8: Link header injection
function add_link_header() {
    $url = $_GET['preload'];
    // VULNERABLE: URL in Link header
    header("Link: <$url>; rel=preload");
}

// Test 9: Content-Type header
function set_content_type() {
    $content_type = $_GET['type'];
    // VULNERABLE: User controls content type
    header("Content-Type: $content_type");
    echo "data";
}

// Test 10: Set-Cookie via header()
function raw_cookie() {
    $name = $_GET['name'];
    $value = $_GET['value'];
    // VULNERABLE: Can inject additional cookies or headers
    header("Set-Cookie: $name=$value");
}

// Test 11: X-Forwarded-For reflection
function log_ip() {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    // VULNERABLE: Header reflected back
    header("X-Client-IP: $ip");
}

// Test 12: Multiple headers injection
function multi_header() {
    $data = $_GET['data'];
    // VULNERABLE: CRLF injection
    header("X-Data: $data");
    header("X-Timestamp: " . time());
    echo "response";
}
?>
