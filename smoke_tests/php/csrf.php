<?php
// Cross-Site Request Forgery (CSRF) vulnerabilities in PHP

// Test 1: No CSRF token on form
function transfer_funds() {
    // VULNERABLE: No CSRF token validation
    $amount = $_POST['amount'];
    $to_account = $_POST['to_account'];
    process_transfer($amount, $to_account);
}

// Test 2: State change via GET
function delete_account() {
    $id = $_GET['id'];
    // VULNERABLE: DELETE via GET request
    delete_user($id);
    header('Location: /');
}

// Test 3: Predictable token
function get_csrf_token() {
    // VULNERABLE: Predictable token
    return md5($_SESSION['user_id'] . 'secret');
}

// Test 4: Token validation bypass
function validate_csrf() {
    $token = $_POST['csrf_token'];
    // VULNERABLE: Empty token accepted
    if (empty($token) || $token === $_SESSION['csrf_token']) {
        return true;
    }
    return false;
}

// Test 5: Token not tied to session
function generate_weak_token() {
    // VULNERABLE: Token not tied to session
    return bin2hex(random_bytes(16));
    // Should be: hash('sha256', session_id() . random_bytes(16))
}

// Test 6: CORS misconfiguration allowing CSRF
function cors_endpoint() {
    // VULNERABLE: CORS allows any origin with credentials
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Credentials: true');
    echo json_encode(['data' => 'sensitive']);
}

// Test 7: Cookie without SameSite
function set_auth_cookie() {
    // VULNERABLE: No SameSite attribute (pre PHP 7.3 style)
    setcookie('auth', 'value', time() + 3600, '/', '', true, true);
    // Missing SameSite
}

// Test 8: Admin action without CSRF
function promote_user() {
    // VULNERABLE: Admin action without protection
    $user_id = $_POST['user_id'];
    set_user_role($user_id, 'admin');
}

// Test 9: Token in query string
function process_payment() {
    $token = $_GET['csrf_token'];
    // VULNERABLE: Token in URL can leak via Referer
    if (validate_token($token)) {
        process_payment_internal();
    }
}

// Test 10: JSON endpoint without CSRF
function api_update() {
    // VULNERABLE: JSON requests need CSRF too
    $data = json_decode(file_get_contents('php://input'), true);
    update_user_profile($data);
}

// Test 11: Token reuse
function reusable_token() {
    // VULNERABLE: Token should be single-use
    $token = $_POST['csrf_token'];
    if ($token === $_SESSION['csrf_token']) {
        // Process - but token remains valid
        return true;
    }
    return false;
}

// Test 12: Referrer-based CSRF protection
function referrer_check() {
    $referrer = $_SERVER['HTTP_REFERER'];
    // VULNERABLE: Referrer can be spoofed or stripped
    if (strpos($referrer, 'example.com') !== false) {
        return true;
    }
    return false;
}

// Helper functions
function process_transfer($amount, $to) {}
function delete_user($id) {}
function set_user_role($id, $role) {}
function validate_token($token) { return true; }
function process_payment_internal() {}
function update_user_profile($data) {}
?>
