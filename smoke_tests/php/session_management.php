<?php
// Session Management vulnerabilities in PHP

// Test 1: Session fixation - no regeneration
function login_no_regenerate() {
    if (authenticate($_POST['username'], $_POST['password'])) {
        // VULNERABLE: Session ID not regenerated
        $_SESSION['user_id'] = get_user_id();
        return true;
    }
    return false;
}

// Test 2: Session ID in URL
function show_with_session() {
    $session_id = session_id();
    // VULNERABLE: Session ID in URL (logged, shared)
    header("Location: /dashboard?PHPSESSID=$session_id");
}

// Test 3: Long session lifetime
function set_long_session() {
    // VULNERABLE: Very long session lifetime
    ini_set('session.gc_maxlifetime', 31536000);  // 1 year
    session_set_cookie_params(31536000);
    session_start();
}

// Test 4: No session timeout
function check_session() {
    session_start();
    // VULNERABLE: No idle timeout check
    if (isset($_SESSION['user_id'])) {
        return $_SESSION['user_id'];
    }
    return null;
}

// Test 5: Predictable session ID
function custom_session_id() {
    // VULNERABLE: Predictable session identifier
    $session_id = md5($_SERVER['REMOTE_ADDR'] . time());
    session_id($session_id);
    session_start();
}

// Test 6: Sensitive data in session cookie
function store_in_session() {
    session_start();
    // VULNERABLE: Sensitive data in session
    $_SESSION['credit_card'] = $_POST['card_number'];
    $_SESSION['ssn'] = $_POST['ssn'];
}

// Test 7: No HttpOnly flag
function insecure_session_start() {
    // VULNERABLE: No HttpOnly flag
    ini_set('session.cookie_httponly', 0);
    session_start();
}

// Test 8: No Secure flag
function insecure_cookie() {
    // VULNERABLE: Cookie sent over HTTP
    ini_set('session.cookie_secure', 0);
    session_start();
}

// Test 9: Session not destroyed on logout
function logout_incomplete() {
    session_start();
    // VULNERABLE: Session not properly destroyed
    $_SESSION = [];
    // session_destroy() not called
    header('Location: /');
}

// Test 10: Session ID accepted from GET/POST
function accept_session_input() {
    // VULNERABLE: Allows session fixation
    ini_set('session.use_only_cookies', 0);
    ini_set('session.use_trans_sid', 1);
    session_start();
}

// Test 11: No session entropy
function weak_session_config() {
    // VULNERABLE: Weak session configuration
    ini_set('session.entropy_length', 0);
    ini_set('session.hash_function', 'md5');
    session_start();
}

// Test 12: Concurrent sessions not controlled
function allow_concurrent() {
    session_start();
    if (authenticate($_POST['username'], $_POST['password'])) {
        // VULNERABLE: No concurrent session control
        $_SESSION['user_id'] = get_user_id();
        // Previous sessions not invalidated
    }
}

// Test 13: Session path vulnerability
function custom_session_path() {
    // VULNERABLE: Session files in web-accessible directory
    session_save_path('/var/www/html/sessions');
    session_start();
}

// Test 14: Custom session handler without validation
class InsecureSessionHandler implements SessionHandlerInterface {
    public function read($id): string|false {
        // VULNERABLE: No validation of session ID format
        return file_get_contents("/tmp/sess_$id");
    }

    public function write($id, $data): bool {
        // VULNERABLE: No sanitization
        return file_put_contents("/tmp/sess_$id", $data) !== false;
    }

    public function open($path, $name): bool { return true; }
    public function close(): bool { return true; }
    public function destroy($id): bool { return true; }
    public function gc($max): int|false { return 0; }
}

function authenticate($username, $password) { return true; }
function get_user_id() { return 1; }
?>
