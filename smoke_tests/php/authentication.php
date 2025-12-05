<?php
// Authentication vulnerabilities in PHP

// Test 1: Plaintext password storage
function register_plaintext() {
    $username = $_POST['username'];
    $password = $_POST['password'];

    $pdo = get_pdo();
    // VULNERABLE: Storing plaintext password
    $stmt = $pdo->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    $stmt->execute([$username, $password]);
}

// Test 2: MD5 password hashing
function register_md5() {
    $password = $_POST['password'];
    // VULNERABLE: MD5 is too weak
    $hash = md5($password);
    store_user($_POST['username'], $hash);
}

// Test 3: SHA1 without salt
function register_sha1() {
    $password = $_POST['password'];
    // VULNERABLE: Unsalted SHA1
    $hash = sha1($password);
    store_user($_POST['username'], $hash);
}

// Test 4: Hardcoded credentials
function admin_login() {
    $username = $_POST['username'];
    $password = $_POST['password'];
    // VULNERABLE: Hardcoded credentials
    if ($username === 'admin' && $password === 'admin123') {
        $_SESSION['admin'] = true;
        return true;
    }
    return false;
}

// Test 5: Timing attack in comparison
function login_timing() {
    $username = $_POST['username'];
    $password = $_POST['password'];

    $user = get_user_by_username($username);
    // VULNERABLE: String comparison leaks timing
    if ($user && $user['password_hash'] === hash('sha256', $password)) {
        $_SESSION['user_id'] = $user['id'];
        return true;
    }
    return false;
}

// Test 6: No account lockout
function login_no_lockout() {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // VULNERABLE: No failed attempt tracking
    $user = get_user_by_username($username);
    if ($user && password_verify($password, $user['password_hash'])) {
        $_SESSION['user_id'] = $user['id'];
        return true;
    }
    return false;
}

// Test 7: Password in URL (GET request)
function login_get() {
    $username = $_GET['username'];
    $password = $_GET['password'];
    // VULNERABLE: GET request with credentials
    return authenticate($username, $password);
}

// Test 8: Password logged
function login_with_logging() {
    $username = $_POST['username'];
    $password = $_POST['password'];
    // VULNERABLE: Password in logs
    error_log("Login attempt: $username/$password");
    return authenticate($username, $password);
}

// Test 9: Weak session configuration
function create_session() {
    // VULNERABLE: Insecure session settings
    ini_set('session.cookie_httponly', 0);
    ini_set('session.cookie_secure', 0);
    session_start();
    $_SESSION['user_id'] = get_user_id();
}

// Test 10: Insufficient password requirements
function set_password() {
    $password = $_POST['password'];
    // VULNERABLE: No complexity check
    if (strlen($password) >= 4) {  // Too short
        update_password($password);
        return true;
    }
    return false;
}

// Test 11: Predictable remember token
function remember_me() {
    $user_id = $_SESSION['user_id'];
    // VULNERABLE: Predictable remember token
    $token = $user_id . time();
    setcookie('remember_token', $token, time() + 86400 * 365);
}

// Test 12: Session fixation
function login_no_regenerate() {
    if (authenticate($_POST['username'], $_POST['password'])) {
        // VULNERABLE: Session not regenerated after login
        $_SESSION['user_id'] = get_user_id();
        return true;
    }
    return false;
}

// Helper functions
function get_pdo() { return new PDO('sqlite::memory:'); }
function store_user($username, $hash) {}
function get_user_by_username($username) { return null; }
function authenticate($username, $password) { return false; }
function get_user_id() { return 1; }
function update_password($password) {}
?>
