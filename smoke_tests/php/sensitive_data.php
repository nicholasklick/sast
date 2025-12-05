<?php
// Sensitive Data Exposure vulnerabilities in PHP

// Test 1: Exception details exposed
function show_error() {
    try {
        throw new Exception('Database connection failed');
    } catch (Exception $e) {
        // VULNERABLE: Stack trace exposed
        echo "Error: " . $e->getMessage() . "\n";
        echo "Stack trace:\n" . $e->getTraceAsString();
    }
}

// Test 2: Debug info in response
function get_data() {
    $data = load_data();
    // VULNERABLE: Debug information exposed
    return json_encode([
        'data' => $data,
        'debug' => [
            'server' => php_uname(),
            'user' => get_current_user(),
            'path' => __DIR__
        ]
    ]);
}

// Test 3: Logging sensitive data
function process_payment() {
    $card_number = $_POST['card_number'];
    $cvv = $_POST['cvv'];
    // VULNERABLE: Credit card data logged
    error_log("Processing card: $card_number, CVV: $cvv");
    do_payment($card_number, $cvv);
}

// Test 4: Sensitive data in URL
function show_account() {
    $ssn = $_GET['ssn'];
    $account = $_GET['account_number'];
    // VULNERABLE: SSN and account in URL (logged, cached)
    return get_user_by_ssn($ssn);
}

// Test 5: Caching sensitive responses
function get_user_details() {
    // VULNERABLE: Sensitive data being cached
    header('Cache-Control: public, max-age=3600');
    echo json_encode([
        'user_id' => $_SESSION['user_id'],
        'email' => get_user_email(),
        'ssn' => get_user_ssn()
    ]);
}

// Test 6: Unencrypted sensitive storage
function store_ssn() {
    $ssn = $_POST['ssn'];
    // VULNERABLE: SSN stored unencrypted
    file_put_contents('/data/user.txt', $ssn);
}

// Test 7: API key in response
function get_config() {
    // VULNERABLE: API keys exposed
    echo json_encode([
        'api_endpoint' => 'https://api.example.com',
        'api_key' => 'sk-12345-secret-key',
        'db_password' => 'secret123'
    ]);
}

// Test 8: display_errors in production
function enable_errors() {
    // VULNERABLE: Shows errors in production
    ini_set('display_errors', 1);
    ini_set('display_startup_errors', 1);
    error_reporting(E_ALL);
}

// Test 9: HTTP for sensitive data
function redirect_to_payment() {
    // VULNERABLE: HTTP for payment page
    header('Location: http://payment.example.com/checkout');
}

// Test 10: phpinfo exposed
function show_info() {
    // VULNERABLE: Exposes server configuration
    phpinfo();
}

// Test 11: var_dump in production
function debug_output() {
    $user = get_current_user_data();
    // VULNERABLE: Debug output in production
    var_dump($user);
    print_r($user);
}

// Test 12: Backup files accessible
function check_backup() {
    // Note: Issue is that .bak files might be web-accessible
    // /config.php.bak, /database.sql.bak
    // This is a configuration issue more than code issue
}

// Test 13: Verbose error messages
function database_error() {
    try {
        $pdo = new PDO('mysql:host=localhost;dbname=test', 'root', 'password');
    } catch (PDOException $e) {
        // VULNERABLE: Database credentials might be in message
        echo "Database error: " . $e->getMessage();
    }
}

// Helper functions
function load_data() { return []; }
function do_payment($card, $cvv) {}
function get_user_by_ssn($ssn) { return null; }
function get_user_email() { return 'user@example.com'; }
function get_user_ssn() { return '123-45-6789'; }
function get_current_user_data() { return []; }
?>
