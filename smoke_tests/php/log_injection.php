<?php
// Log Injection vulnerabilities in PHP

// Test 1: error_log with user input
function log_error_unsafe() {
    $message = $_GET['message'];
    // VULNERABLE: User input can contain newlines
    error_log("[ERROR] User message: $message");
}

// Test 2: file_put_contents logging
function file_log() {
    $username = $_POST['username'];
    $action = $_POST['action'];
    // VULNERABLE: Can inject fake log entries
    $log = "[" . date('Y-m-d H:i:s') . "] User $username performed $action\n";
    file_put_contents('/var/log/app.log', $log, FILE_APPEND);
}

// Test 3: syslog with user input
function syslog_unsafe() {
    $user_input = $_GET['input'];
    openlog('myapp', LOG_PID, LOG_USER);
    // VULNERABLE: User input in syslog
    syslog(LOG_INFO, "User action: $user_input");
    closelog();
}

// Test 4: fwrite logging
function fwrite_log() {
    $event = $_POST['event'];
    $f = fopen('/var/log/events.log', 'a');
    // VULNERABLE: Event can contain CRLF
    fwrite($f, "[EVENT] $event\n");
    fclose($f);
}

// Test 5: JSON log breaking
function json_log() {
    $message = $_GET['msg'];
    // VULNERABLE: Can break JSON structure
    $log_entry = json_encode([
        'timestamp' => time(),
        'message' => $message
    ]);
    file_put_contents('/var/log/json.log', $log_entry . "\n", FILE_APPEND);
}

// Test 6: Monolog with user data
function monolog_log() {
    $data = $_POST['data'];
    $logger = new \Monolog\Logger('app');
    $logger->pushHandler(new \Monolog\Handler\StreamHandler('/var/log/app.log'));
    // VULNERABLE: User data in log context
    $logger->info("Processing: $data");
}

// Test 7: Apache error log
function apache_log() {
    $error = $_GET['error'];
    // VULNERABLE: User controls error message
    trigger_error("User error: $error", E_USER_WARNING);
}

// Test 8: Debug logging
function debug_log() {
    $debug_data = $_POST['debug'];
    // VULNERABLE: Debug data from user
    file_put_contents('/tmp/debug.log', print_r($debug_data, true), FILE_APPEND);
}

// Test 9: Exception message logging
function log_exception() {
    try {
        throw new Exception($_GET['error']);
    } catch (Exception $e) {
        // VULNERABLE: Exception message from user
        error_log("Exception: " . $e->getMessage());
    }
}

// Test 10: Audit log manipulation
function audit_log() {
    $user = $_POST['user'];
    $action = $_POST['action'];
    $result = $_POST['result'];
    // VULNERABLE: Multiple fields can contain newlines
    $audit = "User: $user\nAction: $action\nResult: $result\n---\n";
    file_put_contents('/var/log/audit.log', $audit, FILE_APPEND);
}

// Test 11: PSR-3 logger injection
function psr3_log() {
    $context = $_POST['context'];
    $logger = get_logger();
    // VULNERABLE: Context from user input
    $logger->info("Request processed", ['context' => $context]);
}

function get_logger() {
    // Return PSR-3 compatible logger
    return new class {
        public function info($message, $context = []) {
            error_log("$message " . json_encode($context));
        }
    };
}
?>
