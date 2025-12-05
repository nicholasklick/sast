<?php
// PHP Object Injection vulnerabilities

// Dangerous class that can be exploited
class FileHandler {
    public $filename;
    public $content;

    public function __destruct() {
        // Dangerous: Writes file in destructor
        file_put_contents($this->filename, $this->content);
    }
}

class CommandRunner {
    public $command;

    public function __wakeup() {
        // Dangerous: Executes command on unserialize
        system($this->command);
    }
}

class Logger {
    public $logFile;

    public function __toString() {
        // Dangerous: Reads file when cast to string
        return file_get_contents($this->logFile);
    }
}

// Test 1: unserialize with user input
function unsafe_unserialize() {
    $data = $_GET['data'];
    // VULNERABLE: Direct unserialize of user input
    $obj = unserialize($data);
    return $obj;
}

// Test 2: unserialize from cookie
function unserialize_cookie() {
    $cookie = $_COOKIE['user_prefs'];
    // VULNERABLE: Cookie can be manipulated
    $prefs = unserialize($cookie);
    return $prefs;
}

// Test 3: unserialize from POST
function unserialize_post() {
    $serialized = $_POST['object'];
    // VULNERABLE: POST data unserialize
    return unserialize($serialized);
}

// Test 4: unserialize from database
function unserialize_db() {
    $row = get_user_data($_GET['id']);
    // VULNERABLE: If database contains user-controlled serialized data
    return unserialize($row['preferences']);
}

// Test 5: unserialize from file
function unserialize_file() {
    $filename = $_GET['file'];
    // VULNERABLE: File content unserialize
    $content = file_get_contents($filename);
    return unserialize($content);
}

// Test 6: unserialize with base64
function unserialize_base64() {
    $encoded = $_POST['data'];
    // VULNERABLE: Base64 decode then unserialize
    $decoded = base64_decode($encoded);
    return unserialize($decoded);
}

// Test 7: unserialize in session handler
function custom_session_read($id) {
    $data = file_get_contents("/sessions/$id");
    // VULNERABLE: Session data unserialize
    return unserialize($data);
}

// Test 8: unserialize with allowed_classes but dangerous
function unserialize_allowed() {
    $data = $_POST['data'];
    // VULNERABLE: FileHandler is dangerous
    return unserialize($data, ['allowed_classes' => ['FileHandler', 'stdClass']]);
}

// Test 9: maybe_unserialize WordPress-style
function maybe_unserialize($data) {
    if (is_serialized($data)) {
        // VULNERABLE: Conditional unserialize
        return unserialize($data);
    }
    return $data;
}

function is_serialized($data) {
    return (@unserialize($data) !== false);
}

// Test 10: unserialize in cache
function get_cached($key) {
    $cached = $_SESSION['cache'][$key] ?? null;
    if ($cached) {
        // VULNERABLE: Cached data may be user-controlled
        return unserialize($cached);
    }
    return null;
}

// Test 11: phar:// deserialization
function process_phar() {
    $file = $_GET['file'];
    // VULNERABLE: phar:// triggers deserialization
    file_exists("phar://$file");
}

// Test 12: PHAR metadata exploitation
function read_phar() {
    $path = $_GET['path'];
    // VULNERABLE: Any file operation on phar:// can trigger deserialization
    $content = file_get_contents("phar://$path/test.txt");
    return $content;
}

function get_user_data($id) {
    // Placeholder
    return ['preferences' => 'a:0:{}'];
}
?>
