<?php
// Clean PHP code with no vulnerabilities

class SafePhpCode {

    // 1. Safe SQL Query - Prepared statement
    function getUserById($pdo, $userId) {
        $query = "SELECT * FROM users WHERE id = ?";
        $stmt = $pdo->prepare($query);
        $stmt->execute([$userId]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    // 2. Safe File Access - Path validation
    function readFile($filename) {
        $basePath = realpath('/var/data');
        $filePath = realpath($basePath . '/' . $filename);

        if (!$filePath || strpos($filePath, $basePath) !== 0) {
            throw new Exception("Path traversal detected");
        }

        return file_get_contents($filePath);
    }

    // 3. Safe Configuration
    function getApiKey() {
        $apiKey = getenv('API_KEY');
        if ($apiKey === false) {
            throw new Exception("API_KEY not set");
        }
        return $apiKey;
    }

    // 4. Safe Cryptography - Using OpenSSL
    function encryptData($data, $key) {
        $cipher = "aes-256-gcm";
        $ivLen = openssl_cipher_iv_length($cipher);
        $iv = openssl_random_pseudo_bytes($ivLen);
        $tag = "";

        $ciphertext = openssl_encrypt($data, $cipher, $key, OPENSSL_RAW_DATA, $iv, $tag);
        return base64_encode($iv . $tag . $ciphertext);
    }

    // 5. Safe Hashing - SHA-256
    function hashPassword($password) {
        return hash('sha256', $password);
    }

    // 6. Safe Random Generation
    function generateSecureToken() {
        return bin2hex(random_bytes(32));
    }

    // 7. Safe Command Execution - Using escapeshellarg
    function listFiles($directory) {
        $allowedDirs = ['/tmp', '/var/log'];
        if (!in_array($directory, $allowedDirs)) {
            throw new Exception("Directory not allowed");
        }

        $safeDir = escapeshellarg($directory);
        return shell_exec("ls -la $safeDir");
    }

    // 8. Safe Output - HTML escaping
    function displayUserInput($userInput) {
        return htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');
    }

    // 9. Safe XML Processing - Disable external entities
    function parseXmlSafely($xmlContent) {
        libxml_disable_entity_loader(true);

        $dom = new DOMDocument();
        $dom->loadXML($xmlContent, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);

        return $dom;
    }

    // 10. Safe Input Validation
    function validateAndSanitize($input) {
        return preg_replace('/[^a-zA-Z0-9_-]/', '', $input);
    }

    // 11. Safe URL Fetching - Whitelist validation
    function fetchUrl($url) {
        $allowedHosts = ['api.example.com', 'data.example.com'];
        $parsedUrl = parse_url($url);

        if (!in_array($parsedUrl['host'], $allowedHosts)) {
            throw new Exception("Host not allowed");
        }

        $context = stream_context_create([
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true
            ]
        ]);

        return file_get_contents($url, false, $context);
    }

    // 12. Safe Type Checking - Strict comparison
    function strictTypeCheck($value) {
        // Using === instead of ==
        return ($value === "0") ? true : false;
    }

    // 13. Safe Array Access
    function safeArrayAccess($array, $key) {
        return isset($array[$key]) ? $array[$key] : null;
    }

    // 14. Safe File Upload Validation
    function validateUploadedFile($file) {
        $allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
        $allowedExtensions = ['jpg', 'jpeg', 'png', 'gif'];

        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mimeType = finfo_file($finfo, $file['tmp_name']);
        finfo_close($finfo);

        $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));

        return in_array($mimeType, $allowedTypes) &&
               in_array($extension, $allowedExtensions);
    }
}
?>
