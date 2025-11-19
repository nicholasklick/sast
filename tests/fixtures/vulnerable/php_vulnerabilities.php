<?php
// PHP Vulnerability Test Fixtures

class PhpVulnerabilities {

    // 1. SQL Injection - String concatenation
    function sqlInjectionConcat($userId) {
        $conn = new mysqli("localhost", "user", "password", "database");
        $query = "SELECT * FROM users WHERE id = '" . $userId . "'";
        $result = $conn->query($query);
        return $result->fetch_assoc();
    }

    // 2. SQL Injection - String interpolation
    function sqlInjectionInterpolation($username) {
        $conn = new mysqli("localhost", "user", "password", "database");
        $query = "SELECT * FROM users WHERE username = '$username'";
        $result = $conn->query($query);
        return $result->num_rows > 0;
    }

    // 3. Command Injection - shell_exec
    function commandInjectionShellExec($filename) {
        return shell_exec("cat $filename");
    }

    // 4. Command Injection - exec
    function commandInjectionExec($userInput) {
        exec("ls $userInput", $output);
        return $output;
    }

    // 5. Command Injection - system
    function commandInjectionSystem($command) {
        system("sh -c $command");
    }

    // 6. Command Injection - passthru
    function commandInjectionPassthru($filename) {
        passthru("cat $filename");
    }

    // 7. Path Traversal
    function pathTraversal($filename) {
        return file_get_contents("/var/data/$filename");
    }

    // 8. Hardcoded Credentials - API Key
    const API_KEY = "sk_live_php1234567890abcdef";

    // 9. Hardcoded Credentials - Database Password
    function connectToDatabase() {
        $password = "PhpSecret456!";
        return new mysqli("localhost", "admin", $password, "database");
    }

    // 10. Weak Cryptography - MD5
    function weakHashMd5($input) {
        return md5($input);
    }

    // 11. Weak Cryptography - SHA1
    function weakHashSha1($input) {
        return sha1($input);
    }

    // 12. Eval with User Input
    function codeInjection($userCode) {
        eval($userCode);
    }

    // 13. Unsafe Unserialize
    function unsafeUnserialize($data) {
        return unserialize($data);
    }

    // 14. XSS - Direct Echo
    function xssDirect($userInput) {
        echo "<html><body><h1>Welcome $userInput</h1></body></html>";
    }

    // 15. XSS - No Escaping
    function xssNoEscape($userInput) {
        return "<div>" . $userInput . "</div>";
    }

    // 16. SSRF Vulnerability
    function fetchUrl($url) {
        return file_get_contents($url);
    }

    // 17. Open Redirect
    function redirect($url) {
        header("Location: $url");
    }

    // 18. LFI (Local File Inclusion)
    function localFileInclusion($page) {
        include("/var/www/pages/$page.php");
    }

    // 19. RFI (Remote File Inclusion)
    function remoteFileInclusion($url) {
        include($url);
    }

    // 20. XXE Vulnerability
    function parseXml($xmlContent) {
        $dom = new DOMDocument();
        // Missing: libxml_disable_entity_loader(true);
        $dom->loadXML($xmlContent);
        return $dom;
    }

    // 21. LDAP Injection
    function ldapInjection($username) {
        $filter = "(uid=$username)";
        // ldap_search with unvalidated input
        return $filter;
    }

    // 22. XPath Injection
    function xpathInjection($userId) {
        $xml = simplexml_load_file('users.xml');
        $query = "//user[@id='$userId']";
        return $xml->xpath($query);
    }

    // 23. Unsafe Random Number Generation
    function generateToken() {
        return rand(100000, 999999);
    }

    // 24. SQL Injection in PDO
    function sqlInjectionPDO($userId) {
        $pdo = new PDO('mysql:host=localhost;dbname=test', 'user', 'password');
        $query = "SELECT * FROM users WHERE id = '$userId'";
        $stmt = $pdo->query($query);
        return $stmt->fetch();
    }

    // 25. NoSQL Injection (MongoDB pattern)
    function mongoQuery($userId) {
        $query = ['userId' => $userId];
        // Vulnerable if $userId contains operators like $ne, $gt
        return $query;
    }

    // 26. Template Injection
    function renderTemplate($userInput) {
        $template = "<html><body><h1>Welcome $userInput</h1></body></html>";
        return $template;
    }

    // 27. Unsafe File Operations
    function deleteFile($filename) {
        unlink("/tmp/$filename");
    }

    // 28. Type Juggling Vulnerability
    function typeJuggling($userInput) {
        if ($userInput == "0") {  // Loose comparison vulnerable
            return true;
        }
        return false;
    }

    // 29. Disabled TLS Verification
    function insecureHttpRequest($url) {
        $context = stream_context_create([
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false
            ]
        ]);
        return file_get_contents($url, false, $context);
    }

    // 30. Extract Function Vulnerability
    function extractVuln($userData) {
        extract($userData);  // Can overwrite variables
        // $isAdmin could be overwritten
    }
}
?>
