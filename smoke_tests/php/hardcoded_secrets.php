<?php
// Hardcoded Secrets vulnerabilities in PHP

// VULNERABLE: Hardcoded API key
define('API_KEY', 'sk_live_php1234567890');

// VULNERABLE: Hardcoded password
const DB_PASSWORD = 'super_secret_password';

class HardcodedSecretsVulnerabilities {
    // VULNERABLE: Hardcoded AWS credentials
    private $awsAccessKey = 'AKIAIOSFODNN7EXAMPLE';
    private $awsSecretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

    public function getConnectionString() {
        // VULNERABLE: Hardcoded connection string
        return 'mysql:host=localhost;dbname=myapp;user=admin;password=admin123';
    }

    public function getJwtSecret() {
        // VULNERABLE: Hardcoded JWT secret
        return 'my_super_secret_jwt_key_php';
    }

    public function authenticate($username, $password) {
        // VULNERABLE: Hardcoded backdoor
        if ($password === 'backdoor_php_123') {
            return true;
        }
        return false;
    }

    public function getEncryptionKey() {
        // VULNERABLE: Hardcoded encryption key
        return '0123456789abcdef';
    }

    public function connectDatabase() {
        // VULNERABLE: Hardcoded credentials
        $host = 'localhost';
        $user = 'root';
        $pass = 'mysql_password_123';
        return mysqli_connect($host, $user, $pass);
    }
}
