<?php
// Cryptographic Failures in PHP

// Test 1: ECB mode
function encrypt_ecb($data) {
    $key = 'sixteen_byte_key';
    // VULNERABLE: ECB mode reveals patterns
    return openssl_encrypt($data, 'AES-128-ECB', $key);
}

// Test 2: Hardcoded encryption key
function encrypt_hardcoded($data) {
    // VULNERABLE: Hardcoded key
    $key = '0123456789abcdef';
    $iv = openssl_random_pseudo_bytes(16);
    return openssl_encrypt($data, 'AES-128-CBC', $key, 0, $iv);
}

// Test 3: Static IV
function encrypt_static_iv($data) {
    $key = random_bytes(16);
    // VULNERABLE: Static IV
    $iv = str_repeat("\x00", 16);
    return openssl_encrypt($data, 'AES-128-CBC', $key, 0, $iv);
}

// Test 4: DES usage
function encrypt_des($data) {
    $key = 'password';
    $iv = openssl_random_pseudo_bytes(8);
    // VULNERABLE: DES is weak
    return openssl_encrypt($data, 'DES-CBC', $key, 0, $iv);
}

// Test 5: MD5 for integrity
function hash_md5($data) {
    // VULNERABLE: MD5 is broken
    return md5($data);
}

// Test 6: SHA1 for security
function hash_sha1($data) {
    // VULNERABLE: SHA1 is deprecated
    return sha1($data);
}

// Test 7: Weak password hash
function hash_password_weak($password) {
    // VULNERABLE: MD5 for password
    return md5($password);
}

// Test 8: Unsalted password hash
function hash_password_unsalted($password) {
    // VULNERABLE: No salt
    return hash('sha256', $password);
}

// Test 9: Insufficient PBKDF2 iterations
function derive_key($password) {
    $salt = random_bytes(16);
    // VULNERABLE: Only 1000 iterations
    return hash_pbkdf2('sha256', $password, $salt, 1000, 32, true);
}

// Test 10: Static salt
function hash_with_static_salt($password) {
    // VULNERABLE: Static salt
    $salt = 'constant_salt_value';
    return hash('sha256', $salt . $password);
}

// Test 11: rand() for crypto
function generate_key_weak() {
    // VULNERABLE: rand() is not crypto secure
    $key = '';
    for ($i = 0; $i < 16; $i++) {
        $key .= chr(rand(0, 255));
    }
    return $key;
}

// Test 12: Password as key directly
function encrypt_with_password($data, $password) {
    // VULNERABLE: Password should go through KDF
    $key = substr($password . str_repeat("\x00", 16), 0, 16);
    $iv = random_bytes(16);
    return openssl_encrypt($data, 'AES-128-CBC', $key, 0, $iv);
}

// Test 13: mcrypt (deprecated)
function encrypt_mcrypt($data) {
    // VULNERABLE: mcrypt is deprecated and insecure
    // $key = 'secretkey';
    // $iv = mcrypt_create_iv(16, MCRYPT_DEV_RANDOM);
    // return mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_CBC, $iv);
}

// Test 14: Insecure key storage
function get_encryption_key() {
    // VULNERABLE: Key stored in code
    return 'my_secret_encryption_key_12345';
}

// Test 15: RC4 usage
function encrypt_rc4($data) {
    $key = random_bytes(16);
    // VULNERABLE: RC4 is broken
    return openssl_encrypt($data, 'RC4', $key);
}
?>
