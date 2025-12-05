<?php
// Insecure Randomness vulnerabilities in PHP

// Test 1: rand() for security token
function generate_token_rand() {
    // VULNERABLE: rand() is not cryptographically secure
    $token = '';
    for ($i = 0; $i < 32; $i++) {
        $token .= dechex(rand(0, 15));
    }
    return $token;
}

// Test 2: mt_rand() for session
function create_session_mt_rand() {
    // VULNERABLE: mt_rand() is predictable
    $session_id = mt_rand() . mt_rand();
    return $session_id;
}

// Test 3: Seeded rand with predictable seed
function seeded_random() {
    // VULNERABLE: Predictable seed
    srand(42);
    return rand();
}

// Test 4: Time-based seed
function time_seeded() {
    // VULNERABLE: Time-based seed is predictable
    srand(time());
    return rand();
}

// Test 5: rand() for password
function generate_password() {
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $password = '';
    // VULNERABLE: Using rand() for password
    for ($i = 0; $i < 12; $i++) {
        $password .= $chars[rand(0, strlen($chars) - 1)];
    }
    return $password;
}

// Test 6: array_rand with shuffle
function shuffle_deck() {
    $deck = range(1, 52);
    // VULNERABLE: shuffle uses internal PRNG
    shuffle($deck);
    return $deck;
}

// Test 7: rand() for CSRF token
function get_csrf_token() {
    // VULNERABLE: CSRF token needs crypto random
    return sprintf('%032x', rand() ^ rand());
}

// Test 8: rand() for OTP
function generate_otp() {
    // VULNERABLE: OTP should use random_int()
    return sprintf('%06d', rand(0, 999999));
}

// Test 9: rand() for API key
function generate_api_key() {
    // VULNERABLE: API key needs crypto random
    $key = '';
    for ($i = 0; $i < 40; $i++) {
        $key .= dechex(mt_rand(0, 15));
    }
    return $key;
}

// Test 10: rand() for encryption IV
function generate_iv() {
    // VULNERABLE: IV needs crypto random
    $iv = '';
    for ($i = 0; $i < 16; $i++) {
        $iv .= chr(rand(0, 255));
    }
    return $iv;
}

// Test 11: uniqid() for security
function unique_token() {
    // VULNERABLE: uniqid() is time-based, not random
    return uniqid('token_', true);
}

// Test 12: microtime as seed
function microtime_seeded() {
    // VULNERABLE: microtime is predictable
    srand((int)(microtime(true) * 1000000));
    return rand();
}

// Test 13: str_shuffle for security
function shuffle_string() {
    $chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    // VULNERABLE: str_shuffle uses PRNG
    return substr(str_shuffle($chars), 0, 16);
}

// Note: Secure alternatives in PHP:
// random_bytes(16)
// random_int(0, 999999)
// bin2hex(random_bytes(16))
// openssl_random_pseudo_bytes(16)
?>
