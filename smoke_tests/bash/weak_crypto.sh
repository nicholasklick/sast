#!/bin/bash
# Weak Cryptography vulnerabilities in Bash

# Test 1: MD5 for password hashing
vulnerable_md5_password() {
    local password="$1"
    # VULNERABLE: MD5 is weak for passwords
    echo -n "$password" | md5sum
}

# Test 2: SHA1 for security purposes
vulnerable_sha1() {
    local data="$1"
    # VULNERABLE: SHA1 is deprecated
    echo -n "$data" | sha1sum
}

# Test 3: openssl with weak cipher
vulnerable_weak_cipher() {
    local file="$1"
    # VULNERABLE: DES is weak
    openssl enc -des -in "$file" -out "$file.enc" -k password
}

# Test 4: openssl with ECB mode
vulnerable_ecb_mode() {
    local file="$1"
    # VULNERABLE: ECB mode is insecure
    openssl enc -aes-128-ecb -in "$file" -out "$file.enc" -k password
}

# Test 5: GPG with weak algorithm
vulnerable_gpg_weak() {
    local file="$1"
    # VULNERABLE: 3DES is weak
    gpg --cipher-algo 3DES -c "$file"
}

# Test 6: SSL with weak protocol
vulnerable_ssl_v3() {
    local host="$1"
    # VULNERABLE: SSLv3 is deprecated
    openssl s_client -ssl3 -connect "$host:443"
}

# Test 7: TLS 1.0
vulnerable_tls_1_0() {
    local host="$1"
    # VULNERABLE: TLS 1.0 is deprecated
    openssl s_client -tls1 -connect "$host:443"
}

# Test 8: Hardcoded encryption key
vulnerable_hardcoded_key() {
    local file="$1"
    # VULNERABLE: Hardcoded key
    KEY="0123456789abcdef"
    openssl enc -aes-256-cbc -in "$file" -out "$file.enc" -k "$KEY"
}

# Test 9: Weak key generation
vulnerable_weak_keygen() {
    # VULNERABLE: Insufficient entropy
    KEY=$(date +%s | md5sum | head -c 16)
    echo "$KEY"
}

# Test 10: RC4 cipher
vulnerable_rc4() {
    local file="$1"
    # VULNERABLE: RC4 is broken
    openssl enc -rc4 -in "$file" -out "$file.enc" -k password
}

# Test 11: Short RSA key
vulnerable_short_rsa() {
    # VULNERABLE: 1024-bit RSA is too short
    openssl genrsa -out key.pem 1024
}

# Test 12: Predictable IV
vulnerable_predictable_iv() {
    local file="$1"
    # VULNERABLE: Predictable IV
    IV="0000000000000000"
    openssl enc -aes-256-cbc -iv "$IV" -in "$file" -out "$file.enc" -k password
}

# Test 13: Password in openssl command
vulnerable_password_cmdline() {
    local file="$1"
    # VULNERABLE: Password visible in process list
    openssl enc -aes-256-cbc -in "$file" -out "$file.enc" -k "mysecretpassword"
}

# Test 14: Blowfish with short key
vulnerable_blowfish() {
    local file="$1"
    # VULNERABLE: Blowfish is deprecated
    openssl enc -bf -in "$file" -out "$file.enc" -k pass
}

# Test 15: Using /dev/urandom incorrectly
vulnerable_random() {
    # VULNERABLE: Truncating randomness
    KEY=$(head -c 8 /dev/urandom | xxd -p)
    echo "$KEY"
}

