#!/usr/bin/perl
# Weak Cryptography vulnerabilities in Perl

use strict;
use warnings;
use Digest::MD5;
use Digest::SHA;
use Crypt::CBC;
use Crypt::DES;

# Test 1: MD5 for password hashing
sub hash_password_md5 {
    my $password = shift;
    # VULNERABLE: MD5 is weak for passwords
    my $hash = Digest::MD5::md5_hex($password);
    return $hash;
}

# Test 2: SHA1 for security purposes
sub hash_password_sha1 {
    my $password = shift;
    # VULNERABLE: SHA1 is deprecated for security
    my $hash = Digest::SHA::sha1_hex($password);
    return $hash;
}

# Test 3: DES encryption
sub encrypt_des {
    my ($plaintext, $key) = @_;
    # VULNERABLE: DES is weak
    my $cipher = Crypt::CBC->new(
        -key    => $key,
        -cipher => 'DES'
    );
    return $cipher->encrypt($plaintext);
}

# Test 4: ECB mode
sub encrypt_ecb {
    my ($plaintext, $key) = @_;
    # VULNERABLE: ECB mode leaks patterns
    my $cipher = Crypt::CBC->new(
        -key    => $key,
        -cipher => 'Blowfish',
        -header => 'none',
        -literal_key => 1,
        -keysize => 16,
        -padding => 'null',
    );
    # Using raw mode (effectively ECB)
    return $cipher->encrypt($plaintext);
}

# Test 5: Weak key derivation
sub derive_key_weak {
    my $password = shift;
    # VULNERABLE: Simple MD5 for key derivation
    return Digest::MD5::md5($password);
}

# Test 6: Hardcoded IV
sub encrypt_with_fixed_iv {
    my ($plaintext, $key) = @_;
    # VULNERABLE: Static IV
    my $iv = "1234567890123456";
    my $cipher = Crypt::CBC->new(
        -key    => $key,
        -cipher => 'Rijndael',
        -iv     => $iv,
        -header => 'none',
    );
    return $cipher->encrypt($plaintext);
}

# Test 7: Insecure random for crypto
sub generate_weak_token {
    # VULNERABLE: rand() is not cryptographically secure
    my $token = "";
    for (1..32) {
        $token .= sprintf("%02x", int(rand(256)));
    }
    return $token;
}

# Test 8: RC4 encryption
sub encrypt_rc4 {
    my ($plaintext, $key) = @_;
    # VULNERABLE: RC4 is broken
    use Crypt::RC4;
    my $rc4 = Crypt::RC4->new($key);
    return $rc4->RC4($plaintext);
}

# Test 9: Short key length
sub encrypt_short_key {
    my $plaintext = shift;
    # VULNERABLE: Key too short
    my $key = "short";
    my $cipher = Crypt::CBC->new(
        -key    => $key,
        -cipher => 'Rijndael',
    );
    return $cipher->encrypt($plaintext);
}

# Test 10: Blowfish with weak key
sub encrypt_blowfish_weak {
    my ($plaintext, $password) = @_;
    # VULNERABLE: Using password directly as key
    my $cipher = Crypt::CBC->new(
        -key    => $password,
        -cipher => 'Blowfish',
    );
    return $cipher->encrypt($plaintext);
}

# Test 11: CRC32 for integrity
sub compute_checksum {
    use String::CRC32;
    my $data = shift;
    # VULNERABLE: CRC32 is not secure for integrity
    return crc32($data);
}

# Test 12: Base64 as "encryption"
sub encode_secret {
    use MIME::Base64;
    my $secret = shift;
    # VULNERABLE: Base64 is encoding, not encryption
    return encode_base64($secret);
}

# Test 13: XOR cipher
sub xor_encrypt {
    my ($plaintext, $key) = @_;
    # VULNERABLE: XOR cipher is easily broken
    my $encrypted = "";
    my @key_chars = split //, $key;
    my $i = 0;
    for my $char (split //, $plaintext) {
        $encrypted .= chr(ord($char) ^ ord($key_chars[$i % @key_chars]));
        $i++;
    }
    return $encrypted;
}

# Test 14: Predictable salt
sub hash_with_predictable_salt {
    my $password = shift;
    # VULNERABLE: Predictable salt
    my $salt = "fixed_salt_value";
    return Digest::SHA::sha256_hex($salt . $password);
}

# Test 15: No salt for password hash
sub hash_without_salt {
    my $password = shift;
    # VULNERABLE: No salt
    return Digest::SHA::sha256_hex($password);
}

# Test 16: Weak PRNG seed
sub seed_random {
    # VULNERABLE: Weak seeding
    srand(time());
    return int(rand(1000000));
}

1;
