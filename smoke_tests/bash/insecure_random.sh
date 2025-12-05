#!/bin/bash
# Insecure Random Number Generation vulnerabilities in Bash

# Test 1: Using $RANDOM for security
vulnerable_random_var() {
    # VULNERABLE: $RANDOM is predictable (15-bit LFSR)
    TOKEN="$RANDOM$RANDOM$RANDOM"
    echo "Session token: $TOKEN"
}

# Test 2: Using date for randomness
vulnerable_date_random() {
    # VULNERABLE: Timestamp is predictable
    SECRET=$(date +%s%N)
    echo "$SECRET"
}

# Test 3: Using PID for randomness
vulnerable_pid_random() {
    # VULNERABLE: PID is predictable
    TOKEN="secret_$$"
    echo "$TOKEN"
}

# Test 4: Using seq with shuf
vulnerable_seq_shuf() {
    # VULNERABLE: May use weak PRNG
    PASSWORD=$(seq 1000 9999 | shuf -n 1)
    echo "$PASSWORD"
}

# Test 5: Using /dev/urandom incorrectly
vulnerable_urandom_weak() {
    # VULNERABLE: Insufficient bytes
    KEY=$(head -c 4 /dev/urandom | xxd -p)
    echo "$KEY"
}

# Test 6: Seeding with predictable value
vulnerable_seed() {
    # VULNERABLE: Predictable seed
    RANDOM=$$
    echo $RANDOM
}

# Test 7: Using awk rand()
vulnerable_awk_rand() {
    # VULNERABLE: awk rand() is weak
    awk 'BEGIN {srand(); print int(rand() * 1000000)}'
}

# Test 8: Using bc for random
vulnerable_bc_random() {
    # VULNERABLE: Not cryptographically secure
    echo "scale=0; $RANDOM * 1000 / 32768" | bc
}

# Test 9: md5 of timestamp
vulnerable_md5_time() {
    # VULNERABLE: Predictable input to hash
    TOKEN=$(date | md5sum | head -c 32)
    echo "$TOKEN"
}

# Test 10: UUID from random
vulnerable_uuid_random() {
    # VULNERABLE: Using $RANDOM for UUID
    UUID=$(printf '%04x%04x-%04x-%04x-%04x-%04x%04x%04x' \
        $RANDOM $RANDOM $RANDOM $RANDOM $RANDOM $RANDOM $RANDOM $RANDOM)
    echo "$UUID"
}

# Test 11: Password from weak source
vulnerable_password_gen() {
    # VULNERABLE: Weak random source
    PASSWORD=$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 8)
    # 8 chars is too short
    echo "$PASSWORD"
}

# Test 12: Session ID from hostname+time
vulnerable_session_id() {
    # VULNERABLE: Predictable components
    SESSION_ID=$(hostname)-$(date +%s)-$$
    echo "$SESSION_ID"
}

# Test 13: Using jot for security tokens
vulnerable_jot() {
    # VULNERABLE: jot uses weak PRNG
    TOKEN=$(jot -r 1 100000 999999)
    echo "$TOKEN"
}

# Test 14: Using sort -R for shuffling secrets
vulnerable_sort_random() {
    # VULNERABLE: sort -R may be weak
    echo -e "secret1\nsecret2\nsecret3" | sort -R | head -1
}

# Test 15: Perl rand via bash
vulnerable_perl_rand() {
    # VULNERABLE: Perl's rand() without srand
    perl -e 'print int(rand(1000000))'
}

