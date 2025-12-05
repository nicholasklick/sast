#!/bin/bash
# Authentication vulnerabilities in Bash

# Test 1: Plaintext password comparison
vulnerable_plaintext_auth() {
    local user="$1"
    local password="$2"
    # VULNERABLE: Plaintext password comparison
    if [ "$password" = "admin123" ]; then
        echo "Authenticated"
    fi
}

# Test 2: Weak password validation
vulnerable_weak_validation() {
    local password="$1"
    # VULNERABLE: No complexity requirements
    if [ ${#password} -ge 4 ]; then
        echo "Password accepted"
    fi
}

# Test 3: Hardcoded credentials check
vulnerable_hardcoded_check() {
    local user="$1"
    local pass="$2"
    # VULNERABLE: Hardcoded credentials
    if [ "$user" = "admin" ] && [ "$pass" = "password123" ]; then
        return 0
    fi
    return 1
}

# Test 4: Insecure sudo usage
vulnerable_sudo() {
    local password="$1"
    # VULNERABLE: Password in echo pipe
    echo "$password" | sudo -S whoami
}

# Test 5: SSH with password
vulnerable_ssh_password() {
    local password="$1"
    local host="$2"
    # VULNERABLE: Password-based SSH
    sshpass -p "$password" ssh user@"$host"
}

# Test 6: No rate limiting
vulnerable_no_rate_limit() {
    local user="$1"
    local pass="$2"
    # VULNERABLE: No brute force protection
    while true; do
        if check_login "$user" "$pass"; then
            break
        fi
        read -p "Try again: " pass
    done
}

# Test 7: Password in URL
vulnerable_url_password() {
    local user="$1"
    local pass="$2"
    # VULNERABLE: Credentials in URL
    curl "https://$user:$pass@api.example.com/data"
}

# Test 8: Storing password in file
vulnerable_password_file() {
    local password="$1"
    # VULNERABLE: Password stored in plaintext
    echo "$password" > /tmp/password.txt
}

# Test 9: Password in command history
vulnerable_history() {
    local password="$1"
    # VULNERABLE: Password visible in history
    mysql -u root -p"$password" -e "SELECT 1"
}

# Test 10: Weak password hash
vulnerable_weak_hash() {
    local password="$1"
    # VULNERABLE: MD5 for password
    echo -n "$password" | md5sum | cut -d' ' -f1
}

# Test 11: No session timeout
vulnerable_session() {
    # VULNERABLE: Session never expires
    export SESSION_TOKEN="permanent_token"
    # No expiration logic
}

# Test 12: Insecure token generation
vulnerable_token() {
    # VULNERABLE: Predictable token
    TOKEN=$(date +%s)
    echo "$TOKEN"
}

# Test 13: Password logging
vulnerable_log_password() {
    local user="$1"
    local password="$2"
    # VULNERABLE: Password in logs
    echo "Login attempt: $user:$password" >> /var/log/auth.log
}

# Test 14: Default credentials
vulnerable_default_creds() {
    # VULNERABLE: Default admin credentials
    ADMIN_USER="${ADMIN_USER:-admin}"
    ADMIN_PASS="${ADMIN_PASS:-admin}"
}

# Test 15: Password in process args
vulnerable_process_args() {
    local password="$1"
    # VULNERABLE: Visible in ps output
    /usr/bin/myapp --password="$password"
}

