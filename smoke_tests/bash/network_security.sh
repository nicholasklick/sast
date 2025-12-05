#!/bin/bash
# Network Security vulnerabilities in Bash

# Test 1: HTTP instead of HTTPS
vulnerable_http() {
    local endpoint="$1"
    # VULNERABLE: Unencrypted connection
    curl "http://api.example.com/$endpoint"
}

# Test 2: Insecure wget
vulnerable_wget_insecure() {
    local url="$1"
    # VULNERABLE: No certificate verification
    wget --no-check-certificate "$url"
}

# Test 3: curl without cert verification
vulnerable_curl_insecure() {
    local url="$1"
    # VULNERABLE: SSL verification disabled
    curl -k "$url"
}

# Test 4: Telnet for sensitive data
vulnerable_telnet() {
    local host="$1"
    # VULNERABLE: Telnet is unencrypted
    telnet "$host" 23
}

# Test 5: FTP for file transfer
vulnerable_ftp() {
    local host="$1"
    # VULNERABLE: FTP is unencrypted
    ftp "$host"
}

# Test 6: rsh/rlogin usage
vulnerable_rsh() {
    local host="$1"
    local cmd="$2"
    # VULNERABLE: rsh is insecure
    rsh "$host" "$cmd"
}

# Test 7: Unencrypted netcat
vulnerable_netcat() {
    local host="$1"
    local port="$2"
    # VULNERABLE: Plaintext transmission
    echo "secret data" | nc "$host" "$port"
}

# Test 8: SNMP v1/v2c
vulnerable_snmp() {
    local host="$1"
    # VULNERABLE: SNMPv1/v2c has weak auth
    snmpwalk -v 2c -c public "$host"
}

# Test 9: DNS without DNSSEC
vulnerable_dns() {
    local domain="$1"
    # VULNERABLE: DNS spoofing possible
    dig +short "$domain"
}

# Test 10: Open port binding
vulnerable_bind() {
    local port="$1"
    # VULNERABLE: Binding to all interfaces
    nc -l -p "$port" 0.0.0.0
}

# Test 11: Insecure protocol in config
vulnerable_protocol() {
    local config="$1"
    # VULNERABLE: Setting insecure protocol
    echo "protocol = ftp" >> "$config"
}

# Test 12: No timeout on network ops
vulnerable_no_timeout() {
    local url="$1"
    # VULNERABLE: No timeout - DoS potential
    curl "$url"
}

# Test 13: LDAP without TLS
vulnerable_ldap() {
    local server="$1"
    # VULNERABLE: LDAP without encryption
    ldapsearch -H "ldap://$server" -b "dc=example,dc=com"
}

# Test 14: Redis without auth
vulnerable_redis() {
    local host="$1"
    # VULNERABLE: Redis without password
    redis-cli -h "$host" KEYS "*"
}

# Test 15: MongoDB without auth
vulnerable_mongodb() {
    local host="$1"
    # VULNERABLE: MongoDB without authentication
    mongo "$host/admin" --eval "db.getUsers()"
}

