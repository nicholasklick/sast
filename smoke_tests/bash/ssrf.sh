#!/bin/bash
# SSRF vulnerabilities in Bash

# Test 1: curl with user-controlled URL
vulnerable_curl() {
    local url="$1"
    # VULNERABLE: SSRF via curl
    curl "$url"
}

# Test 2: wget with user-controlled URL
vulnerable_wget() {
    local url="$1"
    # VULNERABLE: SSRF via wget
    wget "$url"
}

# Test 3: curl with user-controlled host
vulnerable_curl_host() {
    local host="$1"
    # VULNERABLE: SSRF via host parameter
    curl "http://$host/api/data"
}

# Test 4: wget output to file
vulnerable_wget_output() {
    local url="$1"
    local output="$2"
    # VULNERABLE: SSRF + path traversal
    wget "$url" -O "$output"
}

# Test 5: curl with user headers
vulnerable_curl_headers() {
    local url="$1"
    local header="$2"
    # VULNERABLE: SSRF with header injection
    curl -H "$header" "$url"
}

# Test 6: curl POST with user data
vulnerable_curl_post() {
    local url="$1"
    local data="$2"
    # VULNERABLE: SSRF with data exfiltration
    curl -X POST -d "$data" "$url"
}

# Test 7: nc/netcat connection
vulnerable_netcat() {
    local host="$1"
    local port="$2"
    # VULNERABLE: Arbitrary network connection
    nc "$host" "$port"
}

# Test 8: telnet connection
vulnerable_telnet() {
    local host="$1"
    local port="$2"
    # VULNERABLE: Arbitrary telnet connection
    telnet "$host" "$port"
}

# Test 9: curl to internal service
vulnerable_internal_ssrf() {
    local service="$1"
    # VULNERABLE: Internal service access
    curl "http://localhost:$service/admin"
}

# Test 10: wget with proxy
vulnerable_wget_proxy() {
    local proxy="$1"
    local url="$2"
    # VULNERABLE: SSRF via proxy
    wget -e "http_proxy=$proxy" "$url"
}

# Test 11: curl file protocol
vulnerable_curl_file() {
    local path="$1"
    # VULNERABLE: Local file read via SSRF
    curl "file://$path"
}

# Test 12: dig/nslookup with user domain
vulnerable_dns() {
    local domain="$1"
    # VULNERABLE: DNS rebinding potential
    dig "$domain"
}

# Test 13: curl with user-controlled port
vulnerable_port_scan() {
    local port="$1"
    # VULNERABLE: Internal port scanning
    curl "http://127.0.0.1:$port"
}

# Test 14: wget spider mode
vulnerable_wget_spider() {
    local url="$1"
    # VULNERABLE: Website crawling
    wget --spider -r "$url"
}

# Test 15: curl FTP protocol
vulnerable_ftp() {
    local url="$1"
    # VULNERABLE: FTP SSRF
    curl "ftp://$url"
}

