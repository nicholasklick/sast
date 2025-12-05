#!/bin/bash
# Input Validation vulnerabilities in Bash

# Test 1: No length validation
vulnerable_no_length() {
    local input="$1"
    # VULNERABLE: No length check - buffer issues
    echo "$input" > /tmp/data
}

# Test 2: No type validation
vulnerable_no_type() {
    local number="$1"
    # VULNERABLE: Expected number, no validation
    result=$((number * 2))
    echo "$result"
}

# Test 3: No character validation
vulnerable_no_chars() {
    local username="$1"
    # VULNERABLE: Special characters allowed
    useradd "$username"
}

# Test 4: No null byte check
vulnerable_null_byte() {
    local filename="$1"
    # VULNERABLE: Null byte injection
    cat "$filename"
}

# Test 5: No path validation
vulnerable_no_path_check() {
    local path="$1"
    # VULNERABLE: Path traversal possible
    cat "/var/data/$path"
}

# Test 6: No whitespace handling
vulnerable_whitespace() {
    local arg="$1"
    # VULNERABLE: Word splitting
    rm $arg
}

# Test 7: No escape handling
vulnerable_escapes() {
    local data="$1"
    # VULNERABLE: Escape sequences interpreted
    echo -e "$data"
}

# Test 8: No regex validation
vulnerable_no_regex() {
    local email="$1"
    # VULNERABLE: No email format validation
    echo "Email: $email" >> users.txt
}

# Test 9: Trusting Content-Type
vulnerable_content_type() {
    local file="$1"
    local type="$2"
    # VULNERABLE: Trusting user-provided type
    if [ "$type" = "image/png" ]; then
        convert "$file" output.png
    fi
}

# Test 10: No integer bounds
vulnerable_no_bounds() {
    local count="$1"
    # VULNERABLE: No upper bound
    for i in $(seq 1 "$count"); do
        echo "iteration $i"
    done
}

# Test 11: No command whitelist
vulnerable_no_whitelist() {
    local cmd="$1"
    # VULNERABLE: Any command allowed
    $cmd
}

# Test 12: No file extension check
vulnerable_no_extension() {
    local upload="$1"
    # VULNERABLE: Any file type accepted
    cp "$upload" /var/www/uploads/
}

# Test 13: No URL validation
vulnerable_no_url_check() {
    local url="$1"
    # VULNERABLE: Any URL scheme allowed
    curl "$url"
}

# Test 14: No IP validation
vulnerable_no_ip_check() {
    local ip="$1"
    # VULNERABLE: No IP format validation
    ping -c 1 "$ip"
}

# Test 15: No hostname validation
vulnerable_no_hostname() {
    local host="$1"
    # VULNERABLE: No hostname validation
    ssh "user@$host"
}

