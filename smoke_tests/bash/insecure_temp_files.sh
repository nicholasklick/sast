#!/bin/bash
# Insecure Temporary File vulnerabilities in Bash

# Test 1: Predictable temp file name
vulnerable_predictable_temp() {
    # VULNERABLE: Predictable temp file
    TMPFILE="/tmp/myapp_temp.txt"
    echo "data" > "$TMPFILE"
}

# Test 2: Using PID as only unique identifier
vulnerable_pid_temp() {
    # VULNERABLE: PID is predictable
    TMPFILE="/tmp/myapp.$$"
    echo "sensitive data" > "$TMPFILE"
}

# Test 3: Race condition in temp file creation
vulnerable_race_condition() {
    TMPFILE="/tmp/myapp_$$_$(date +%s)"
    # VULNERABLE: TOCTOU race condition
    if [ ! -e "$TMPFILE" ]; then
        echo "data" > "$TMPFILE"
    fi
}

# Test 4: World-readable temp file
vulnerable_permissions() {
    TMPFILE="/tmp/secret_data.txt"
    # VULNERABLE: Default permissions are too open
    echo "password=secret123" > "$TMPFILE"
}

# Test 5: Temp directory not cleaned up
vulnerable_cleanup() {
    TMPDIR="/tmp/myapp_work"
    mkdir -p "$TMPDIR"
    echo "sensitive" > "$TMPDIR/data.txt"
    # VULNERABLE: No cleanup on exit
    # Missing: trap cleanup EXIT
}

# Test 6: Using /tmp without mktemp
vulnerable_no_mktemp() {
    # VULNERABLE: Should use mktemp
    WORKDIR="/tmp/build_output"
    mkdir "$WORKDIR"
    cp secrets.conf "$WORKDIR/"
}

# Test 7: Temp file in current directory
vulnerable_local_temp() {
    # VULNERABLE: Temp in current dir might be shared
    echo "data" > ./temp_file.tmp
}

# Test 8: Symlink attack vector
vulnerable_symlink_attack() {
    TMPFILE="/tmp/app_config_$$"
    # VULNERABLE: Could be symlinked to sensitive file
    echo "config_data" > "$TMPFILE"
}

# Test 9: Insecure umask
vulnerable_umask() {
    # VULNERABLE: Umask too permissive
    umask 000
    echo "secret" > /tmp/secret_file
}

# Test 10: Temp file left with credentials
vulnerable_creds_in_temp() {
    TMPFILE="/tmp/db_creds.txt"
    # VULNERABLE: Credentials in temp file
    echo "user=admin" > "$TMPFILE"
    echo "pass=secret" >> "$TMPFILE"
    mysql --defaults-file="$TMPFILE" -e "SELECT 1"
}

# Test 11: /var/tmp usage (persists across reboots)
vulnerable_var_tmp() {
    # VULNERABLE: /var/tmp persists across reboots
    echo "sensitive_data" > /var/tmp/persistent_temp
}

# Test 12: Shared temp directory
vulnerable_shared_tmp() {
    # VULNERABLE: Shared between users
    SHARED_TMP="/tmp/shared_app"
    mkdir -p "$SHARED_TMP"
    chmod 777 "$SHARED_TMP"
}

# Test 13: Temp file with predictable extension
vulnerable_extension() {
    # VULNERABLE: Predictable pattern
    TMPFILE="/tmp/upload_$(date +%Y%m%d).tmp"
    cat > "$TMPFILE"
}

# Test 14: heredoc to temp file
vulnerable_heredoc_temp() {
    # VULNERABLE: Predictable temp with sensitive data
    cat > /tmp/script_$$.sh << 'EOF'
#!/bin/bash
DB_PASSWORD="secret"
EOF
}

# Test 15: Insecure temp in Docker context
vulnerable_docker_temp() {
    # VULNERABLE: Temp file visible in container
    echo "$DOCKER_PASSWORD" > /tmp/docker_auth
    docker login --password-stdin < /tmp/docker_auth
}
