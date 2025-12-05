#!/bin/bash
# Privilege Escalation vulnerabilities in Bash

# Test 1: SUID binary creation
vulnerable_suid() {
    local binary="$1"
    # VULNERABLE: Creating SUID binary
    chmod u+s "$binary"
}

# Test 2: Sudoers modification
vulnerable_sudoers() {
    local user="$1"
    # VULNERABLE: Adding user to sudoers
    echo "$user ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
}

# Test 3: Writable PATH directory
vulnerable_writable_path() {
    # VULNERABLE: World-writable in PATH
    mkdir -p /tmp/bin
    chmod 777 /tmp/bin
    export PATH="/tmp/bin:$PATH"
}

# Test 4: Cron job with user input
vulnerable_cron_job() {
    local cmd="$1"
    # VULNERABLE: Arbitrary cron job
    echo "* * * * * root $cmd" >> /etc/crontab
}

# Test 5: Wildcard injection in privileged script
vulnerable_wildcard() {
    local dir="$1"
    # VULNERABLE: Wildcard injection
    cd "$dir"
    tar cf /backup/archive.tar *
}

# Test 6: Insecure service file
vulnerable_service() {
    local exec="$1"
    # VULNERABLE: Arbitrary service execution
    cat > /etc/systemd/system/vuln.service << EOF
[Service]
ExecStart=$exec
User=root
EOF
    systemctl daemon-reload
}

# Test 7: World-writable script in PATH
vulnerable_writable_script() {
    local script="$1"
    # VULNERABLE: World-writable executable
    chmod 777 "$script"
    mv "$script" /usr/local/bin/
}

# Test 8: Unsafe file ownership
vulnerable_ownership() {
    local file="$1"
    local owner="$2"
    # VULNERABLE: Changing ownership
    chown "$owner" "$file"
}

# Test 9: Capabilities manipulation
vulnerable_capabilities() {
    local binary="$1"
    # VULNERABLE: Adding dangerous capabilities
    setcap cap_setuid+ep "$binary"
}

# Test 10: Shared library injection
vulnerable_shared_lib() {
    local lib="$1"
    # VULNERABLE: Adding to library path
    cp "$lib" /usr/lib/
    ldconfig
}

# Test 11: init.d script injection
vulnerable_initd() {
    local script="$1"
    # VULNERABLE: Init script injection
    cp "$script" /etc/init.d/
    chmod +x /etc/init.d/"$(basename "$script")"
    update-rc.d "$(basename "$script")" defaults
}

# Test 12: PAM configuration
vulnerable_pam() {
    local module="$1"
    # VULNERABLE: PAM module injection
    echo "auth sufficient $module" >> /etc/pam.d/common-auth
}

# Test 13: SSH authorized keys
vulnerable_ssh_keys() {
    local key="$1"
    # VULNERABLE: SSH key injection
    echo "$key" >> /root/.ssh/authorized_keys
}

# Test 14: /etc/passwd modification
vulnerable_passwd() {
    local entry="$1"
    # VULNERABLE: Adding user to passwd
    echo "$entry" >> /etc/passwd
}

# Test 15: Group membership
vulnerable_group() {
    local user="$1"
    # VULNERABLE: Adding to privileged groups
    usermod -aG sudo "$user"
    usermod -aG wheel "$user"
    usermod -aG docker "$user"
}

