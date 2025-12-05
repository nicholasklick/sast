#!/bin/bash
# Information Disclosure vulnerabilities in Bash

# Test 1: Echoing sensitive environment variables
vulnerable_env_echo() {
    # VULNERABLE: Exposing secrets in output
    echo "Database password: $DB_PASSWORD"
}

# Test 2: Logging credentials
vulnerable_log_creds() {
    local user="$1"
    local pass="$2"
    # VULNERABLE: Credentials in logs
    echo "$(date) - Login attempt: user=$user, password=$pass" >> /var/log/app.log
}

# Test 3: Error messages with sensitive data
vulnerable_error_msg() {
    local config_file="$1"
    # VULNERABLE: Exposing internal paths
    if [ ! -f "$config_file" ]; then
        echo "Error: Config not found at $config_file on server $(hostname)"
    fi
}

# Test 4: Debug output enabled
vulnerable_debug() {
    # VULNERABLE: Debug information exposure
    set -x
    mysql -u admin -pSecret123 -h localhost
    set +x
}

# Test 5: Exposing system information
vulnerable_sysinfo() {
    # VULNERABLE: System enumeration data
    echo "OS: $(uname -a)"
    echo "Kernel: $(cat /proc/version)"
    echo "Users: $(cat /etc/passwd)"
}

# Test 6: Exposing process list
vulnerable_processes() {
    # VULNERABLE: May expose sensitive command arguments
    ps aux
}

# Test 7: Dumping environment
vulnerable_env_dump() {
    # VULNERABLE: All environment variables exposed
    env
    printenv
}

# Test 8: Exposing network config
vulnerable_network_info() {
    # VULNERABLE: Network enumeration
    ifconfig -a
    netstat -an
    ss -tuln
}

# Test 9: Directory listing exposure
vulnerable_dir_list() {
    local dir="$1"
    # VULNERABLE: May expose sensitive files
    ls -la "$dir"
    find "$dir" -type f
}

# Test 10: Stack trace in error
vulnerable_stack_trace() {
    # VULNERABLE: Exposing internals
    set -e
    trap 'echo "Error at line $LINENO: $BASH_COMMAND"' ERR
}

# Test 11: Git information exposure
vulnerable_git_info() {
    # VULNERABLE: Repository information
    git log --oneline -20
    cat .git/config
}

# Test 12: Package version disclosure
vulnerable_versions() {
    # VULNERABLE: Version enumeration
    dpkg -l
    rpm -qa
    pip list
}

# Test 13: Cron jobs exposure
vulnerable_cron() {
    # VULNERABLE: Scheduled tasks exposure
    crontab -l
    cat /etc/crontab
}

# Test 14: SSH key exposure
vulnerable_ssh_keys() {
    # VULNERABLE: Private key exposure
    cat ~/.ssh/id_rsa
    cat ~/.ssh/config
}

# Test 15: Config file exposure
vulnerable_config_exposure() {
    # VULNERABLE: Configuration disclosure
    cat /etc/shadow
    cat /etc/mysql/my.cnf
    cat ~/.aws/credentials
}

