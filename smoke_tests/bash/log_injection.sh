#!/bin/bash
# Log Injection vulnerabilities in Bash

# Test 1: Unsanitized user input in logs
vulnerable_log_input() {
    local user_input="$1"
    # VULNERABLE: Log injection
    echo "$(date) - User action: $user_input" >> /var/log/app.log
}

# Test 2: Logger with user data
vulnerable_logger() {
    local message="$1"
    # VULNERABLE: Syslog injection
    logger "Application event: $message"
}

# Test 3: Printf to log file
vulnerable_printf_log() {
    local data="$1"
    # VULNERABLE: Format string in log
    printf "Event: %s\n" "$data" >> /var/log/events.log
}

# Test 4: Tee to log
vulnerable_tee_log() {
    local input="$1"
    # VULNERABLE: Log injection via tee
    echo "Received: $input" | tee -a /var/log/received.log
}

# Test 5: Apache/nginx log injection
vulnerable_access_log() {
    local user_agent="$1"
    # VULNERABLE: User-agent in logs
    curl -A "$user_agent" http://localhost/
}

# Test 6: Multi-line log injection
vulnerable_multiline() {
    local input="$1"
    # VULNERABLE: Can inject multiple log lines
    echo "[INFO] Processing: $input" >> /var/log/process.log
}

# Test 7: Timestamp forgery
vulnerable_timestamp() {
    local event="$1"
    # VULNERABLE: Event can contain fake timestamps
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $event" >> /var/log/audit.log
}

# Test 8: Log file path injection
vulnerable_log_path() {
    local logfile="$1"
    local message="$2"
    # VULNERABLE: Arbitrary file write
    echo "$message" >> "$logfile"
}

# Test 9: JSON log injection
vulnerable_json_log() {
    local username="$1"
    local action="$2"
    # VULNERABLE: JSON injection in logs
    echo "{\"user\": \"$username\", \"action\": \"$action\"}" >> /var/log/json.log
}

# Test 10: Syslog facility injection
vulnerable_syslog() {
    local priority="$1"
    local msg="$2"
    # VULNERABLE: Priority manipulation
    logger -p "$priority" "$msg"
}

# Test 11: Log rotation bypass
vulnerable_rotation() {
    local data="$1"
    # VULNERABLE: Could overflow logs
    for i in $(seq 1 10000); do
        echo "$data" >> /var/log/overflow.log
    done
}

# Test 12: Audit log tampering
vulnerable_audit() {
    local user="$1"
    local ip="$2"
    # VULNERABLE: Can inject false audit entries
    echo "LOGIN SUCCESS: user=$user ip=$ip" >> /var/log/auth.log
}

# Test 13: Journalctl injection
vulnerable_journalctl() {
    local message="$1"
    # VULNERABLE: Systemd journal injection
    systemd-cat echo "$message"
}

# Test 14: CSV log injection
vulnerable_csv_log() {
    local field1="$1"
    local field2="$2"
    # VULNERABLE: CSV injection
    echo "$field1,$field2" >> /var/log/data.csv
}

# Test 15: Error log injection
vulnerable_error_log() {
    local error="$1"
    # VULNERABLE: Fake error injection
    echo "ERROR: $error" >&2 2>> /var/log/error.log
}

