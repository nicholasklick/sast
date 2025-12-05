#!/bin/bash
# Race Condition vulnerabilities in Bash

# Test 1: TOCTOU in file check
vulnerable_toctou_check() {
    local file="$1"
    # VULNERABLE: Time-of-check to time-of-use
    if [ -f "$file" ]; then
        cat "$file"
    fi
}

# Test 2: TOCTOU in file write
vulnerable_toctou_write() {
    local file="$1"
    local data="$2"
    # VULNERABLE: Race between check and write
    if [ ! -f "$file" ]; then
        echo "$data" > "$file"
    fi
}

# Test 3: TOCTOU in ownership check
vulnerable_toctou_owner() {
    local file="$1"
    # VULNERABLE: Ownership can change
    if [ -O "$file" ]; then
        chmod 755 "$file"
    fi
}

# Test 4: Race in temp file creation
vulnerable_temp_race() {
    local base="$1"
    # VULNERABLE: Race in temp creation
    TMPFILE="/tmp/$base.$$"
    if [ ! -e "$TMPFILE" ]; then
        touch "$TMPFILE"
        echo "data" > "$TMPFILE"
    fi
}

# Test 5: Race in directory creation
vulnerable_dir_race() {
    local dir="$1"
    # VULNERABLE: Directory race condition
    if [ ! -d "$dir" ]; then
        mkdir "$dir"
        chmod 700 "$dir"
    fi
}

# Test 6: Lock file race
vulnerable_lock_race() {
    local lockfile="$1"
    # VULNERABLE: Race in lock acquisition
    if [ ! -f "$lockfile" ]; then
        touch "$lockfile"
        # Critical section
        rm "$lockfile"
    fi
}

# Test 7: Symlink check race
vulnerable_symlink_race() {
    local file="$1"
    # VULNERABLE: Symlink can be created between check and use
    if [ ! -L "$file" ]; then
        echo "safe data" > "$file"
    fi
}

# Test 8: PID file race
vulnerable_pid_race() {
    local pidfile="$1"
    # VULNERABLE: PID file race condition
    if [ ! -f "$pidfile" ]; then
        echo $$ > "$pidfile"
    fi
}

# Test 9: Signal handler race
vulnerable_signal_race() {
    local tmpfile="$1"
    # VULNERABLE: Race in cleanup
    cleanup() {
        if [ -f "$tmpfile" ]; then
            rm "$tmpfile"
        fi
    }
    trap cleanup EXIT
}

# Test 10: Resource exhaustion race
vulnerable_resource_race() {
    local count="$1"
    # VULNERABLE: Resource check race
    current=$(ps aux | wc -l)
    if [ "$current" -lt "$count" ]; then
        ./spawn_process &
    fi
}

# Test 11: Permission check race
vulnerable_perm_race() {
    local file="$1"
    # VULNERABLE: Permission can change
    if [ -r "$file" ]; then
        cat "$file"
    fi
}

# Test 12: Existence check race
vulnerable_exist_race() {
    local src="$1"
    local dst="$2"
    # VULNERABLE: Source/dest can change
    if [ -f "$src" ] && [ ! -f "$dst" ]; then
        cp "$src" "$dst"
    fi
}

# Test 13: Mount point race
vulnerable_mount_race() {
    local path="$1"
    # VULNERABLE: Mount can change
    if mountpoint -q "$path"; then
        rm -rf "$path"/*
    fi
}

# Test 14: User existence race
vulnerable_user_race() {
    local user="$1"
    # VULNERABLE: User can be added between check and use
    if ! id "$user" &>/dev/null; then
        useradd "$user"
    fi
}

# Test 15: Process check race
vulnerable_process_race() {
    local pidfile="$1"
    # VULNERABLE: Process can exit between check and signal
    pid=$(cat "$pidfile" 2>/dev/null)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        kill -9 "$pid"
    fi
}

