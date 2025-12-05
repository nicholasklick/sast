#!/bin/bash
# Path Traversal vulnerabilities in Bash

# Test 1: cat with user-controlled path
vulnerable_cat() {
    local file="$1"
    # VULNERABLE: Path traversal via cat
    cat "$file"
}

# Test 2: rm with user path
vulnerable_rm() {
    local path="$1"
    # VULNERABLE: Arbitrary file deletion
    rm -rf "$path"
}

# Test 3: cp with user-controlled destination
vulnerable_cp() {
    local src="$1"
    local dst="$2"
    # VULNERABLE: Path traversal in copy
    cp "$src" "$dst"
}

# Test 4: mv with user paths
vulnerable_mv() {
    local old="$1"
    local new="$2"
    # VULNERABLE: Arbitrary file move
    mv "$old" "$new"
}

# Test 5: mkdir with user path
vulnerable_mkdir() {
    local dir="$1"
    # VULNERABLE: Directory creation outside intended path
    mkdir -p "$dir"
}

# Test 6: ln symlink creation
vulnerable_symlink() {
    local target="$1"
    local link="$2"
    # VULNERABLE: Symlink to arbitrary file
    ln -s "$target" "$link"
}

# Test 7: chmod with user path
vulnerable_chmod() {
    local file="$1"
    # VULNERABLE: Permission change on arbitrary file
    chmod 777 "$file"
}

# Test 8: chown with user path
vulnerable_chown() {
    local file="$1"
    local owner="$2"
    # VULNERABLE: Ownership change
    chown "$owner" "$file"
}

# Test 9: tar extraction
vulnerable_tar() {
    local archive="$1"
    # VULNERABLE: Tar slip / path traversal
    tar xf "$archive"
}

# Test 10: unzip extraction
vulnerable_unzip() {
    local zipfile="$1"
    local dest="$2"
    # VULNERABLE: Zip slip
    unzip "$zipfile" -d "$dest"
}

# Test 11: File append/redirect
vulnerable_redirect() {
    local file="$1"
    local data="$2"
    # VULNERABLE: Arbitrary file write
    echo "$data" >> "$file"
}

# Test 12: tee to user-controlled path
vulnerable_tee() {
    local logfile="$1"
    # VULNERABLE: Write to arbitrary file
    echo "data" | tee "$logfile"
}

# Test 13: dd with user-controlled output
vulnerable_dd() {
    local output="$1"
    # VULNERABLE: Arbitrary file overwrite
    dd if=/dev/zero of="$output" bs=1M count=1
}

# Test 14: touch with user path
vulnerable_touch() {
    local file="$1"
    # VULNERABLE: Create/modify arbitrary file
    touch "$file"
}

# Test 15: head/tail with user file
vulnerable_head() {
    local file="$1"
    # VULNERABLE: Read arbitrary file
    head -n 10 "$file"
}

# Test 16: grep in user directory
vulnerable_grep() {
    local dir="$1"
    local pattern="$2"
    # VULNERABLE: Search in arbitrary directory
    grep -r "$pattern" "$dir"
}

# Test 17: find in user path
vulnerable_find() {
    local path="$1"
    # VULNERABLE: List arbitrary directory
    find "$path" -type f
}

# Test 18: stat/ls user file
vulnerable_stat() {
    local file="$1"
    # VULNERABLE: Information disclosure
    stat "$file"
}
