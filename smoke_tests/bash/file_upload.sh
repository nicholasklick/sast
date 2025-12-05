#!/bin/bash
# File Upload vulnerabilities in Bash

# Test 1: No file type validation
vulnerable_no_validation() {
    local uploaded_file="$1"
    local dest_dir="$2"
    # VULNERABLE: No file type check
    cp "$uploaded_file" "$dest_dir/"
}

# Test 2: Extension-only validation (bypassable)
vulnerable_extension_only() {
    local uploaded_file="$1"
    local dest_dir="$2"
    # VULNERABLE: Extension can be spoofed
    if [[ "$uploaded_file" == *.jpg ]] || [[ "$uploaded_file" == *.png ]]; then
        cp "$uploaded_file" "$dest_dir/"
    fi
}

# Test 3: No size limit
vulnerable_no_size_limit() {
    local uploaded_file="$1"
    local dest_dir="$2"
    # VULNERABLE: No file size validation
    mv "$uploaded_file" "$dest_dir/"
}

# Test 4: Executable upload allowed
vulnerable_executable() {
    local uploaded_file="$1"
    local dest_dir="$2"
    # VULNERABLE: Allows executable files
    cp "$uploaded_file" "$dest_dir/"
    chmod +x "$dest_dir/$(basename "$uploaded_file")"
}

# Test 5: Upload to web-accessible directory
vulnerable_web_dir() {
    local uploaded_file="$1"
    # VULNERABLE: Direct upload to web root
    cp "$uploaded_file" /var/www/html/uploads/
}

# Test 6: Filename from user input
vulnerable_filename() {
    local content="$1"
    local filename="$2"
    # VULNERABLE: User-controlled filename
    echo "$content" > "/uploads/$filename"
}

# Test 7: Double extension bypass
vulnerable_double_ext() {
    local uploaded_file="$1"
    # VULNERABLE: Doesn't check for .php.jpg
    if [[ "$uploaded_file" == *.jpg ]]; then
        cp "$uploaded_file" /var/www/uploads/
    fi
}

# Test 8: MIME type from user
vulnerable_mime_trust() {
    local uploaded_file="$1"
    local mime_type="$2"
    # VULNERABLE: Trusting user-provided MIME type
    if [ "$mime_type" = "image/jpeg" ]; then
        cp "$uploaded_file" /uploads/images/
    fi
}

# Test 9: No content inspection
vulnerable_no_content_check() {
    local uploaded_file="$1"
    # VULNERABLE: Not checking actual file content
    extension="${uploaded_file##*.}"
    if [ "$extension" = "txt" ]; then
        cp "$uploaded_file" /uploads/
    fi
}

# Test 10: Archive upload and extraction
vulnerable_archive_upload() {
    local archive="$1"
    local dest="$2"
    # VULNERABLE: Extracting uploaded archive
    tar xf "$archive" -C "$dest"
}

# Test 11: SVG upload (can contain scripts)
vulnerable_svg() {
    local svg_file="$1"
    # VULNERABLE: SVG can contain JavaScript
    if [[ "$svg_file" == *.svg ]]; then
        cp "$svg_file" /var/www/images/
    fi
}

# Test 12: HTML upload
vulnerable_html() {
    local html_file="$1"
    # VULNERABLE: HTML files can contain scripts
    cp "$html_file" /var/www/uploads/
}

# Test 13: No overwrite protection
vulnerable_overwrite() {
    local uploaded_file="$1"
    local filename="$2"
    # VULNERABLE: Can overwrite existing files
    cp "$uploaded_file" "/uploads/$filename"
}

# Test 14: Null byte in filename
vulnerable_null_byte() {
    local uploaded_file="$1"
    # VULNERABLE: Null byte can truncate extension check
    # shell.php%00.jpg might bypass checks
    cp "$uploaded_file" /uploads/
}

# Test 15: Symlink upload
vulnerable_symlink_upload() {
    local uploaded_file="$1"
    local dest="$2"
    # VULNERABLE: Could upload symlink to sensitive file
    cp -P "$uploaded_file" "$dest/"
}

