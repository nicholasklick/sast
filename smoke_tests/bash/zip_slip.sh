#!/bin/bash
# Zip Slip vulnerabilities in Bash

# Test 1: tar extraction without path checking
vulnerable_tar() {
    local archive="$1"
    local dest="$2"
    # VULNERABLE: tar preserves paths including ../
    tar xf "$archive" -C "$dest"
}

# Test 2: unzip without path validation
vulnerable_unzip() {
    local zipfile="$1"
    local dest="$2"
    # VULNERABLE: unzip extracts relative paths
    unzip "$zipfile" -d "$dest"
}

# Test 3: gunzip with path
vulnerable_gunzip() {
    local gzfile="$1"
    # VULNERABLE: Output path not validated
    gunzip -c "$gzfile" > "$(basename "${gzfile%.gz}")"
}

# Test 4: 7z extraction
vulnerable_7z() {
    local archive="$1"
    local dest="$2"
    # VULNERABLE: 7z extracts paths as-is
    7z x "$archive" -o"$dest"
}

# Test 5: cpio extraction
vulnerable_cpio() {
    local archive="$1"
    # VULNERABLE: cpio preserves paths
    cpio -idv < "$archive"
}

# Test 6: jar extraction
vulnerable_jar() {
    local jarfile="$1"
    local dest="$2"
    # VULNERABLE: jar xf extracts paths
    cd "$dest" && jar xf "$jarfile"
}

# Test 7: ar extraction
vulnerable_ar() {
    local archive="$1"
    # VULNERABLE: ar extracts with paths
    ar x "$archive"
}

# Test 8: rpm extraction
vulnerable_rpm() {
    local rpmfile="$1"
    local dest="$2"
    # VULNERABLE: rpm2cpio preserves paths
    cd "$dest" && rpm2cpio "$rpmfile" | cpio -idmv
}

# Test 9: deb extraction
vulnerable_deb() {
    local debfile="$1"
    local dest="$2"
    # VULNERABLE: dpkg extracts with paths
    dpkg -x "$debfile" "$dest"
}

# Test 10: xz extraction
vulnerable_xz() {
    local xzfile="$1"
    local outfile="$2"
    # VULNERABLE: Output path from user input
    xz -dk "$xzfile" -c > "$outfile"
}

# Test 11: bzip2 extraction
vulnerable_bzip2() {
    local bzfile="$1"
    local outfile="$2"
    # VULNERABLE: User-controlled output path
    bunzip2 -c "$bzfile" > "$outfile"
}

# Test 12: zstd extraction
vulnerable_zstd() {
    local zstfile="$1"
    local outfile="$2"
    # VULNERABLE: User-controlled extraction
    zstd -d "$zstfile" -o "$outfile"
}

# Test 13: Python zipfile via bash
vulnerable_python_zip() {
    local zipfile="$1"
    local dest="$2"
    # VULNERABLE: Python extractall without checks
    python -c "import zipfile; zipfile.ZipFile('$zipfile').extractall('$dest')"
}

# Test 14: Ruby unzip via bash
vulnerable_ruby_zip() {
    local zipfile="$1"
    local dest="$2"
    # VULNERABLE: Ruby extraction
    ruby -e "require 'zip'; Zip::File.open('$zipfile') { |z| z.each { |f| z.extract(f, '$dest/' + f.name) } }"
}

# Test 15: Loop extraction without validation
vulnerable_loop_extract() {
    local zipfile="$1"
    local dest="$2"
    # VULNERABLE: No path validation in loop
    unzip -l "$zipfile" | awk 'NR>3 {print $4}' | while read -r file; do
        unzip -p "$zipfile" "$file" > "$dest/$file"
    done
}

