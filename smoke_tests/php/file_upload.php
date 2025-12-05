<?php
// File Upload vulnerabilities in PHP

// Test 1: No file type validation
function upload_file() {
    $file = $_FILES['file'];
    // VULNERABLE: No file type checking
    $destination = '/uploads/' . $file['name'];
    move_uploaded_file($file['tmp_name'], $destination);
}

// Test 2: Extension-only validation
function upload_image_ext() {
    $file = $_FILES['file'];
    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    // VULNERABLE: Can bypass with double extension
    $allowed = ['jpg', 'png', 'gif'];
    if (in_array($ext, $allowed)) {
        move_uploaded_file($file['tmp_name'], '/images/' . $file['name']);
    }
}

// Test 3: MIME type only validation
function upload_mime() {
    $file = $_FILES['file'];
    // VULNERABLE: MIME type can be spoofed
    if (strpos($file['type'], 'image/') === 0) {
        move_uploaded_file($file['tmp_name'], '/uploads/' . $file['name']);
    }
}

// Test 4: Path traversal in filename
function upload_traversal() {
    $file = $_FILES['file'];
    // VULNERABLE: Filename can contain ../
    $path = '/uploads/' . $file['name'];
    move_uploaded_file($file['tmp_name'], $path);
}

// Test 5: Upload to web root
function upload_webroot() {
    $file = $_FILES['file'];
    // VULNERABLE: Can upload PHP files to webroot
    $path = $_SERVER['DOCUMENT_ROOT'] . '/' . $file['name'];
    move_uploaded_file($file['tmp_name'], $path);
}

// Test 6: No file size limit
function upload_large() {
    $file = $_FILES['file'];
    // VULNERABLE: No size check - DoS possible
    move_uploaded_file($file['tmp_name'], '/uploads/' . $file['name']);
}

// Test 7: ZIP bomb
function upload_extract_zip() {
    $file = $_FILES['file'];
    $zip = new ZipArchive();
    $zip->open($file['tmp_name']);
    // VULNERABLE: No decompression bomb protection
    $zip->extractTo('/extracted/');
    $zip->close();
}

// Test 8: getimagesize bypass
function upload_getimagesize() {
    $file = $_FILES['file'];
    // VULNERABLE: Can be bypassed with polyglot files
    if (getimagesize($file['tmp_name'])) {
        move_uploaded_file($file['tmp_name'], '/images/' . $file['name']);
    }
}

// Test 9: Blacklist validation
function upload_blacklist() {
    $file = $_FILES['file'];
    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    $blocked = ['php', 'exe', 'bat'];
    // VULNERABLE: Blacklist incomplete (.phtml, .php5, etc.)
    if (!in_array($ext, $blocked)) {
        move_uploaded_file($file['tmp_name'], '/uploads/' . $file['name']);
    }
}

// Test 10: Null byte injection (older PHP)
function upload_null_byte() {
    $file = $_FILES['file'];
    $ext = pathinfo($file['name'], PATHINFO_EXTENSION);
    // VULNERABLE: shell.php%00.jpg passed as jpg in older PHP
    if ($ext === 'jpg') {
        move_uploaded_file($file['tmp_name'], '/images/' . $file['name']);
    }
}

// Test 11: Race condition
function upload_race() {
    $file = $_FILES['file'];
    $path = '/uploads/' . $file['name'];
    // VULNERABLE: TOCTOU race condition
    if (!file_exists($path)) {
        move_uploaded_file($file['tmp_name'], $path);
    }
}

// Test 12: SVG upload (XSS)
function upload_svg() {
    $file = $_FILES['file'];
    $ext = pathinfo($file['name'], PATHINFO_EXTENSION);
    // VULNERABLE: SVG can contain JavaScript
    if ($ext === 'svg') {
        move_uploaded_file($file['tmp_name'], '/images/' . $file['name']);
    }
}

// Test 13: GD library bypass
function upload_gd_bypass() {
    $file = $_FILES['file'];
    // VULNERABLE: GD can be bypassed with specially crafted images
    $img = imagecreatefromstring(file_get_contents($file['tmp_name']));
    if ($img) {
        move_uploaded_file($file['tmp_name'], '/images/' . $file['name']);
    }
}
?>
