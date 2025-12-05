<?php
// File Inclusion vulnerabilities in PHP (LFI/RFI)

// Test 1: Local File Inclusion via include
function include_page() {
    $page = $_GET['page'];
    // VULNERABLE: Path traversal allows arbitrary file read
    include($page);
}

// Test 2: require with user input
function require_template() {
    $template = $_GET['template'];
    // VULNERABLE: LFI via require
    require($template . '.php');
}

// Test 3: include_once with user path
function load_module() {
    $module = $_GET['module'];
    // VULNERABLE: LFI via include_once
    include_once("modules/$module.php");
}

// Test 4: Remote File Inclusion (if allow_url_include is on)
function include_remote() {
    $url = $_GET['url'];
    // VULNERABLE: RFI if allow_url_include=On
    include($url);
}

// Test 5: Null byte injection (older PHP versions)
function include_with_extension() {
    $file = $_GET['file'];
    // VULNERABLE: Null byte terminates string in older PHP
    // ?file=../../../etc/passwd%00
    include($file . '.php');
}

// Test 6: Path traversal with include
function include_config() {
    $config = $_GET['config'];
    // VULNERABLE: ../../../etc/passwd
    include("config/$config");
}

// Test 7: file_get_contents LFI
function read_file() {
    $file = $_GET['file'];
    // VULNERABLE: Reads arbitrary files
    echo file_get_contents($file);
}

// Test 8: fopen LFI
function open_file() {
    $filename = $_GET['filename'];
    // VULNERABLE: Opens arbitrary files
    $handle = fopen($filename, 'r');
    echo fread($handle, filesize($filename));
    fclose($handle);
}

// Test 9: readfile LFI
function download_file() {
    $file = $_GET['file'];
    // VULNERABLE: Reads and outputs arbitrary files
    readfile($file);
}

// Test 10: PHP wrapper exploitation
function include_wrapper() {
    $input = $_GET['input'];
    // VULNERABLE: php://filter can read source code
    // ?input=php://filter/convert.base64-encode/resource=config.php
    include($input);
}

// Test 11: Zip wrapper exploitation
function include_zip() {
    $archive = $_GET['archive'];
    $file = $_GET['file'];
    // VULNERABLE: zip:// wrapper can execute code
    include("zip://$archive#$file");
}

// Test 12: phar:// wrapper exploitation
function include_phar() {
    $path = $_GET['path'];
    // VULNERABLE: phar:// can deserialize and execute code
    include("phar://$path");
}

// Test 13: data:// wrapper RCE
function include_data() {
    $data = $_GET['data'];
    // VULNERABLE: data:// wrapper executes code
    // ?data=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==
    include($data);
}

// Test 14: Log poisoning setup
function include_log() {
    $logfile = $_GET['log'];
    // VULNERABLE: If log contains user-controlled content
    include("/var/log/$logfile");
}

// Test 15: Session file inclusion
function include_session() {
    $session = $_GET['session'];
    // VULNERABLE: Session files can contain user data
    include("/var/lib/php/sessions/sess_$session");
}
?>
