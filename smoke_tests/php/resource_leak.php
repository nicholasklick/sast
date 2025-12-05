<?php
// Resource Leak vulnerabilities in PHP

// Test 1: File not closed
function read_file_unsafe() {
    $path = $_GET['path'];
    // VULNERABLE: File handle not closed on exception
    $f = fopen($path, 'r');
    $content = fread($f, filesize($path));
    // fclose($f) might not be reached
    return $content;
}

// Test 2: Socket not closed
function connect_socket() {
    $host = $_GET['host'];
    $port = (int)$_GET['port'];
    // VULNERABLE: Socket leak
    $socket = fsockopen($host, $port);
    $data = fgets($socket);
    echo $data;
    // fclose($socket) never called
}

// Test 3: Database connection not closed
function query_database() {
    $pdo = new PDO('mysql:host=localhost;dbname=test', 'root', 'password');
    // VULNERABLE: Connection not closed
    $stmt = $pdo->query("SELECT * FROM users");
    return $stmt->fetchAll();
    // $pdo = null; not called
}

// Test 4: cURL not closed
function fetch_url() {
    $url = $_GET['url'];
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $result = curl_exec($ch);
    // VULNERABLE: curl_close($ch) never called
    return $result;
}

// Test 5: Early return leak
function conditional_read() {
    $path = $_GET['path'];
    $condition = $_GET['condition'];

    $f = fopen($path, 'r');
    if ($condition === 'skip') {
        // VULNERABLE: Early return without close
        return;
    }
    $content = fread($f, 1024);
    fclose($f);
    return $content;
}

// Test 6: Exception path leak
function process_file() {
    $f = fopen('/tmp/data.txt', 'r');
    try {
        process_content(fread($f, 1024));
    } catch (Exception $e) {
        // VULNERABLE: File not closed in catch
        throw $e;
    }
    fclose($f);
}

// Test 7: Multiple handles not all closed
function multiple_files() {
    $f1 = fopen('/tmp/a.txt', 'r');
    // VULNERABLE: If this fails, f1 leaks
    $f2 = fopen('/tmp/b.txt', 'r');

    $content = fread($f1, 1024) . fread($f2, 1024);

    fclose($f1);
    fclose($f2);
    return $content;
}

// Test 8: Directory handle not closed
function list_directory() {
    $path = $_GET['path'];
    // VULNERABLE: Dir handle not closed
    $dir = opendir($path);
    $entries = [];
    while (($entry = readdir($dir)) !== false) {
        $entries[] = $entry;
    }
    // closedir($dir) never called
    return $entries;
}

// Test 9: proc_open not closed
function run_command() {
    $cmd = $_GET['cmd'];
    $descriptors = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w']
    ];
    // VULNERABLE: Process not closed
    $process = proc_open($cmd, $descriptors, $pipes);
    $output = stream_get_contents($pipes[1]);
    // proc_close($process) never called
    return $output;
}

// Test 10: GD image not destroyed
function process_image() {
    $path = $_GET['path'];
    // VULNERABLE: Image resource not destroyed
    $img = imagecreatefromjpeg($path);
    $width = imagesx($img);
    // imagedestroy($img) never called
    return $width;
}

// Test 11: XMLReader not closed
function read_xml() {
    $path = $_GET['path'];
    $reader = new XMLReader();
    $reader->open($path);
    // VULNERABLE: Reader not closed
    while ($reader->read()) {
        echo $reader->name;
    }
    // $reader->close() never called
}

// Test 12: Stream filter leak
function filtered_read() {
    $path = $_GET['path'];
    $f = fopen($path, 'r');
    $filter = stream_filter_append($f, 'string.toupper');
    $content = fread($f, 1024);
    // VULNERABLE: Filter and handle not cleaned up
    return $content;
}

function process_content($content) {
    if (empty($content)) {
        throw new Exception('Empty content');
    }
}
?>
