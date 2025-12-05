<?php
// Denial of Service vulnerabilities in PHP

// Test 1: Unbounded array allocation
function create_array() {
    $size = (int)$_GET['size'];
    // VULNERABLE: User controls array size
    $data = array_fill(0, $size, 'x');
    echo json_encode(['length' => count($data)]);
}

// Test 2: Unbounded string multiplication
function repeat_string() {
    $count = (int)$_GET['count'];
    // VULNERABLE: User controls repetition
    $result = str_repeat('x', $count);
    echo $result;
}

// Test 3: ReDoS
function validate_input() {
    $input = $_GET['input'];
    // VULNERABLE: Catastrophic backtracking
    preg_match('/^(a+)+$/', $input);
}

// Test 4: XML bomb (billion laughs)
function parse_xml() {
    $xml = $_POST['xml'];
    // VULNERABLE: Entity expansion not limited
    libxml_disable_entity_loader(false);
    $doc = new DOMDocument();
    $doc->loadXML($xml, LIBXML_NOENT);
    echo $doc->saveXML();
}

// Test 5: Hash collision
function store_data() {
    // VULNERABLE: Hash collision with crafted keys
    $data = [];
    foreach ($_POST as $key => $value) {
        $data[$key] = $value;
    }
    echo json_encode(['count' => count($data)]);
}

// Test 6: JSON parsing large numbers
function parse_json() {
    $json = $_POST['json'];
    // VULNERABLE: Large numbers/deep nesting
    $data = json_decode($json, true, 512);
    echo json_encode($data);
}

// Test 7: CPU exhaustion
function compute() {
    $iterations = (int)$_GET['n'];
    // VULNERABLE: User controls computation
    $result = 0;
    for ($i = 0; $i < $iterations; $i++) {
        $result += sin($i) * cos($i);
    }
    echo $result;
}

// Test 8: File read amplification
function read_file() {
    $path = $_GET['path'];
    // VULNERABLE: No size limit on file read
    echo file_get_contents($path);
}

// Test 9: ZIP bomb
function extract_zip() {
    $file = $_FILES['file'];
    $zip = new ZipArchive();
    $zip->open($file['tmp_name']);
    // VULNERABLE: No decompression ratio limit
    $zip->extractTo('/tmp/extracted/');
    $zip->close();
}

// Test 10: Synchronous blocking
function slow_operation() {
    $delay = (int)$_GET['delay'];
    // VULNERABLE: User controls blocking time
    sleep($delay);
    echo 'done';
}

// Test 11: Fork bomb setup
function spawn_processes() {
    $count = (int)$_GET['count'];
    // VULNERABLE: User controls process spawning
    for ($i = 0; $i < $count; $i++) {
        pcntl_fork();
    }
}

// Test 12: Memory exhaustion via image
function process_image() {
    $width = (int)$_GET['width'];
    $height = (int)$_GET['height'];
    // VULNERABLE: User controls image dimensions
    $image = imagecreatetruecolor($width, $height);
    // Large dimensions cause memory exhaustion
}

// Test 13: Recursive function with user depth
function recursive_process($depth = 0) {
    $max_depth = (int)$_GET['depth'];
    // VULNERABLE: User controls recursion depth
    if ($depth < $max_depth) {
        recursive_process($depth + 1);
    }
}

// Test 14: File upload exhaustion
function handle_uploads() {
    // VULNERABLE: No limit on number of files
    foreach ($_FILES as $file) {
        move_uploaded_file($file['tmp_name'], '/uploads/' . $file['name']);
    }
}
?>
