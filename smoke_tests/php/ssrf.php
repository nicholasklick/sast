<?php
// Server-Side Request Forgery (SSRF) vulnerabilities in PHP

// Test 1: file_get_contents with user URL
function fetch_url_file_get() {
    $url = $_GET['url'];
    // VULNERABLE: User-controlled URL
    $content = file_get_contents($url);
    echo $content;
}

// Test 2: cURL with user URL
function fetch_url_curl() {
    $url = $_GET['url'];
    $ch = curl_init();
    // VULNERABLE: User-controlled URL
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    curl_close($ch);
    echo $response;
}

// Test 3: fopen with user URL
function fetch_url_fopen() {
    $url = $_GET['url'];
    // VULNERABLE: User-controlled URL
    $handle = fopen($url, 'r');
    $content = stream_get_contents($handle);
    fclose($handle);
    echo $content;
}

// Test 4: Partial URL construction
function fetch_from_host() {
    $host = $_GET['host'];
    // VULNERABLE: User controls hostname
    $url = "http://{$host}/api/data";
    $content = file_get_contents($url);
    echo $content;
}

// Test 5: Port scanning
function check_port() {
    $port = $_GET['port'];
    // VULNERABLE: User controls port
    $url = "http://internal-server:{$port}/";
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    $result = curl_exec($ch);
    echo $result ? 'open' : 'closed';
}

// Test 6: Image proxy
function image_proxy() {
    $image_url = $_GET['src'];
    // VULNERABLE: Can fetch internal resources
    $image = file_get_contents($image_url);
    header('Content-Type: image/png');
    echo $image;
}

// Test 7: Webhook URL
function send_webhook() {
    $webhook_url = $_POST['webhook'];
    $data = $_POST['data'];
    // VULNERABLE: User-controlled webhook
    $ch = curl_init($webhook_url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
    curl_exec($ch);
}

// Test 8: DNS rebinding
function fetch_external() {
    $domain = $_GET['domain'];
    // VULNERABLE: DNS can resolve to internal IP
    $url = "http://{$domain}/data";
    echo file_get_contents($url);
}

// Test 9: File protocol SSRF
function read_resource() {
    $uri = $_GET['uri'];
    // VULNERABLE: Could be file:///etc/passwd
    echo file_get_contents($uri);
}

// Test 10: SOAP client with user URL
function soap_request() {
    $wsdl = $_GET['wsdl'];
    // VULNERABLE: User-controlled WSDL location
    $client = new SoapClient($wsdl);
    return $client->__getFunctions();
}

// Test 11: GuzzleHTTP with user URL
function guzzle_fetch() {
    $url = $_GET['url'];
    $client = new \GuzzleHttp\Client();
    // VULNERABLE: User-controlled URL
    $response = $client->get($url);
    echo $response->getBody();
}

// Test 12: follow redirects
function fetch_with_redirect() {
    $url = $_GET['url'];
    $ch = curl_init($url);
    // VULNERABLE: Following redirects to internal resources
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_MAXREDIRS, 10);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    echo curl_exec($ch);
}
?>
