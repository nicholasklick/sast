<?php
// XPath Injection vulnerabilities in PHP

// Test 1: SimpleXML XPath with user input
function search_simplexml() {
    $username = $_GET['username'];
    $xml = simplexml_load_file('users.xml');
    // VULNERABLE: User input in XPath
    $result = $xml->xpath("//user[name='$username']");
    return $result;
}

// Test 2: Authentication bypass
function authenticate_xpath() {
    $username = $_POST['username'];
    $password = $_POST['password'];

    $xml = simplexml_load_file('users.xml');
    // VULNERABLE: ' or '1'='1 bypasses auth
    $xpath = "//user[name='$username' and password='$password']";
    $user = $xml->xpath($xpath);

    return count($user) > 0;
}

// Test 3: DOMXPath with user input
function search_domxpath() {
    $query = $_GET['query'];

    $doc = new DOMDocument();
    $doc->load('data.xml');
    $xpath = new DOMXPath($doc);

    // VULNERABLE: User input in XPath query
    $results = $xpath->query("//item[contains(name, '$query')]");
    return $results;
}

// Test 4: Numeric injection
function get_by_id() {
    $id = $_GET['id'];

    $xml = simplexml_load_file('users.xml');
    // VULNERABLE: 1 or 1=1 returns all
    $result = $xml->xpath("//user[@id=$id]");
    return $result;
}

// Test 5: OR injection
function search_by_role() {
    $role = $_GET['role'];

    $xml = simplexml_load_file('users.xml');
    // VULNERABLE: ' or '1'='1 returns all
    $results = $xml->xpath("//user[role='$role']");
    return count($results);
}

// Test 6: Function injection
function search_contains() {
    $pattern = $_GET['pattern'];

    $doc = new DOMDocument();
    $doc->load('items.xml');
    $xpath = new DOMXPath($doc);

    // VULNERABLE: XPath function manipulation
    $results = $xpath->query("//item[contains(description, '$pattern')]");
    return $results->length;
}

// Test 7: Axis navigation
function get_parent() {
    $element = $_GET['element'];

    $doc = new DOMDocument();
    $doc->load('data.xml');
    $xpath = new DOMXPath($doc);

    // VULNERABLE: Can navigate to unintended nodes
    $results = $xpath->query("//data/$element");
    return $results->length;
}

// Test 8: Wildcard injection
function search_wildcard() {
    $prefix = $_GET['prefix'];

    $xml = simplexml_load_file('users.xml');
    // VULNERABLE: Wildcard with user input
    $results = $xml->xpath("//user[starts-with(name, '$prefix')]");
    return count($results);
}

// Test 9: Multiple parameters
function advanced_search() {
    $name = $_GET['name'];
    $role = $_GET['role'];
    $status = $_GET['status'];

    $xml = simplexml_load_file('users.xml');
    // VULNERABLE: Multiple injection points
    $xpath = "//user[name='$name' and role='$role' and status='$status']";
    return $xml->xpath($xpath);
}

// Test 10: DOMXPath evaluate
function evaluate_xpath() {
    $expression = $_GET['expr'];

    $doc = new DOMDocument();
    $doc->load('data.xml');
    $xpath = new DOMXPath($doc);

    // VULNERABLE: User controls XPath expression
    $result = $xpath->evaluate($expression);
    return $result;
}

// Test 11: XPath in XSLT
function transform_with_xpath() {
    $search = $_GET['search'];

    $xsl = new DOMDocument();
    $xsl->loadXML("
        <xsl:stylesheet version='1.0' xmlns:xsl='http://www.w3.org/1999/XSL/Transform'>
            <xsl:template match='/'>
                <xsl:copy-of select=\"//item[name='$search']\"/>
            </xsl:template>
        </xsl:stylesheet>
    ");

    $proc = new XSLTProcessor();
    $proc->importStylesheet($xsl);

    $xml = new DOMDocument();
    $xml->load('items.xml');

    return $proc->transformToXML($xml);
}
?>
