<?php
// XXE (XML External Entity) vulnerabilities in PHP

// Test 1: SimpleXML with external entities
function parse_simplexml() {
    $xml = $_POST['xml'];
    // VULNERABLE: External entities enabled by default in older PHP
    $doc = simplexml_load_string($xml);
    echo $doc->asXML();
}

// Test 2: DOMDocument with DTD loading
function parse_domdocument() {
    $xml = $_POST['xml'];
    $doc = new DOMDocument();
    // VULNERABLE: Enabling external entity loading
    $doc->loadXML($xml, LIBXML_DTDLOAD | LIBXML_NOENT);
    echo $doc->saveXML();
}

// Test 3: XMLReader with external entities
function parse_xmlreader() {
    $xml = $_POST['xml'];
    $reader = new XMLReader();
    // VULNERABLE: Setting entity substitution
    $reader->setParserProperty(XMLReader::SUBST_ENTITIES, true);
    $reader->XML($xml);
    while ($reader->read()) {
        echo $reader->readString();
    }
}

// Test 4: LIBXML options vulnerable
function parse_libxml_options() {
    $xml = $_POST['xml'];
    $options = LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR;
    // VULNERABLE: Multiple dangerous options
    $doc = new DOMDocument();
    $doc->loadXML($xml, $options);
    echo $doc->documentElement->textContent;
}

// Test 5: Loading XML from file
function parse_from_file() {
    $filename = $_GET['file'];
    $doc = new DOMDocument();
    // VULNERABLE: Loading potentially malicious XML
    $doc->load($filename, LIBXML_NOENT);
    echo $doc->saveXML();
}

// Test 6: SOAP with XML payload
function soap_xxe() {
    $xml = file_get_contents('php://input');
    // VULNERABLE: SOAP XML parsing
    $doc = new DOMDocument();
    $doc->loadXML($xml, LIBXML_NOENT);
    // Process SOAP...
}

// Test 7: XPath with XXE document
function xpath_xxe() {
    $xml = $_POST['xml'];
    $doc = new DOMDocument();
    // VULNERABLE: XXE before XPath
    $doc->loadXML($xml, LIBXML_NOENT);
    $xpath = new DOMXPath($doc);
    $results = $xpath->query('//data');
    foreach ($results as $node) {
        echo $node->textContent;
    }
}

// Test 8: simplexml_load_file
function load_xml_file() {
    $url = $_GET['url'];
    // VULNERABLE: Loading XML from URL
    $xml = simplexml_load_file($url, null, LIBXML_NOENT);
    echo $xml->asXML();
}

// Test 9: XML stream wrapper
function xml_stream() {
    $uri = $_GET['uri'];
    // VULNERABLE: php://filter or other wrappers
    $xml = file_get_contents($uri);
    $doc = simplexml_load_string($xml);
    echo $doc->asXML();
}

// Test 10: XInclude processing
function xinclude_process() {
    $xml = $_POST['xml'];
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    // VULNERABLE: XInclude can include external files
    $doc->xinclude();
    echo $doc->saveXML();
}

// Test 11: Entity expansion attack (billion laughs)
function parse_no_limits() {
    $xml = $_POST['xml'];
    $doc = new DOMDocument();
    // VULNERABLE: No entity expansion limits
    libxml_disable_entity_loader(false);
    $doc->loadXML($xml, LIBXML_NOENT | LIBXML_PARSEHUGE);
    echo $doc->saveXML();
}
?>
