#!/bin/bash
# XXE (XML External Entity) vulnerabilities in Bash

# Test 1: xmllint with external entities
vulnerable_xmllint() {
    local xml_file="$1"
    # VULNERABLE: External entities enabled
    xmllint --noent "$xml_file"
}

# Test 2: xmlstarlet with user input
vulnerable_xmlstarlet() {
    local xml_file="$1"
    # VULNERABLE: Processing untrusted XML
    xmlstarlet sel -t -v "//data" "$xml_file"
}

# Test 3: xsltproc with user XML
vulnerable_xsltproc() {
    local xml_file="$1"
    local xsl_file="$2"
    # VULNERABLE: XSLT can include external entities
    xsltproc "$xsl_file" "$xml_file"
}

# Test 4: saxon with user XML
vulnerable_saxon() {
    local xml_file="$1"
    local xsl_file="$2"
    # VULNERABLE: Saxon processes external entities
    java -jar saxon.jar -s:"$xml_file" -xsl:"$xsl_file"
}

# Test 5: python xml parsing via bash
vulnerable_python_xml() {
    local xml_data="$1"
    # VULNERABLE: Python's default XML parser allows XXE
    python -c "import xml.etree.ElementTree as ET; ET.fromstring('$xml_data')"
}

# Test 6: php xml parsing via bash
vulnerable_php_xml() {
    local xml_file="$1"
    # VULNERABLE: PHP SimpleXML with external entities
    php -r "simplexml_load_file('$xml_file', 'SimpleXMLElement', LIBXML_NOENT);"
}

# Test 7: ruby xml parsing via bash
vulnerable_ruby_xml() {
    local xml_file="$1"
    # VULNERABLE: Ruby Nokogiri with external entities
    ruby -e "require 'nokogiri'; Nokogiri::XML(File.read('$xml_file'))"
}

# Test 8: perl xml parsing via bash
vulnerable_perl_xml() {
    local xml_file="$1"
    # VULNERABLE: Perl XML parser
    perl -MXML::Simple -e "XMLin('$xml_file')"
}

# Test 9: curl fetching XML and processing
vulnerable_curl_xml() {
    local url="$1"
    # VULNERABLE: Fetching and processing untrusted XML
    curl -s "$url" | xmllint --noent -
}

# Test 10: heredoc XML with entity
vulnerable_heredoc_xml() {
    local entity_value="$1"
    # VULNERABLE: User input in XML entity
    cat << EOF | xmllint --noent -
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "$entity_value">
]>
<root>&xxe;</root>
EOF
}

# Test 11: XML validation with DTD
vulnerable_dtd_validation() {
    local xml_file="$1"
    # VULNERABLE: DTD validation can fetch external resources
    xmllint --valid --dtdvalid external.dtd "$xml_file"
}

# Test 12: XInclude processing
vulnerable_xinclude() {
    local xml_file="$1"
    # VULNERABLE: XInclude can include external files
    xmllint --xinclude "$xml_file"
}

# Test 13: SOAP request with XML
vulnerable_soap() {
    local endpoint="$1"
    local xml_body="$2"
    # VULNERABLE: SOAP with untrusted XML body
    curl -X POST -H "Content-Type: text/xml" -d "$xml_body" "$endpoint"
}

# Test 14: XML in environment variable
vulnerable_xml_env() {
    # VULNERABLE: XML from environment
    echo "$XML_DATA" | xmllint --noent -
}

# Test 15: xq/yq XML processing
vulnerable_xq() {
    local xml_file="$1"
    # VULNERABLE: xq processes XML
    xq '.' "$xml_file"
}

