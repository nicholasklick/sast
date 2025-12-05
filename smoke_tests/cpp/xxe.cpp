// XXE (XML External Entity) vulnerabilities in C++
#include <iostream>
#include <string>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <xercesc/parsers/XercesDOMParser.hpp>

using namespace xercesc;

// Test 1: libxml2 with default settings (external entities enabled)
void parse_xml_unsafe(const std::string& xml_content) {
    // VULNERABLE: External entities enabled by default
    xmlDocPtr doc = xmlParseMemory(xml_content.c_str(), xml_content.size());
    if (doc) {
        xmlFreeDoc(doc);
    }
}

// Test 2: Loading external DTD
void parse_with_dtd(const std::string& filename) {
    // VULNERABLE: Loading external DTD
    xmlDocPtr doc = xmlReadFile(filename.c_str(), nullptr, XML_PARSE_DTDLOAD);
    if (doc) {
        xmlFreeDoc(doc);
    }
}

// Test 3: Entity expansion enabled
void parse_with_entities(const std::string& xml) {
    // VULNERABLE: NOENT causes entity expansion
    xmlDocPtr doc = xmlReadMemory(xml.c_str(), xml.size(),
                                   nullptr, nullptr, XML_PARSE_NOENT);
    if (doc) {
        xmlFreeDoc(doc);
    }
}

// Test 4: Xerces-C with external entities
void parse_xerces_unsafe(const std::string& filename) {
    XMLPlatformUtils::Initialize();

    XercesDOMParser* parser = new XercesDOMParser();
    // VULNERABLE: Not disabling external entities
    // parser->setDoNamespaces(true);
    // parser->setDisableDefaultEntityResolution(true);  // NOT SET

    parser->parse(filename.c_str());

    delete parser;
    XMLPlatformUtils::Terminate();
}

// Test 5: XInclude processing
void parse_with_xinclude(const std::string& filename) {
    xmlDocPtr doc = xmlReadFile(filename.c_str(), nullptr, 0);
    if (doc) {
        // VULNERABLE: XInclude can include external files
        xmlXIncludeProcess(doc);
        xmlFreeDoc(doc);
    }
}

// Test 6: Parameter entity processing
void parse_parameter_entities(const std::string& xml) {
    // VULNERABLE: Parameter entities can exfiltrate data
    xmlDocPtr doc = xmlReadMemory(xml.c_str(), xml.size(),
                                   nullptr, nullptr,
                                   XML_PARSE_DTDATTR | XML_PARSE_NOENT);
    if (doc) {
        xmlFreeDoc(doc);
    }
}

// Test 7: No entity expansion limits
void parse_no_limits(const std::string& xml) {
    // VULNERABLE: Billion laughs attack possible
    xmlDocPtr doc = xmlReadMemory(xml.c_str(), xml.size(),
                                   nullptr, nullptr,
                                   XML_PARSE_NOENT | XML_PARSE_DTDLOAD | XML_PARSE_HUGE);
    if (doc) {
        xmlFreeDoc(doc);
    }
}

// Test 8: XSLT with document() function
void apply_xslt_unsafe(const std::string& xml_file, const std::string& xslt_file) {
    // VULNERABLE: XSLT document() function can read local files
    xmlDocPtr doc = xmlParseFile(xml_file.c_str());
    xmlDocPtr style = xmlParseFile(xslt_file.c_str());
    // xsltStylesheetPtr xslt = xsltParseStylesheetDoc(style);
    // Apply transform...
    if (doc) xmlFreeDoc(doc);
    if (style) xmlFreeDoc(style);
}
