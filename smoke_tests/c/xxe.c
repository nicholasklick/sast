// XXE (XML External Entity) vulnerabilities in C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <expat.h>

// Test 1: libxml2 with external entities enabled (default)
void parse_xml_libxml_unsafe(const char *xml_content) {
    // VULNERABLE: External entities enabled by default
    xmlDocPtr doc = xmlParseMemory(xml_content, strlen(xml_content));
    if (doc) {
        xmlNodePtr root = xmlDocGetRootElement(doc);
        // Process XML...
        xmlFreeDoc(doc);
    }
}

// Test 2: Loading external DTD
void parse_with_dtd(const char *xml_file) {
    // VULNERABLE: Loading external DTD
    xmlDocPtr doc = xmlReadFile(xml_file, NULL, XML_PARSE_DTDLOAD);
    if (doc) {
        xmlFreeDoc(doc);
    }
}

// Test 3: Network entity resolution
void parse_xml_network(const char *xml_content) {
    // VULNERABLE: Allows network access for entities
    xmlDocPtr doc = xmlReadMemory(xml_content, strlen(xml_content),
                                   "noname.xml", NULL,
                                   XML_PARSE_NOENT);
    if (doc) {
        xmlFreeDoc(doc);
    }
}

// Test 4: Expat parser without disabling entities
void parse_xml_expat(const char *xml_data, size_t len) {
    // VULNERABLE: Expat allows external entities by default
    XML_Parser parser = XML_ParserCreate(NULL);
    // Missing: XML_SetExternalEntityRefHandler to reject
    XML_Parse(parser, xml_data, len, 1);
    XML_ParserFree(parser);
}

// Test 5: Parameter entity expansion
void parse_xml_param_entities(const char *xml_content) {
    // VULNERABLE: Parameter entities can exfiltrate data
    xmlDocPtr doc = xmlReadMemory(xml_content, strlen(xml_content),
                                   NULL, NULL,
                                   XML_PARSE_DTDATTR | XML_PARSE_NOENT);
    if (doc) {
        xmlFreeDoc(doc);
    }
}

// Test 6: XInclude processing
void parse_with_xinclude(const char *xml_file) {
    xmlDocPtr doc = xmlReadFile(xml_file, NULL, 0);
    if (doc) {
        // VULNERABLE: XInclude can include external files
        xmlXIncludeProcess(doc);
        xmlFreeDoc(doc);
    }
}

// Test 7: XSLT with document() function
void apply_xslt(const char *xml_file, const char *xslt_file) {
    // VULNERABLE: XSLT document() function can read files
    xmlDocPtr doc = xmlParseFile(xml_file);
    xmlDocPtr style = xmlParseFile(xslt_file);
    // xsltStylesheetPtr xslt = xsltParseStylesheetDoc(style);
    // Apply transform...
    if (doc) xmlFreeDoc(doc);
    if (style) xmlFreeDoc(style);
}

// Test 8: Billion laughs / XML bomb
void parse_untrusted_xml(const char *user_xml) {
    // VULNERABLE: No entity expansion limits
    xmlDocPtr doc = xmlReadMemory(user_xml, strlen(user_xml),
                                   NULL, NULL,
                                   XML_PARSE_NOENT | XML_PARSE_DTDLOAD);
    if (doc) {
        xmlFreeDoc(doc);
    }
}
