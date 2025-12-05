// XXE (XML External Entity) Test Cases

// Test 1: libxmljs with external entities enabled
function parseXMLWithLibxmljs(xmlString: string): any {
    const libxmljs = require('libxmljs');
    // VULNERABLE: noent option enables entity expansion
    return libxmljs.parseXml(xmlString, { noent: true });
}

// Test 2: xml2js without XXE protection
function parseXMLWithXml2js(xmlString: string): Promise<any> {
    const xml2js = require('xml2js');
    const parser = new xml2js.Parser({
        // VULNERABLE: No XXE protection configured
    });
    return parser.parseStringPromise(xmlString);
}

// Test 3: DOMParser without security settings
function parseXMLInBrowser(xmlString: string): Document {
    const parser = new DOMParser();
    // VULNERABLE: No validation or entity restrictions
    return parser.parseFromString(xmlString, 'text/xml');
}

// Test 4: xmldom parser with default settings
function parseXMLWithXmldom(xmlString: string): Document {
    const { DOMParser } = require('xmldom');
    // VULNERABLE: Default settings allow entity expansion
    const parser = new DOMParser();
    return parser.parseFromString(xmlString, 'text/xml');
}

// Test 5: Fast-xml-parser with entities enabled
function parseXMLWithFastParser(xmlString: string): any {
    const { XMLParser } = require('fast-xml-parser');
    const parser = new XMLParser({
        // VULNERABLE: Allowing entities without restrictions
        allowBooleanAttributes: true,
        processEntities: true
    });
    return parser.parse(xmlString);
}
