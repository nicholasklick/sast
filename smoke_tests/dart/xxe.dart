// XXE (XML External Entity) vulnerabilities in Dart

import 'dart:io';
import 'package:xml/xml.dart';

// Test 1: Parse XML from user input
XmlDocument vulnerableXmlParse(String xmlString) {
  // VULNERABLE: Parsing untrusted XML
  return XmlDocument.parse(xmlString);
}

// Test 2: Parse XML from file
Future<XmlDocument> vulnerableXmlFile(String filePath) async {
  // VULNERABLE: Parsing XML from untrusted file
  var file = File(filePath);
  var content = await file.readAsString();
  return XmlDocument.parse(content);
}

// Test 3: Parse XML from HTTP response
Future<XmlDocument> vulnerableXmlHttp(String url) async {
  // VULNERABLE: Parsing XML from network
  var client = HttpClient();
  var request = await client.getUrl(Uri.parse(url));
  var response = await request.close();
  var body = await response.transform(SystemEncoding().decoder).join();
  return XmlDocument.parse(body);
}

// Test 4: SOAP request parsing
XmlDocument vulnerableSoapParse(String soapEnvelope) {
  // VULNERABLE: Parsing SOAP envelope
  return XmlDocument.parse(soapEnvelope);
}

// Test 5: RSS/Atom feed parsing
Future<XmlDocument> vulnerableFeedParse(String feedUrl) async {
  // VULNERABLE: Parsing RSS/Atom from URL
  var client = HttpClient();
  var request = await client.getUrl(Uri.parse(feedUrl));
  var response = await request.close();
  var body = await response.transform(SystemEncoding().decoder).join();
  return XmlDocument.parse(body);
}

// Test 6: XML with DTD
XmlDocument vulnerableXmlWithDtd(String xml) {
  // VULNERABLE: XML with DTD can have external entities
  // The xml package by default processes DTDs
  return XmlDocument.parse(xml);
}

// Test 7: SVG parsing
XmlDocument vulnerableSvgParse(String svgContent) {
  // VULNERABLE: SVG is XML and can contain XXE
  return XmlDocument.parse(svgContent);
}

// Test 8: XML config file
Future<Map<String, String>> vulnerableXmlConfig(String configPath) async {
  // VULNERABLE: Loading XML config
  var file = File(configPath);
  var content = await file.readAsString();
  var doc = XmlDocument.parse(content);
  var config = <String, String>{};
  for (var element in doc.rootElement.children) {
    if (element is XmlElement) {
      config[element.name.toString()] = element.text;
    }
  }
  return config;
}

// Test 9: XSLT transformation
Future<String> vulnerableXslt(String xmlData, String xsltPath) async {
  // VULNERABLE: XSLT can include external documents
  var xsltFile = File(xsltPath);
  var xsltContent = await xsltFile.readAsString();
  // In real code, XSLT processing
  return 'Transformed: $xmlData with $xsltContent';
}

// Test 10: XPath on untrusted XML
List<XmlNode> vulnerableXpath(String xmlString, String xpath) {
  // VULNERABLE: XPath on untrusted XML
  var doc = XmlDocument.parse(xmlString);
  // XPath query would be here
  return doc.findAllElements('*').toList();
}

// Test 11: Office document parsing (simulated)
Future<XmlDocument> vulnerableOfficeDoc(String docxPath) async {
  // VULNERABLE: Office docs contain XML
  // Would extract and parse XML from docx/xlsx
  var file = File(docxPath);
  var content = await file.readAsString();
  return XmlDocument.parse(content);
}

// Test 12: XML from form data
XmlDocument vulnerableFormXml(String formData) {
  // VULNERABLE: XML from form submission
  return XmlDocument.parse(formData);
}

// Test 13: XML from WebSocket
void vulnerableWebSocketXml(String wsUrl) async {
  // VULNERABLE: XML from WebSocket
  var socket = await WebSocket.connect(wsUrl);
  socket.listen((data) {
    var doc = XmlDocument.parse(data);
    print(doc);
  });
}

// Test 14: XML from environment variable
XmlDocument vulnerableEnvXml() {
  // VULNERABLE: XML from environment
  var xmlContent = Platform.environment['XML_CONFIG'];
  if (xmlContent != null) {
    return XmlDocument.parse(xmlContent);
  }
  throw Exception('No XML config');
}

// Test 15: Sitemap parsing
Future<XmlDocument> vulnerableSitemapParse(String sitemapUrl) async {
  // VULNERABLE: Parsing sitemap from URL
  var client = HttpClient();
  var request = await client.getUrl(Uri.parse(sitemapUrl));
  var response = await request.close();
  var body = await response.transform(SystemEncoding().decoder).join();
  return XmlDocument.parse(body);
}
