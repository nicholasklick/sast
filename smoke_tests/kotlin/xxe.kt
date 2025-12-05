// XML External Entity (XXE) vulnerabilities in Kotlin
package com.example.security

import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.parsers.SAXParserFactory
import javax.xml.stream.XMLInputFactory
import javax.xml.transform.TransformerFactory
import javax.xml.transform.stream.StreamSource
import org.xml.sax.InputSource
import java.io.StringReader
import java.io.ByteArrayInputStream

class XxeVulnerabilities {

    // Test 1: DOM parser without protection
    fun parseXmlDom(xmlString: String): String {
        val factory = DocumentBuilderFactory.newInstance()
        // VULNERABLE: External entities enabled
        val builder = factory.newDocumentBuilder()
        val doc = builder.parse(InputSource(StringReader(xmlString)))
        return doc.documentElement.textContent
    }

    // Test 2: SAX parser vulnerable
    fun parseXmlSax(xmlString: String) {
        val factory = SAXParserFactory.newInstance()
        // VULNERABLE: Default settings allow XXE
        val parser = factory.newSAXParser()
        parser.parse(InputSource(StringReader(xmlString)), DefaultHandler())
    }

    // Test 3: StAX parser
    fun parseXmlStax(xmlString: String): String {
        val factory = XMLInputFactory.newInstance()
        // VULNERABLE: External entities not disabled
        val reader = factory.createXMLStreamReader(StringReader(xmlString))
        val content = StringBuilder()
        while (reader.hasNext()) {
            if (reader.isCharacters) {
                content.append(reader.text)
            }
            reader.next()
        }
        return content.toString()
    }

    // Test 4: XSLT transformation
    fun transformXml(xml: String, xslt: String): String {
        val factory = TransformerFactory.newInstance()
        // VULNERABLE: XSLT can include external entities
        val transformer = factory.newTransformer(StreamSource(StringReader(xslt)))
        val result = java.io.StringWriter()
        transformer.transform(
            StreamSource(StringReader(xml)),
            javax.xml.transform.stream.StreamResult(result)
        )
        return result.toString()
    }

    // Test 5: XML from network
    fun fetchAndParseXml(url: String): String {
        val xmlContent = java.net.URL(url).readText()
        // VULNERABLE: Parsing untrusted XML
        val factory = DocumentBuilderFactory.newInstance()
        val doc = factory.newDocumentBuilder().parse(InputSource(StringReader(xmlContent)))
        return doc.documentElement.textContent
    }

    // Test 6: SOAP request parsing
    fun parseSoapRequest(soapXml: String): Map<String, String> {
        val factory = DocumentBuilderFactory.newInstance()
        factory.isNamespaceAware = true
        // VULNERABLE: SOAP XML with XXE
        val doc = factory.newDocumentBuilder().parse(InputSource(StringReader(soapXml)))
        return extractSoapParams(doc)
    }

    // Test 7: XML configuration file
    fun loadXmlConfig(configPath: String): Map<String, String> {
        val factory = DocumentBuilderFactory.newInstance()
        // VULNERABLE: Config file could contain XXE
        val doc = factory.newDocumentBuilder().parse(java.io.File(configPath))
        return parseConfig(doc)
    }

    // Test 8: XML input stream
    fun parseXmlStream(data: ByteArray): String {
        val factory = DocumentBuilderFactory.newInstance()
        // VULNERABLE: Processing untrusted bytes
        val doc = factory.newDocumentBuilder().parse(ByteArrayInputStream(data))
        return doc.documentElement.textContent
    }

    // Test 9: RSS/Atom feed parsing
    fun parseRssFeed(feedXml: String): List<String> {
        val factory = DocumentBuilderFactory.newInstance()
        // VULNERABLE: RSS feeds from external sources
        val doc = factory.newDocumentBuilder().parse(InputSource(StringReader(feedXml)))
        return extractFeedItems(doc)
    }

    // Test 10: SVG parsing
    fun parseSvg(svgContent: String): String {
        val factory = DocumentBuilderFactory.newInstance()
        // VULNERABLE: SVG is XML and can contain XXE
        val doc = factory.newDocumentBuilder().parse(InputSource(StringReader(svgContent)))
        return doc.documentElement.getAttribute("width")
    }

    // Test 11: XML schema validation with external DTD
    fun validateWithSchema(xml: String, schemaUrl: String) {
        val factory = DocumentBuilderFactory.newInstance()
        factory.isValidating = true
        // VULNERABLE: Schema URL from user
        factory.setAttribute("http://java.sun.com/xml/jaxp/properties/schemaSource", schemaUrl)
        factory.newDocumentBuilder().parse(InputSource(StringReader(xml)))
    }

    // Test 12: JAXB unmarshalling
    fun unmarshalXml(xmlString: String, clazz: Class<*>): Any {
        val context = javax.xml.bind.JAXBContext.newInstance(clazz)
        // VULNERABLE: Default JAXB may process external entities
        val unmarshaller = context.createUnmarshaller()
        return unmarshaller.unmarshal(StringReader(xmlString))
    }

    private fun extractSoapParams(doc: org.w3c.dom.Document): Map<String, String> = emptyMap()
    private fun parseConfig(doc: org.w3c.dom.Document): Map<String, String> = emptyMap()
    private fun extractFeedItems(doc: org.w3c.dom.Document): List<String> = emptyList()
}

class DefaultHandler : org.xml.sax.helpers.DefaultHandler()
