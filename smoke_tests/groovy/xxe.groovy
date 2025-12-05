// XML External Entity (XXE) vulnerabilities in Groovy
package com.example.security

import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.parsers.SAXParserFactory
import groovy.xml.XmlSlurper
import groovy.xml.XmlParser

class XxeVulnerabilities {

    // Test 1: XmlSlurper without protection
    def parseXmlSlurper(String xmlString) {
        // VULNERABLE: XmlSlurper may process external entities
        def slurper = new XmlSlurper()
        slurper.parseText(xmlString)
    }

    // Test 2: XmlParser vulnerable
    def parseXmlParser(String xmlString) {
        // VULNERABLE: XmlParser default settings
        def parser = new XmlParser()
        parser.parseText(xmlString)
    }

    // Test 3: DOM parser without protection
    String parseXmlDom(String xmlString) {
        def factory = DocumentBuilderFactory.newInstance()
        // VULNERABLE: External entities enabled
        def builder = factory.newDocumentBuilder()
        def doc = builder.parse(new ByteArrayInputStream(xmlString.bytes))
        doc.documentElement.textContent
    }

    // Test 4: SAX parser vulnerable
    void parseXmlSax(String xmlString) {
        def factory = SAXParserFactory.newInstance()
        // VULNERABLE: Default settings allow XXE
        def parser = factory.newSAXParser()
        parser.parse(new ByteArrayInputStream(xmlString.bytes), new org.xml.sax.helpers.DefaultHandler())
    }

    // Test 5: XML from network
    def fetchAndParseXml(String url) {
        // VULNERABLE: Parsing untrusted XML from URL
        new XmlSlurper().parse(url)
    }

    // Test 6: SOAP request parsing
    Map parseSoapRequest(String soapXml) {
        def factory = DocumentBuilderFactory.newInstance()
        factory.namespaceAware = true
        // VULNERABLE: SOAP XML with XXE
        def doc = factory.newDocumentBuilder().parse(new ByteArrayInputStream(soapXml.bytes))
        extractSoapParams(doc)
    }

    // Test 7: XML configuration file
    def loadXmlConfig(String configPath) {
        // VULNERABLE: Config file could contain XXE
        new XmlSlurper().parse(new File(configPath))
    }

    // Test 8: RSS feed parsing
    List parseRssFeed(String feedXml) {
        // VULNERABLE: RSS feeds from external sources
        def xml = new XmlSlurper().parseText(feedXml)
        xml.channel.item.collect { it.title.text() }
    }

    // Test 9: SVG parsing
    String parseSvg(String svgContent) {
        // VULNERABLE: SVG is XML and can contain XXE
        def svg = new XmlSlurper().parseText(svgContent)
        svg.'@width'.text()
    }

    // Test 10: XML input stream
    def parseXmlStream(InputStream inputStream) {
        // VULNERABLE: Processing untrusted stream
        new XmlSlurper().parse(inputStream)
    }

    // Test 11: MarkupBuilder with external data
    String buildXmlWithExternal(String externalData) {
        def writer = new StringWriter()
        def xml = new groovy.xml.MarkupBuilder(writer)
        xml.root {
            // VULNERABLE: External data in XML
            data(externalData)
        }
        writer.toString()
    }

    // Test 12: StreamingMarkupBuilder
    String streamingXml(String userContent) {
        def builder = new groovy.xml.StreamingMarkupBuilder()
        builder.bind {
            root {
                // VULNERABLE: User content
                content(userContent)
            }
        }.toString()
    }

    private Map extractSoapParams(doc) { [:] }
}
