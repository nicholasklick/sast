// XML External Entity (XXE) vulnerabilities in Scala
package com.example.security

import javax.xml.parsers.{DocumentBuilderFactory, SAXParserFactory}
import scala.xml.{XML, Elem}
import java.io.StringReader
import org.xml.sax.InputSource

class XxeVulnerabilities {

  // Test 1: Scala XML loading
  def parseScalaXml(xmlString: String): Elem = {
    // VULNERABLE: scala.xml.XML may process external entities
    XML.loadString(xmlString)
  }

  // Test 2: DOM parser without protection
  def parseXmlDom(xmlString: String): String = {
    val factory = DocumentBuilderFactory.newInstance()
    // VULNERABLE: External entities enabled
    val builder = factory.newDocumentBuilder()
    val doc = builder.parse(new InputSource(new StringReader(xmlString)))
    doc.getDocumentElement.getTextContent
  }

  // Test 3: SAX parser vulnerable
  def parseXmlSax(xmlString: String): Unit = {
    val factory = SAXParserFactory.newInstance()
    // VULNERABLE: Default settings allow XXE
    val parser = factory.newSAXParser()
    parser.parse(new InputSource(new StringReader(xmlString)), new org.xml.sax.helpers.DefaultHandler())
  }

  // Test 4: XML from network
  def fetchAndParseXml(url: String): Elem = {
    // VULNERABLE: Parsing untrusted XML from URL
    XML.load(url)
  }

  // Test 5: SOAP request parsing
  def parseSoapRequest(soapXml: String): Map[String, String] = {
    val factory = DocumentBuilderFactory.newInstance()
    factory.setNamespaceAware(true)
    // VULNERABLE: SOAP XML with XXE
    val doc = factory.newDocumentBuilder().parse(new InputSource(new StringReader(soapXml)))
    extractSoapParams(doc)
  }

  // Test 6: XML configuration file
  def loadXmlConfig(configPath: String): Map[String, String] = {
    // VULNERABLE: Config file could contain XXE
    val xml = XML.loadFile(configPath)
    parseConfig(xml)
  }

  // Test 7: RSS feed parsing
  def parseRssFeed(feedXml: String): List[String] = {
    // VULNERABLE: RSS feeds from external sources
    val xml = XML.loadString(feedXml)
    (xml \\ "item" \\ "title").map(_.text).toList
  }

  // Test 8: SVG parsing
  def parseSvg(svgContent: String): String = {
    // VULNERABLE: SVG is XML and can contain XXE
    val svg = XML.loadString(svgContent)
    (svg \ "@width").text
  }

  // Test 9: XML input stream
  def parseXmlStream(inputStream: java.io.InputStream): Elem = {
    // VULNERABLE: Processing untrusted stream
    XML.load(inputStream)
  }

  // Test 10: XML literal with external data
  def buildXmlWithExternal(externalData: String): Elem = {
    // VULNERABLE: External data in XML
    <root>
      <data>{scala.xml.Unparsed(externalData)}</data>
    </root>
  }

  // Test 11: Play XML parser
  def playXmlParse(xmlString: String): String = {
    // VULNERABLE: Play XML parsing
    val xml = XML.loadString(xmlString)
    xml.text
  }

  // Test 12: XSLT transformation
  def transformXml(xml: String, xslt: String): String = {
    val factory = javax.xml.transform.TransformerFactory.newInstance()
    // VULNERABLE: XSLT can include external entities
    val transformer = factory.newTransformer(
      new javax.xml.transform.stream.StreamSource(new StringReader(xslt))
    )
    val result = new java.io.StringWriter()
    transformer.transform(
      new javax.xml.transform.stream.StreamSource(new StringReader(xml)),
      new javax.xml.transform.stream.StreamResult(result)
    )
    result.toString
  }

  private def extractSoapParams(doc: org.w3c.dom.Document): Map[String, String] = Map.empty
  private def parseConfig(xml: Elem): Map[String, String] = Map.empty
}
