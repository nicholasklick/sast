// XML External Entity (XXE) vulnerabilities in Swift
import Foundation

class XxeVulnerabilities {

    // Test 1: XMLParser with external entities
    func parseXmlUnsafe(xmlData: Data) {
        let parser = XMLParser(data: xmlData)
        // VULNERABLE: External entities enabled by default in some configurations
        parser.shouldResolveExternalEntities = true
        parser.parse()
    }

    // Test 2: XMLDocument parsing
    func parseXmlDocument(xmlString: String) throws {
        // VULNERABLE: May process external entities
        let doc = try XMLDocument(xmlString: xmlString, options: [])
        print(doc.rootElement()?.name ?? "")
    }

    // Test 3: User-provided XML
    func processUserXml(userXml: String) {
        guard let data = userXml.data(using: .utf8) else { return }
        let parser = XMLParser(data: data)
        // VULNERABLE: Processing untrusted XML
        parser.shouldResolveExternalEntities = true
        parser.parse()
    }

    // Test 4: XML from network
    func fetchAndParseXml(url: URL, completion: @escaping (Bool) -> Void) {
        URLSession.shared.dataTask(with: url) { data, _, _ in
            guard let data = data else {
                completion(false)
                return
            }
            let parser = XMLParser(data: data)
            // VULNERABLE: Remote XML with entities
            parser.shouldResolveExternalEntities = true
            completion(parser.parse())
        }.resume()
    }

    // Test 5: SOAP request parsing
    func parseSoapResponse(response: Data) {
        let parser = XMLParser(data: response)
        // VULNERABLE: SOAP responses may contain XXE
        parser.shouldResolveExternalEntities = true
        parser.parse()
    }

    // Test 6: Configuration file parsing
    func loadConfig(path: String) {
        guard let data = FileManager.default.contents(atPath: path) else { return }
        let parser = XMLParser(data: data)
        // VULNERABLE: Config file could be tampered
        parser.shouldResolveExternalEntities = true
        parser.parse()
    }

    // Test 7: XML transform
    func transformXml(xmlData: Data, xsltData: Data) throws {
        // VULNERABLE: XSLT can also include XXE attacks
        let doc = try XMLDocument(data: xmlData, options: [])
        let xslt = try XMLDocument(data: xsltData, options: [])
        _ = try doc.object(byApplyingXSLT: xslt, arguments: nil)
    }

    // Test 8: RSS feed parsing
    func parseRssFeed(feedUrl: URL) {
        URLSession.shared.dataTask(with: feedUrl) { data, _, _ in
            guard let data = data else { return }
            let parser = XMLParser(data: data)
            // VULNERABLE: RSS feeds from external sources
            parser.shouldResolveExternalEntities = true
            parser.parse()
        }.resume()
    }

    // Test 9: SVG parsing (XML-based)
    func parseSvg(svgData: Data) {
        let parser = XMLParser(data: svgData)
        // VULNERABLE: SVG files can contain XXE
        parser.shouldResolveExternalEntities = true
        parser.parse()
    }

    // Test 10: Plist XML parsing
    func parsePlistXml(plistData: Data) throws {
        // VULNERABLE: XML plists can potentially contain entities
        let _ = try PropertyListSerialization.propertyList(from: plistData,
                                                           options: [],
                                                           format: nil)
    }
}

// XMLParser delegate
extension XxeVulnerabilities: XMLParserDelegate {
    func parser(_ parser: XMLParser, didStartElement elementName: String,
                namespaceURI: String?, qualifiedName qName: String?,
                attributes attributeDict: [String: String] = [:]) {
        // Handle element
    }
}
