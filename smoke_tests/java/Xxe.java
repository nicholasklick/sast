import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import java.io.StringReader;

public class XXE {
    public void vulnerableXmlParsing(String xmlString) throws Exception {
        // Malicious XML: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

        // --- VULNERABLE CODE ---
        // By default, many older XML parsers have XXE enabled.
        // To be safe, features need to be explicitly disabled.
        // CWE-611: Improper Restriction of XML External Entity Reference
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(new InputSource(new StringReader(xmlString)));
        // -----------------------

        System.out.println("Parsed XML: " + doc.getDocumentElement().getTextContent());
    }
}