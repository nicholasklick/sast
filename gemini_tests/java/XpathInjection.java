import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.xml.sax.InputSource;

public class XPathInjection {
    public String vulnerableXPathQuery(String username, String password) throws Exception {
        InputSource source = new InputSource("users.xml");
        XPath xpath = XPathFactory.newInstance().newXPath();

        // --- VULNERABLE CODE ---
        // User input is concatenated into the XPath expression.
        // Attacker can use: user="' or '1'='1" and pass="' or '1'='1"
        // CWE-643: Improper Neutralization of Data within XPath Expressions
        String expression = "/users/user[name='" + username + "' and pass='" + password + "']/account";
        String account = xpath.evaluate(expression, source);
        // -----------------------

        return account;
    }
}