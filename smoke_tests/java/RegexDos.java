// Regular Expression DoS (ReDoS) vulnerabilities in Java

import java.util.regex.Pattern;
import java.util.regex.Matcher;
import javax.servlet.http.*;

public class RegexDos extends HttpServlet {

    // Test 1: Nested quantifiers
    public boolean validateNested(String input) {
        // VULNERABLE: (a+)+ causes exponential backtracking
        Pattern pattern = Pattern.compile("(a+)+b");
        return pattern.matcher(input).matches();
    }

    // Test 2: Overlapping alternation
    public boolean checkOverlap(String input) {
        // VULNERABLE: Overlapping alternatives
        Pattern pattern = Pattern.compile("(a|a)+b");
        return pattern.matcher(input).matches();
    }

    // Test 3: Email validation ReDoS
    public boolean validateEmail(String email) {
        // VULNERABLE: Classic email ReDoS pattern
        String regex = "^([a-zA-Z0-9]+)+@([a-zA-Z0-9]+)+\\.([a-zA-Z]+)+$";
        return email.matches(regex);
    }

    // Test 4: URL validation ReDoS
    public boolean validateUrl(String url) {
        // VULNERABLE: Nested groups in URL pattern
        Pattern pattern = Pattern.compile("^(https?://)?([a-zA-Z0-9.-]+)+(/.*)* $");
        return pattern.matcher(url).matches();
    }

    // Test 5: User-supplied regex
    public boolean customMatch(HttpServletRequest request) {
        String input = request.getParameter("input");
        String patternStr = request.getParameter("pattern");
        // VULNERABLE: User supplies regex pattern
        Pattern pattern = Pattern.compile(patternStr);
        return pattern.matcher(input).matches();
    }

    // Test 6: replaceAll with vulnerable pattern
    public String replacePattern(String input) {
        // VULNERABLE: Vulnerable pattern in replaceAll
        return input.replaceAll("(a+)+", "X");
    }

    // Test 7: split with ReDoS
    public String[] splitInput(String input) {
        // VULNERABLE: Split can trigger ReDoS
        return input.split("(\\s+)+");
    }

    // Test 8: HTML tag matching ReDoS
    public int matchHtml(String html) {
        // VULNERABLE: Complex HTML pattern
        Pattern pattern = Pattern.compile("<([a-z]+)([^>]*)*>");
        Matcher matcher = pattern.matcher(html);
        int count = 0;
        while (matcher.find()) {
            count++;
        }
        return count;
    }

    // Test 9: Multiline ReDoS
    public boolean multilineMatch(String content) {
        // VULNERABLE: Multiline with backtracking
        Pattern pattern = Pattern.compile("^(.+)+$", Pattern.MULTILINE);
        return pattern.matcher(content).matches();
    }

    // Test 10: Case insensitive ReDoS
    public boolean caseInsensitive(String input) {
        // VULNERABLE: Case insensitive can make it worse
        Pattern pattern = Pattern.compile("([a-z]+)+$", Pattern.CASE_INSENSITIVE);
        return pattern.matcher(input).matches();
    }
}
