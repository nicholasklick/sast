// Template Injection vulnerabilities in C++
#include <iostream>
#include <string>
#include <sstream>
#include <regex>
#include <map>

// Test 1: Simple string template with user input
std::string render_template(const std::string& tmpl, const std::string& user_value) {
    // VULNERABLE: User value directly in template without escaping
    std::string result = tmpl;
    size_t pos = result.find("{{value}}");
    if (pos != std::string::npos) {
        result.replace(pos, 9, user_value);
    }
    return result;
}

// Test 2: HTML template injection
std::string render_html(const std::string& username) {
    // VULNERABLE: Direct interpolation in HTML
    std::stringstream ss;
    ss << "<html><body><h1>Welcome, " << username << "</h1></body></html>";
    return ss.str();
}

// Test 3: JSON template injection
std::string create_json(const std::string& user_data) {
    // VULNERABLE: Can break JSON structure
    return "{\"data\": \"" + user_data + "\"}";
}

// Test 4: SQL template (not parameterized)
std::string build_query(const std::string& table, const std::string& column) {
    // VULNERABLE: Direct interpolation in SQL
    return "SELECT * FROM " + table + " WHERE " + column + " = 1";
}

// Test 5: XML template injection
std::string create_xml(const std::string& tag, const std::string& content) {
    // VULNERABLE: Can inject XML elements
    return "<" + tag + ">" + content + "</" + tag + ">";
}

// Test 6: Shell command template
std::string build_command(const std::string& filename) {
    // VULNERABLE: Shell metacharacter injection
    return "cat /data/" + filename;
}

// Test 7: LDAP query template
std::string build_ldap_query(const std::string& username) {
    // VULNERABLE: LDAP injection
    return "(uid=" + username + ")";
}

// Test 8: URL template injection
std::string build_url(const std::string& endpoint, const std::string& param) {
    // VULNERABLE: URL parameter injection
    return "https://api.example.com/" + endpoint + "?data=" + param;
}

// Test 9: Regex from user input
bool match_pattern(const std::string& input, const std::string& user_pattern) {
    // VULNERABLE: ReDoS possible with malicious pattern
    std::regex pattern(user_pattern);
    return std::regex_match(input, pattern);
}

// Test 10: Expression evaluation template
double evaluate_expression(const std::string& expr) {
    // VULNERABLE: If expr is parsed/evaluated, code injection possible
    // This is a simplified example
    return 0.0;  // Would need actual expression evaluator
}

// Test 11: Config file template
std::string create_config(const std::string& key, const std::string& value) {
    // VULNERABLE: Can inject additional config lines
    return key + "=" + value + "\n";
}
