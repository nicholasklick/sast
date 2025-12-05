// XSS (Cross-Site Scripting) vulnerabilities in C++ (Web/CGI context)
#include <iostream>
#include <string>
#include <sstream>

// Test 1: Direct output of user input
void echo_input_cgi() {
    char* query = getenv("QUERY_STRING");
    std::cout << "Content-Type: text/html\r\n\r\n";
    // VULNERABLE: Direct output without escaping
    std::cout << "<html><body>You searched for: " << query << "</body></html>";
}

// Test 2: Reflected XSS in error message
void display_error(const std::string& error_msg) {
    std::cout << "Content-Type: text/html\r\n\r\n";
    // VULNERABLE: error_msg from user input
    std::cout << "<div class='error'>" << error_msg << "</div>";
}

// Test 3: XSS in URL parameter
void redirect_with_message(const std::string& message) {
    std::cout << "Content-Type: text/html\r\n\r\n";
    std::cout << "<html><head>";
    // VULNERABLE: message not escaped in meta refresh
    std::cout << "<meta http-equiv='refresh' content='0;url=/home?msg=" << message << "'>";
    std::cout << "</head></html>";
}

// Test 4: XSS in JavaScript context
void generate_js(const std::string& username) {
    std::cout << "Content-Type: text/html\r\n\r\n";
    std::cout << "<script>";
    // VULNERABLE: username can break out of string
    std::cout << "var user = '" << username << "';";
    std::cout << "</script>";
}

// Test 5: XSS in HTML attribute
void generate_link(const std::string& url, const std::string& text) {
    std::cout << "Content-Type: text/html\r\n\r\n";
    // VULNERABLE: url and text can contain malicious content
    std::cout << "<a href=\"" << url << "\">" << text << "</a>";
}

// Test 6: XSS in style attribute
void set_color(const std::string& color) {
    std::cout << "Content-Type: text/html\r\n\r\n";
    // VULNERABLE: color can break out of style
    std::cout << "<div style=\"color: " << color << "\">Colored text</div>";
}

// Test 7: DOM-based XSS setup
void generate_page_with_dom_sink(const std::string& default_value) {
    std::cout << "Content-Type: text/html\r\n\r\n";
    std::cout << "<html><body>";
    // VULNERABLE: default_value goes to DOM
    std::cout << "<input id='search' value='" << default_value << "'>";
    std::cout << "<script>document.getElementById('result').innerHTML = document.getElementById('search').value;</script>";
    std::cout << "</body></html>";
}

// Test 8: XSS in JSON response
void json_response(const std::string& user_data) {
    std::cout << "Content-Type: application/json\r\n\r\n";
    // VULNERABLE: user_data can break JSON and inject script if rendered as HTML
    std::cout << "{\"data\": \"" << user_data << "\"}";
}
