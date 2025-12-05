// Open Redirect vulnerabilities in C++ (CGI/Web context)
#include <iostream>
#include <string>
#include <cstdlib>

// Test 1: Direct redirect from query parameter
void handle_redirect() {
    char* url = getenv("QUERY_STRING");
    // VULNERABLE: Unvalidated redirect
    std::cout << "Status: 302 Found\r\n";
    std::cout << "Location: " << url << "\r\n\r\n";
}

// Test 2: Redirect from POST data
void login_redirect(const std::string& return_url) {
    // VULNERABLE: return_url not validated
    std::cout << "Status: 302 Found\r\n";
    std::cout << "Location: " << return_url << "\r\n\r\n";
}

// Test 3: Partial validation bypass
void redirect_checked(const std::string& url) {
    // VULNERABLE: Can be bypassed with //evil.com or javascript:
    if (url[0] == '/') {
        std::cout << "Status: 302 Found\r\n";
        std::cout << "Location: " << url << "\r\n\r\n";
    }
}

// Test 4: Meta refresh redirect
void meta_redirect(const std::string& target) {
    std::cout << "Content-Type: text/html\r\n\r\n";
    // VULNERABLE: Unvalidated target URL
    std::cout << "<html><head><meta http-equiv='refresh' content='0;url=" << target << "'></head></html>";
}

// Test 5: JavaScript redirect
void js_redirect(const std::string& url) {
    std::cout << "Content-Type: text/html\r\n\r\n";
    // VULNERABLE: User-controlled URL in JavaScript
    std::cout << "<script>window.location='" << url << "';</script>";
}

// Test 6: Header injection through redirect
void redirect_with_header(const std::string& target) {
    // VULNERABLE: target can contain CRLF to inject headers
    std::cout << "Status: 302 Found\r\n";
    std::cout << "Location: " << target << "\r\n";
    std::cout << "Content-Type: text/html\r\n\r\n";
}

// Test 7: Subdomain-based redirect bypass
void redirect_same_domain(const std::string& url) {
    // VULNERABLE: evil.example.com matches *.example.com
    if (url.find("example.com") != std::string::npos) {
        std::cout << "Status: 302 Found\r\n";
        std::cout << "Location: " << url << "\r\n\r\n";
    }
}

// Test 8: Encoded redirect bypass
void redirect_decoded(const std::string& encoded_url) {
    // VULNERABLE: URL decoding may reveal malicious URL
    std::string decoded = encoded_url;  // Assume decoded
    std::cout << "Status: 302 Found\r\n";
    std::cout << "Location: " << decoded << "\r\n\r\n";
}
