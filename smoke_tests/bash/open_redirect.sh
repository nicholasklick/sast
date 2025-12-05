#!/bin/bash
# Open Redirect vulnerabilities in Bash

# Test 1: curl follow redirect to user URL
vulnerable_curl_redirect() {
    local url="$1"
    # VULNERABLE: Following redirects to arbitrary URL
    curl -L "$url"
}

# Test 2: wget follow redirect
vulnerable_wget_redirect() {
    local url="$1"
    # VULNERABLE: wget follows redirects
    wget "$url"
}

# Test 3: HTTP redirect header in CGI
vulnerable_cgi_redirect() {
    local redirect_url="$1"
    # VULNERABLE: Open redirect in CGI script
    echo "Status: 302 Found"
    echo "Location: $redirect_url"
    echo ""
}

# Test 4: Meta refresh redirect
vulnerable_meta_redirect() {
    local url="$1"
    # VULNERABLE: HTML meta redirect
    echo "<meta http-equiv='refresh' content='0;url=$url'>"
}

# Test 5: JavaScript redirect generation
vulnerable_js_redirect() {
    local url="$1"
    # VULNERABLE: JavaScript redirect
    echo "<script>window.location='$url';</script>"
}

# Test 6: nginx config redirect
vulnerable_nginx_redirect() {
    local target="$1"
    # VULNERABLE: User input in nginx redirect
    echo "return 302 $target;"
}

# Test 7: Apache redirect config
vulnerable_apache_redirect() {
    local target="$1"
    # VULNERABLE: User input in Apache redirect
    echo "Redirect 302 /old $target"
}

# Test 8: Header injection for redirect
vulnerable_header_redirect() {
    local url="$1"
    # VULNERABLE: Header injection
    printf "HTTP/1.1 302 Found\r\nLocation: %s\r\n\r\n" "$url"
}

# Test 9: Python HTTP redirect via bash
vulnerable_python_redirect() {
    local url="$1"
    # VULNERABLE: Python redirect server
    python -c "
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header('Location', '$url')
        self.end_headers()
"
}

# Test 10: PHP redirect via bash
vulnerable_php_redirect() {
    local url="$1"
    # VULNERABLE: PHP redirect
    php -r "header('Location: $url'); exit();"
}

# Test 11: Return URL parameter
vulnerable_return_url() {
    local return_url="$1"
    # VULNERABLE: Unvalidated return URL
    echo "After login, redirecting to: $return_url"
    curl -L "$return_url"
}

# Test 12: Callback URL
vulnerable_callback() {
    local callback="$1"
    # VULNERABLE: Unvalidated callback
    curl -X POST "$callback" -d "status=complete"
}

# Test 13: Next URL parameter
vulnerable_next_url() {
    local next="$1"
    # VULNERABLE: Next page redirect
    echo "Location: $next"
}

# Test 14: OAuth redirect URI
vulnerable_oauth_redirect() {
    local redirect_uri="$1"
    local code="$2"
    # VULNERABLE: OAuth redirect without validation
    curl "$redirect_uri?code=$code"
}

# Test 15: Logout redirect
vulnerable_logout_redirect() {
    local post_logout="$1"
    # VULNERABLE: Post-logout redirect
    echo "Logged out. Redirecting..."
    curl -L "$post_logout"
}

