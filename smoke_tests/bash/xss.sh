#!/bin/bash
# XSS (Cross-Site Scripting) vulnerabilities in Bash
# Note: Bash scripts that generate HTML output

# Test 1: Echo user input to HTML
vulnerable_echo_html() {
    local user_input="$1"
    # VULNERABLE: Direct output to HTML
    echo "<html><body>Hello, $user_input</body></html>"
}

# Test 2: CGI script with unescaped output
vulnerable_cgi() {
    # VULNERABLE: CGI output without encoding
    echo "Content-Type: text/html"
    echo ""
    echo "<html><body>"
    echo "Search results for: $QUERY_STRING"
    echo "</body></html>"
}

# Test 3: Generating HTML file with user data
vulnerable_html_file() {
    local username="$1"
    local output_file="$2"
    # VULNERABLE: User input in generated HTML
    cat > "$output_file" << EOF
<html>
<head><title>Profile</title></head>
<body>
<h1>Welcome, $username</h1>
</body>
</html>
EOF
}

# Test 4: printf to HTML
vulnerable_printf_html() {
    local message="$1"
    # VULNERABLE: printf without escaping
    printf "<div class='message'>%s</div>\n" "$message"
}

# Test 5: sed replacement in HTML template
vulnerable_sed_template() {
    local name="$1"
    local template="$2"
    # VULNERABLE: Unescaped replacement in HTML
    sed "s/{{NAME}}/$name/g" "$template"
}

# Test 6: awk output to HTML
vulnerable_awk_html() {
    local data_file="$1"
    # VULNERABLE: awk output directly to HTML
    awk '{print "<tr><td>" $1 "</td><td>" $2 "</td></tr>"}' "$data_file"
}

# Test 7: envsubst with HTML template
vulnerable_envsubst() {
    export USER_INPUT="$1"
    # VULNERABLE: Environment substitution in HTML
    envsubst < template.html
}

# Test 8: heredoc HTML with variables
vulnerable_heredoc_html() {
    local title="$1"
    local content="$2"
    # VULNERABLE: Variables in heredoc HTML
    cat << EOF
<!DOCTYPE html>
<html>
<head><title>$title</title></head>
<body>$content</body>
</html>
EOF
}

# Test 9: JSON embedded in HTML
vulnerable_json_html() {
    local json_data="$1"
    # VULNERABLE: JSON in script tag
    echo "<script>var data = $json_data;</script>"
}

# Test 10: URL parameter in HTML link
vulnerable_url_html() {
    local url="$1"
    # VULNERABLE: Unvalidated URL in href
    echo "<a href='$url'>Click here</a>"
}

# Test 11: Form action with user input
vulnerable_form_action() {
    local action_url="$1"
    # VULNERABLE: User-controlled form action
    echo "<form action='$action_url' method='POST'>"
}

# Test 12: Image src with user input
vulnerable_img_src() {
    local image_url="$1"
    # VULNERABLE: User-controlled image source
    echo "<img src='$image_url' alt='User image'>"
}

# Test 13: Style attribute injection
vulnerable_style() {
    local color="$1"
    # VULNERABLE: User input in style
    echo "<div style='color: $color'>Text</div>"
}

# Test 14: Event handler injection
vulnerable_event() {
    local handler="$1"
    # VULNERABLE: User input in event handler
    echo "<button onclick='$handler'>Click</button>"
}

# Test 15: Meta refresh with user URL
vulnerable_meta_refresh() {
    local redirect_url="$1"
    # VULNERABLE: User-controlled redirect
    echo "<meta http-equiv='refresh' content='0;url=$redirect_url'>"
}

