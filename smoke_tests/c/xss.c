// XSS (Cross-Site Scripting) Test Cases

#include <stdio.h>
#include <string.h>

// Test 1: Direct HTML output without escaping
void render_user_comment(const char *comment) {
    // VULNERABLE: User input directly in HTML
    printf("<div class='comment'>%s</div>\n", comment);
}

// Test 2: JavaScript context without escaping
void generate_script(const char *user_data) {
    // VULNERABLE: User data in script tag
    printf("<script>var data = '%s';</script>\n", user_data);
}

// Test 3: Attribute injection
void create_link(const char *url, const char *title) {
    // VULNERABLE: URL and title not escaped
    printf("<a href='%s' title='%s'>%s</a>\n", url, title, title);
}

// Test 4: innerHTML equivalent
void render_html_content(const char *html) {
    // VULNERABLE: Raw HTML from user
    printf("<div>%s</div>\n", html);
}

// Test 5: Event handler injection
void create_button(const char *onclick_code, const char *label) {
    // VULNERABLE: User-controlled onclick attribute
    printf("<button onclick='%s'>%s</button>\n", onclick_code, label);
}
