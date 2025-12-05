// XSS (Cross-Site Scripting) Test Cases

// Test 1: Direct HTML output without escaping
fn render_user_comment(comment: &str) -> String {
    // VULNERABLE: User input directly in HTML
    format!("<div class='comment'>{}</div>", comment)
}

// Test 2: JavaScript context without escaping
fn generate_script(user_data: &str) -> String {
    // VULNERABLE: User data in script tag
    format!("<script>var data = '{}';</script>", user_data)
}

// Test 3: Attribute injection
fn create_link(url: &str, title: &str) -> String {
    // VULNERABLE: URL and title not escaped
    format!("<a href='{}' title='{}'>{}</a>", url, title, title)
}

// Test 4: innerHTML equivalent
fn render_html_content(html: &str) -> String {
    // VULNERABLE: Raw HTML from user
    format!("<div>{}</div>", html)
}

// Test 5: Event handler injection
fn create_button(onclick_code: &str, label: &str) -> String {
    // VULNERABLE: User-controlled onclick attribute
    format!("<button onclick='{}'>{}</button>", onclick_code, label)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xss_vulnerabilities() {
        let _ = render_user_comment("<script>alert('XSS')</script>");
        let _ = generate_script("'; alert('XSS'); var x='");
        let _ = create_link("javascript:alert(1)", "Click me");
    }
}
