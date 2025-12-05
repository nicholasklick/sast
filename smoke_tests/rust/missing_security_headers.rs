// Missing Security Headers Test Cases

use actix_web::{HttpResponse};

// Test 1: Missing X-Frame-Options
fn serve_page_without_frame_options() -> HttpResponse {
    // VULNERABLE: No X-Frame-Options header - vulnerable to clickjacking
    HttpResponse::Ok()
        .content_type("text/html")
        .body("<html><body>Content</body></html>")
}

// Test 2: Missing Content-Security-Policy
fn serve_page_without_csp() -> HttpResponse {
    // VULNERABLE: No CSP header - vulnerable to XSS
    HttpResponse::Ok()
        .content_type("text/html")
        .body("<html><body><script>...</script></body></html>")
}

// Test 3: Missing X-Content-Type-Options
fn serve_file_without_content_type_options() -> HttpResponse {
    // VULNERABLE: No X-Content-Type-Options - MIME sniffing enabled
    HttpResponse::Ok()
        .content_type("text/plain")
        .body("File content")
}

// Test 4: Missing Strict-Transport-Security
fn serve_secure_page_without_hsts() -> HttpResponse {
    // VULNERABLE: No HSTS header - vulnerable to downgrade attacks
    HttpResponse::Ok()
        .body("Secure content")
}

// Test 5: Missing multiple security headers
fn serve_with_no_security_headers() -> HttpResponse {
    // VULNERABLE: No security headers at all
    let html = r#"
        <!DOCTYPE html>
        <html>
        <head><title>Insecure Page</title></head>
        <body>
            <h1>Welcome</h1>
            <div id="content"></div>
        </body>
        </html>
    "#;

    HttpResponse::Ok()
        .content_type("text/html")
        .body(html)
}
