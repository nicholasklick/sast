// Open Redirect Test Cases

// Test 1: Direct redirect to user-provided URL
fn redirect_to_url(url: &str) -> String {
    // VULNERABLE: Redirecting to unvalidated URL
    format!("Location: {}\r\n\r\n", url)
}

// Test 2: Redirect with return parameter
fn handle_login_redirect(return_url: &str) -> String {
    // Authenticate user...
    // VULNERABLE: Redirecting to user-controlled URL after login
    format!("HTTP/1.1 302 Found\r\nLocation: {}\r\n\r\n", return_url)
}

// Test 3: Meta refresh redirect
fn client_side_redirect(target_url: &str) -> String {
    // VULNERABLE: User input in meta refresh
    format!(r#"<html><head><meta http-equiv="refresh" content="0;url={}"></head></html>"#, target_url)
}

// Test 4: JavaScript redirect
fn js_redirect(destination: &str) -> String {
    // VULNERABLE: User-controlled redirect destination
    format!(r#"<script>window.location.href = '{}';</script>"#, destination)
}

// Test 5: Redirect using actix-web
use actix_web::{HttpResponse, web};

async fn redirect_handler(query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    if let Some(url) = query.get("url") {
        // VULNERABLE: No validation of redirect URL
        return HttpResponse::Found()
            .append_header(("Location", url.as_str()))
            .finish();
    }
    HttpResponse::BadRequest().finish()
}
