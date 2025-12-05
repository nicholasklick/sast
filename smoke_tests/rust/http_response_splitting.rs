// HTTP Response Splitting Test Cases

use actix_web::{HttpRequest, HttpResponse, web};

// Test 1: Setting header with unsanitized user input
fn set_custom_header(req: HttpRequest) -> HttpResponse {
    let user_value = req.query_string();
    // VULNERABLE: user_value could contain \r\n to inject headers
    HttpResponse::Ok()
        .append_header(("X-Custom-Header", user_value))
        .body("OK")
}

// Test 2: Location header with user input
fn redirect_with_user_input(query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    if let Some(target) = query.get("target") {
        // VULNERABLE: target could contain \r\n\r\n<script>alert(1)</script>
        return HttpResponse::Found()
            .append_header(("Location", target.as_str()))
            .finish();
    }
    HttpResponse::BadRequest().finish()
}

// Test 3: Set-Cookie with user-controlled value
fn set_user_cookie(query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    if let Some(cookie_value) = query.get("value") {
        // VULNERABLE: cookie_value could inject additional headers
        let cookie_header = format!("user={}; Path=/", cookie_value);
        return HttpResponse::Ok()
            .append_header(("Set-Cookie", cookie_header))
            .body("Cookie set");
    }
    HttpResponse::BadRequest().finish()
}

// Test 4: Multiple headers from user input
fn set_multiple_headers(query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    let header_name = query.get("name").map(|s| s.as_str()).unwrap_or("X-Default");
    let header_value = query.get("value").map(|s| s.as_str()).unwrap_or("");

    // VULNERABLE: Both name and value could contain CRLF
    HttpResponse::Ok()
        .append_header((header_name, header_value))
        .body("Headers set")
}

// Test 5: Content-Type header injection
fn serve_content(query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    if let Some(content_type) = query.get("type") {
        // VULNERABLE: content_type could inject headers or response body
        return HttpResponse::Ok()
            .append_header(("Content-Type", content_type.as_str()))
            .body("Content here");
    }
    HttpResponse::BadRequest().finish()
}
