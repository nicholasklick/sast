// Insecure Cookie Test Cases

use actix_web::{HttpResponse, cookie::Cookie};

// Test 1: Cookie without Secure flag
fn set_insecure_cookie() -> HttpResponse {
    // VULNERABLE: Missing Secure flag - can be sent over HTTP
    let cookie = Cookie::build("session", "abc123")
        .http_only(true)
        .finish();

    HttpResponse::Ok().cookie(cookie).finish()
}

// Test 2: Cookie without HttpOnly flag
fn set_javascript_accessible_cookie() -> HttpResponse {
    // VULNERABLE: Missing HttpOnly - accessible via JavaScript
    let cookie = Cookie::build("authToken", "xyz789")
        .secure(true)
        .finish();

    HttpResponse::Ok().cookie(cookie).finish()
}

// Test 3: Cookie without SameSite attribute
fn set_cookie_without_samesite() -> HttpResponse {
    // VULNERABLE: Missing SameSite - vulnerable to CSRF
    let cookie = Cookie::build("user", "john")
        .secure(true)
        .http_only(true)
        .finish();

    HttpResponse::Ok().cookie(cookie).finish()
}

// Test 4: Raw Set-Cookie header without security flags
fn set_raw_cookie() -> HttpResponse {
    // VULNERABLE: No security flags in raw Set-Cookie header
    HttpResponse::Ok()
        .append_header(("Set-Cookie", "sessionId=secret123; Path=/"))
        .finish()
}

// Test 5: Cookie with SameSite=None without Secure
fn set_samesite_none_cookie() -> HttpResponse {
    use actix_web::cookie::SameSite;

    // VULNERABLE: SameSite=None requires Secure flag
    let cookie = Cookie::build("tracking", "12345")
        .same_site(SameSite::None)
        .http_only(true)
        .finish();

    HttpResponse::Ok().cookie(cookie).finish()
}
