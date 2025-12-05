// Insecure CORS Test Cases

use actix_web::{HttpRequest, HttpResponse};

// Test 1: Wildcard CORS with credentials
fn set_wildcard_cors() -> HttpResponse {
    // VULNERABLE: Wildcard origin with credentials is not allowed
    HttpResponse::Ok()
        .append_header(("Access-Control-Allow-Origin", "*"))
        .append_header(("Access-Control-Allow-Credentials", "true"))
        .finish()
}

// Test 2: Reflecting origin without validation
fn reflect_origin(req: HttpRequest) -> HttpResponse {
    let origin = req.headers()
        .get("Origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // VULNERABLE: Reflecting origin without validation
    HttpResponse::Ok()
        .append_header(("Access-Control-Allow-Origin", origin))
        .append_header(("Access-Control-Allow-Credentials", "true"))
        .finish()
}

// Test 3: Null origin allowed
fn allow_null_origin() -> HttpResponse {
    // VULNERABLE: null origin can be exploited
    HttpResponse::Ok()
        .append_header(("Access-Control-Allow-Origin", "null"))
        .append_header(("Access-Control-Allow-Credentials", "true"))
        .finish()
}

// Test 4: Overly permissive CORS headers
fn set_permissive_cors(req: HttpRequest) -> HttpResponse {
    let origin = req.headers()
        .get("Origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("*");

    // VULNERABLE: Allowing all origins without proper validation
    HttpResponse::Ok()
        .append_header(("Access-Control-Allow-Origin", origin))
        .append_header(("Access-Control-Allow-Methods", "*"))
        .append_header(("Access-Control-Allow-Headers", "*"))
        .finish()
}

// Test 5: Weak subdomain validation
fn trust_subdomain_with_regex(req: HttpRequest) -> HttpResponse {
    let origin = req.headers()
        .get("Origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // VULNERABLE: Weak regex can be bypassed (e.g., evilexample.com)
    if origin.contains("example.com") {
        return HttpResponse::Ok()
            .append_header(("Access-Control-Allow-Origin", origin))
            .append_header(("Access-Control-Allow-Credentials", "true"))
            .finish();
    }

    HttpResponse::Ok().finish()
}
