// Missing CSRF Protection Test Cases

use actix_web::{web, HttpResponse};
use serde::Deserialize;

#[derive(Deserialize)]
struct UpdateProfile {
    email: String,
    phone: String,
}

// Test 1: State-changing POST without CSRF token
async fn update_user_profile(data: web::Json<UpdateProfile>) -> HttpResponse {
    // VULNERABLE: No CSRF token validation
    // Update user profile in database
    HttpResponse::Ok().json(serde_json::json!({"success": true}))
}

#[derive(Deserialize)]
struct DeleteRequest {
    user_id: String,
}

// Test 2: DELETE endpoint without CSRF protection
async fn delete_account(data: web::Json<DeleteRequest>) -> HttpResponse {
    // VULNERABLE: Destructive action without CSRF token
    // Delete user account
    HttpResponse::Ok().json(serde_json::json!({"deleted": true}))
}

#[derive(Deserialize)]
struct TransferRequest {
    from_account: String,
    to_account: String,
    amount: f64,
}

// Test 3: Money transfer without CSRF token
async fn transfer_funds(data: web::Json<TransferRequest>) -> HttpResponse {
    // VULNERABLE: Financial transaction without CSRF protection
    // Process transfer
    HttpResponse::Ok().json(serde_json::json!({"transferred": data.amount}))
}

#[derive(Deserialize)]
struct PasswordChange {
    old_password: String,
    new_password: String,
}

// Test 4: Password change without CSRF token
async fn change_password(data: web::Json<PasswordChange>) -> HttpResponse {
    // VULNERABLE: Security-critical action without CSRF token
    // Change password
    HttpResponse::Ok().json(serde_json::json!({"success": true}))
}

#[derive(Deserialize)]
struct PromoteRequest {
    user_id: String,
}

// Test 5: Admin action without CSRF protection
async fn promote_to_admin(data: web::Json<PromoteRequest>) -> HttpResponse {
    // VULNERABLE: Privilege escalation without CSRF token
    // Promote user to admin
    HttpResponse::Ok().json(serde_json::json!({"promoted": true}))
}
