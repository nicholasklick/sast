// Missing Security Headers vulnerabilities in Dart

import 'dart:io';

// Test 1: No security headers at all
void vulnerableNoSecurityHeaders(HttpResponse response) {
  // VULNERABLE: No security headers set
  response.write('Hello World');
}

// Test 2: Missing X-Content-Type-Options
void vulnerableMissingContentTypeOptions(HttpResponse response) {
  // VULNERABLE: Missing nosniff header
  response.headers.add('X-Frame-Options', 'DENY');
  response.headers.add('X-XSS-Protection', '1; mode=block');
  // Missing: X-Content-Type-Options: nosniff
}

// Test 3: Missing X-Frame-Options
void vulnerableMissingFrameOptions(HttpResponse response) {
  // VULNERABLE: Missing clickjacking protection
  response.headers.add('X-Content-Type-Options', 'nosniff');
  // Missing: X-Frame-Options
}

// Test 4: Missing Content-Security-Policy
void vulnerableMissingCsp(HttpResponse response) {
  // VULNERABLE: No CSP header
  response.headers.add('X-Frame-Options', 'DENY');
  response.headers.add('X-Content-Type-Options', 'nosniff');
  // Missing: Content-Security-Policy
}

// Test 5: Weak CSP with unsafe-inline
void vulnerableWeakCsp(HttpResponse response) {
  // VULNERABLE: CSP allows inline scripts
  response.headers.add('Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline'");
}

// Test 6: CSP with unsafe-eval
void vulnerableUnsafeEvalCsp(HttpResponse response) {
  // VULNERABLE: CSP allows eval()
  response.headers.add('Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-eval'");
}

// Test 7: Missing Strict-Transport-Security
void vulnerableMissingHsts(HttpResponse response) {
  // VULNERABLE: No HSTS header
  response.headers.add('X-Frame-Options', 'DENY');
  response.headers.add('X-Content-Type-Options', 'nosniff');
  // Missing: Strict-Transport-Security
}

// Test 8: Weak HSTS configuration
void vulnerableWeakHsts(HttpResponse response) {
  // VULNERABLE: Short max-age
  response.headers.add('Strict-Transport-Security', 'max-age=86400');
  // Should be at least 1 year (31536000)
}

// Test 9: HSTS without includeSubDomains
void vulnerableHstsNoSubdomains(HttpResponse response) {
  // VULNERABLE: Subdomains not protected
  response.headers.add('Strict-Transport-Security', 'max-age=31536000');
  // Missing: includeSubDomains
}

// Test 10: Missing Referrer-Policy
void vulnerableMissingReferrerPolicy(HttpResponse response) {
  // VULNERABLE: No referrer policy
  response.headers.add('X-Frame-Options', 'DENY');
  // Missing: Referrer-Policy
}

// Test 11: Weak Referrer-Policy
void vulnerableWeakReferrerPolicy(HttpResponse response) {
  // VULNERABLE: Leaks referrer to other origins
  response.headers.add('Referrer-Policy', 'unsafe-url');
}

// Test 12: Missing Permissions-Policy
void vulnerableMissingPermissionsPolicy(HttpResponse response) {
  // VULNERABLE: No feature restrictions
  response.headers.add('X-Frame-Options', 'DENY');
  // Missing: Permissions-Policy
}

// Test 13: Deprecated X-XSS-Protection
void vulnerableDeprecatedXssProtection(HttpResponse response) {
  // VULNERABLE: Relying on deprecated header instead of CSP
  response.headers.add('X-XSS-Protection', '1; mode=block');
  // Should use CSP instead
}

// Test 14: Missing Cache-Control for sensitive pages
void vulnerableMissingCacheControl(HttpResponse response, String sensitiveData) {
  // VULNERABLE: Sensitive data may be cached
  response.write(sensitiveData);
  // Missing: Cache-Control: no-store, no-cache, must-revalidate
}

// Test 15: Overly permissive CORS with missing security headers
void vulnerableCorsNoHeaders(HttpResponse response) {
  // VULNERABLE: CORS without proper security headers
  response.headers.add('Access-Control-Allow-Origin', '*');
  // Missing all security headers
}

// Test 16: X-Frame-Options with ALLOWALL
void vulnerableFrameOptionsAllowAll(HttpResponse response) {
  // VULNERABLE: Allows framing from anywhere
  response.headers.add('X-Frame-Options', 'ALLOWALL');
}

// Test 17: CSP report-only mode in production
void vulnerableCspReportOnly(HttpResponse response) {
  // VULNERABLE: CSP not enforced, only reporting
  response.headers.add('Content-Security-Policy-Report-Only',
    "default-src 'self'");
}

// Test 18: Server header information disclosure
void vulnerableServerHeader(HttpResponse response) {
  // VULNERABLE: Exposing server version
  response.headers.add('Server', 'Dart/2.19.0');
  response.headers.add('X-Powered-By', 'Shelf/1.4.0');
}

// Test 19: Cross-Origin headers missing
void vulnerableMissingCrossOriginHeaders(HttpResponse response) {
  // VULNERABLE: Missing cross-origin isolation headers
  // Missing: Cross-Origin-Opener-Policy
  // Missing: Cross-Origin-Embedder-Policy
  // Missing: Cross-Origin-Resource-Policy
}

// Test 20: Incomplete security header middleware
class VulnerableSecurityMiddleware {
  void addHeaders(HttpResponse response) {
    // VULNERABLE: Incomplete set of security headers
    response.headers.add('X-Frame-Options', 'SAMEORIGIN');
    // Missing many important headers
  }
}
