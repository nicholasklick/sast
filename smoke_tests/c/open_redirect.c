// Open Redirect vulnerabilities in C (CGI/Web context)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Test 1: Direct redirect from query parameter
void handle_redirect_cgi() {
    char *url = getenv("QUERY_STRING");
    // VULNERABLE: Unvalidated redirect
    printf("Status: 302 Found\r\n");
    printf("Location: %s\r\n\r\n", url);
}

// Test 2: Redirect from POST data
void handle_login_redirect(const char *redirect_url) {
    // VULNERABLE: redirect_url not validated
    printf("Status: 302 Found\r\n");
    printf("Location: %s\r\n\r\n", redirect_url);
}

// Test 3: Partial URL validation bypass
void redirect_with_check(const char *url) {
    // VULNERABLE: Only checks prefix, can be bypassed with //evil.com
    if (strncmp(url, "/", 1) == 0) {
        printf("Status: 302 Found\r\n");
        printf("Location: %s\r\n\r\n", url);
    }
}

// Test 4: Redirect via meta refresh
void meta_redirect(const char *url) {
    // VULNERABLE: Open redirect via meta tag
    printf("Content-Type: text/html\r\n\r\n");
    printf("<html><head><meta http-equiv='refresh' content='0;url=%s'></head></html>", url);
}

// Test 5: JavaScript redirect
void js_redirect(const char *url) {
    // VULNERABLE: Open redirect via JavaScript
    printf("Content-Type: text/html\r\n\r\n");
    printf("<html><body><script>window.location='%s';</script></body></html>", url);
}

// Test 6: Redirect with URL in path
void path_based_redirect() {
    char *path = getenv("PATH_INFO");
    // VULNERABLE: Path used as redirect target
    if (path && strlen(path) > 1) {
        printf("Status: 302 Found\r\n");
        printf("Location: %s\r\n\r\n", path + 1);  // Skip leading /
    }
}

// Test 7: Referrer-based redirect
void referer_redirect() {
    char *referer = getenv("HTTP_REFERER");
    // VULNERABLE: Trusting Referer header
    if (referer) {
        printf("Status: 302 Found\r\n");
        printf("Location: %s\r\n\r\n", referer);
    }
}

// Test 8: Encoded URL bypass
void redirect_after_decode(const char *encoded_url) {
    char decoded[1024];
    // Assume url_decode fills decoded buffer
    // VULNERABLE: Decoding may reveal malicious URL
    // url_decode(encoded_url, decoded, sizeof(decoded));
    strcpy(decoded, encoded_url);  // Simplified
    printf("Status: 302 Found\r\n");
    printf("Location: %s\r\n\r\n", decoded);
}
