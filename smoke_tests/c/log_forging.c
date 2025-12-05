// Log Forging/Injection vulnerabilities in C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

// Test 1: Direct user input in log
void log_user_action(const char *username) {
    // VULNERABLE: username can contain newlines to forge log entries
    printf("[INFO] User %s logged in\n", username);
}

// Test 2: Syslog injection
void log_to_syslog(const char *message) {
    // VULNERABLE: message can contain format specifiers or newlines
    syslog(LOG_INFO, message);
}

// Test 3: Log file injection
void write_to_log(const char *user_input) {
    FILE *log = fopen("/var/log/myapp.log", "a");
    if (log) {
        time_t now = time(NULL);
        // VULNERABLE: user_input not sanitized
        fprintf(log, "[%ld] User action: %s\n", now, user_input);
        fclose(log);
    }
}

// Test 4: Format string in logging
void log_error(const char *error_msg) {
    // VULNERABLE: Format string vulnerability
    fprintf(stderr, error_msg);
}

// Test 5: HTTP header injection through logs
void log_http_request(const char *method, const char *path, const char *user_agent) {
    // VULNERABLE: user_agent can contain CRLF to inject headers
    printf("Request: %s %s\nUser-Agent: %s\n", method, path, user_agent);
}

// Test 6: Carriage return injection
void log_transaction(const char *account, double amount) {
    // VULNERABLE: account may contain \r\n to forge entries
    printf("Transaction: Account=%s Amount=%.2f Status=PENDING\n", account, amount);
}

// Test 7: Null byte injection in logs
void log_filename(const char *filename) {
    // VULNERABLE: filename may contain null bytes
    printf("Processing file: %s\n", filename);
}

// Test 8: Log injection through error messages
void log_database_error(const char *query, const char *error) {
    // VULNERABLE: Both query and error could contain injection characters
    fprintf(stderr, "DB Error executing '%s': %s\n", query, error);
}
