// Format String vulnerabilities in C++
#include <iostream>
#include <cstdio>
#include <cstdarg>
#include <syslog.h>

// Test 1: printf with user-controlled format
void print_message(const char* user_input) {
    // VULNERABLE: User controls format string
    printf(user_input);
}

// Test 2: sprintf with user format
void format_to_buffer(char* buffer, const char* user_format) {
    // VULNERABLE: user_format from untrusted source
    sprintf(buffer, user_format);
}

// Test 3: fprintf to file with user format
void log_to_file(FILE* logfile, const char* user_input) {
    // VULNERABLE: Format string from user
    fprintf(logfile, user_input);
}

// Test 4: snprintf with user format
void safe_buffer_format(char* buf, size_t size, const char* format) {
    // VULNERABLE: format still user-controlled
    snprintf(buf, size, format);
}

// Test 5: syslog with user format
void log_event(const char* event_data) {
    // VULNERABLE: Format string to syslog
    openlog("myapp", LOG_PID, LOG_USER);
    syslog(LOG_INFO, event_data);
    closelog();
}

// Test 6: vprintf wrapper with user format
void custom_print(const char* format, ...) {
    va_list args;
    va_start(args, format);
    // VULNERABLE if format comes from user
    vprintf(format, args);
    va_end(args);
}

// Test 7: scanf with user format
void read_input(const char* format) {
    char buffer[100];
    // VULNERABLE: Format string controls parsing
    scanf(format, buffer);
}

// Test 8: wprintf with wide string format
void print_wide(const wchar_t* user_format) {
    // VULNERABLE: Wide format string attack
    wprintf(user_format);
}

// Test 9: Error message with format
void report_error(const char* error_msg) {
    char buffer[256];
    // VULNERABLE: error_msg used as format
    sprintf(buffer, error_msg);
    std::cerr << buffer << std::endl;
}

// Test 10: Multiple format string sinks
void process_input(const char* input) {
    // VULNERABLE: Same input to multiple format functions
    printf(input);
    fprintf(stderr, input);

    char buf[100];
    sprintf(buf, input);
}
