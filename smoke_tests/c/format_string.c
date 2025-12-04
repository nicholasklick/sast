// Format String vulnerabilities in C
#include <stdio.h>
#include <syslog.h>

void format_string_printf(char *user_input) {
    // VULNERABLE: User input as format string
    printf(user_input);
}

void format_string_fprintf(FILE *fp, char *user_data) {
    // VULNERABLE: Format string in fprintf
    fprintf(fp, user_data);
}

void format_string_sprintf(char *buffer, char *user_input) {
    // VULNERABLE: Format string in sprintf
    sprintf(buffer, user_input);
}

void format_string_syslog(char *message) {
    // VULNERABLE: Format string in syslog
    syslog(LOG_INFO, message);
}

void format_string_snprintf(char *buf, size_t size, char *fmt) {
    // VULNERABLE: User-controlled format
    snprintf(buf, size, fmt);
}
