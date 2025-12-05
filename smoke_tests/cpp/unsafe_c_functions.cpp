// Unsafe C Library Function Usage in C++
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>

// Test 1: strcpy without bounds checking
void copy_string(char* dest, const char* src) {
    // VULNERABLE: No bounds checking
    strcpy(dest, src);
}

// Test 2: strcat buffer overflow
void concat_strings(char* buffer, const char* suffix) {
    // VULNERABLE: No space checking
    strcat(buffer, suffix);
}

// Test 3: gets - always vulnerable (deprecated)
void read_line(char* buffer) {
    // VULNERABLE: No bounds checking at all
    gets(buffer);
}

// Test 4: sprintf without size limit
void format_string(char* buffer, const char* name, int value) {
    // VULNERABLE: No buffer size limit
    sprintf(buffer, "Name: %s, Value: %d", name, value);
}

// Test 5: scanf with %s (no width limit)
void read_string() {
    char buffer[64];
    // VULNERABLE: %s has no width limit
    scanf("%s", buffer);
}

// Test 6: strncpy without null termination
void copy_n_chars(char* dest, const char* src, size_t n) {
    // VULNERABLE: May not null-terminate
    strncpy(dest, src, n);
    // dest may not be null-terminated if strlen(src) >= n
}

// Test 7: memcpy with overlapping regions
void copy_overlapping(char* buffer, size_t offset, size_t len) {
    // VULNERABLE: Undefined behavior with overlapping memory
    memcpy(buffer, buffer + offset, len);
}

// Test 8: realpath without size check
void resolve_path(const char* path) {
    char resolved[PATH_MAX];
    // VULNERABLE: resolved buffer assumption
    realpath(path, resolved);
}

// Test 9: getwd - deprecated and unsafe
void get_directory(char* buffer) {
    // VULNERABLE: No size parameter
    getwd(buffer);
}

// Test 10: system() with user input
void run_command(const char* cmd) {
    // VULNERABLE: Command injection
    system(cmd);
}

// Test 11: atoi without error checking
int parse_int(const char* str) {
    // VULNERABLE: No error detection
    return atoi(str);
}

// Test 12: strtok with non-reentrant state
void tokenize(char* str) {
    // VULNERABLE: Not thread-safe
    char* token = strtok(str, ",");
    while (token) {
        std::cout << token << std::endl;
        token = strtok(nullptr, ",");
    }
}
