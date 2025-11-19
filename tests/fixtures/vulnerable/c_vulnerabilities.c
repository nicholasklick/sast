// C Vulnerability Test Fixtures
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 1. Buffer Overflow - strcpy
void buffer_overflow_strcpy(char *input) {
    char buffer[64];
    strcpy(buffer, input); // No bounds checking
}

// 2. Buffer Overflow - gets
void buffer_overflow_gets() {
    char buffer[64];
    gets(buffer); // Deprecated, unbounded read
}

// 3. Format String Vulnerability
void format_string_vuln(char *user_input) {
    printf(user_input); // User input directly in format string
}

// 4. SQL Injection - String concatenation
void sql_injection(char *user_id) {
    char query[256];
    sprintf(query, "SELECT * FROM users WHERE id = '%s'", user_id);
    // execute_query(query);
}

// 5. Command Injection
void command_injection(char *filename) {
    char command[256];
    sprintf(command, "cat %s", filename);
    system(command);
}

// 6. Use After Free
void use_after_free() {
    char *ptr = malloc(100);
    free(ptr);
    strcpy(ptr, "data"); // Using freed memory
}

// 7. Double Free
void double_free() {
    char *ptr = malloc(100);
    free(ptr);
    free(ptr); // Freeing same pointer twice
}

// 8. Memory Leak
void memory_leak() {
    char *ptr = malloc(100);
    // Forgot to free
}

// 9. Integer Overflow
int integer_overflow(int a, int b) {
    return a + b; // No overflow check
}

// 10. Null Pointer Dereference
void null_pointer_deref(int *ptr) {
    *ptr = 42; // No null check
}

// 11. Hardcoded Credentials
const char *API_KEY = "sk_live_c1234567890abcdef";

void connect_to_db() {
    const char *password = "CSecret123!";
    // connect(password);
}

// 12. Path Traversal
void path_traversal(char *filename) {
    char path[256];
    sprintf(path, "/var/data/%s", filename);
    FILE *fp = fopen(path, "r");
}

// 13. Race Condition
int shared_counter = 0;

void increment_counter() {
    // No mutex protection
    shared_counter++;
}

// 14. Unsafe String Operations - strcat
void unsafe_strcat(char *dest, char *src) {
    strcat(dest, src); // No bounds checking
}

// 15. Uninitialized Variable
void uninitialized_var() {
    int x;
    printf("%d", x); // Using uninitialized variable
}

// 16. Off-by-One Error
void off_by_one() {
    char buffer[10];
    for (int i = 0; i <= 10; i++) {
        buffer[i] = 'A'; // i <= 10 causes off-by-one
    }
}

// 17. Weak Random Number Generation
int weak_random() {
    return rand(); // Predictable PRNG for security
}

// 18. Unsafe Type Cast
void unsafe_cast(void *ptr) {
    int *iptr = (int *)ptr; // No type safety
    *iptr = 42;
}

// 19. Missing Bounds Check
void missing_bounds_check(char *buffer, int index) {
    buffer[index] = 'X'; // No bounds check
}

// 20. Time-of-Check Time-of-Use (TOCTOU)
void toctou(char *filename) {
    if (access(filename, R_OK) == 0) {
        // File permissions can change here
        FILE *fp = fopen(filename, "r");
    }
}
