// Off-by-One Error vulnerabilities in C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Test 1: Classic off-by-one in loop
void fill_array_obo() {
    int arr[10];
    // VULNERABLE: Accesses arr[10] which is out of bounds
    for (int i = 0; i <= 10; i++) {
        arr[i] = i;
    }
}

// Test 2: Off-by-one in string termination
void copy_string_obo(const char *src, size_t max_len) {
    char dest[64];
    size_t i;
    // VULNERABLE: May not null-terminate if src is exactly max_len
    for (i = 0; i < max_len && src[i]; i++) {
        dest[i] = src[i];
    }
    // Missing: dest[i] = '\0';
}

// Test 3: Fence post error
int sum_array(int *arr, int len) {
    int sum = 0;
    // VULNERABLE: Should be i < len
    for (int i = 0; i <= len; i++) {
        sum += arr[i];
    }
    return sum;
}

// Test 4: Off-by-one in buffer allocation
char* duplicate_string(const char *str) {
    size_t len = strlen(str);
    // VULNERABLE: Should allocate len + 1 for null terminator
    char *copy = malloc(len);
    strcpy(copy, str);
    return copy;
}

// Test 5: Off-by-one in array index calculation
void process_elements(int *arr, int start, int end) {
    // VULNERABLE: end index is accessed but may be out of bounds
    for (int i = start; i <= end; i++) {
        arr[i] *= 2;
    }
}

// Test 6: Off-by-one with sizeof
void clear_buffer() {
    char buffer[100];
    // VULNERABLE: sizeof(buffer) - 1 leaves last byte potentially uncleared
    // Or sometimes: using sizeof on pointer instead of array
    memset(buffer, 0, sizeof(buffer) + 1);  // writes one byte too many
}

// Test 7: Off-by-one in strncpy
void safe_copy(char *dest, const char *src, size_t dest_size) {
    // VULNERABLE: strncpy may not null-terminate
    strncpy(dest, src, dest_size);
    // Missing: dest[dest_size - 1] = '\0';
}

// Test 8: Off-by-one in reverse loop
void reverse_array(int *arr, int len) {
    // VULNERABLE: when i becomes -1, it wraps to large number (if unsigned)
    for (int i = len; i >= 0; i--) {
        printf("%d\n", arr[i]);  // arr[len] is out of bounds
    }
}
