// Heap Overflow vulnerabilities in C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Test 1: Basic heap buffer overflow
void heap_overflow_strcpy(const char *input) {
    char *buffer = malloc(32);
    // VULNERABLE: input may exceed 32 bytes
    strcpy(buffer, input);
    free(buffer);
}

// Test 2: Heap overflow via sprintf
void heap_overflow_sprintf(const char *name, int id) {
    char *buffer = malloc(16);
    // VULNERABLE: formatted string may exceed 16 bytes
    sprintf(buffer, "User: %s (ID: %d)", name, id);
    free(buffer);
}

// Test 3: Off-by-one on heap
void off_by_one_heap(const char *str) {
    size_t len = strlen(str);
    char *copy = malloc(len);  // VULNERABLE: Should be len + 1
    strcpy(copy, str);
    free(copy);
}

// Test 4: Heap overflow in loop
void fill_heap_buffer(int count) {
    int *arr = malloc(10 * sizeof(int));
    // VULNERABLE: count may exceed 10
    for (int i = 0; i < count; i++) {
        arr[i] = i;
    }
    free(arr);
}

// Test 5: Heap overflow via memcpy
void copy_to_heap(const char *src, size_t src_len) {
    char *dest = malloc(64);
    // VULNERABLE: src_len may exceed 64
    memcpy(dest, src, src_len);
    free(dest);
}

// Test 6: Integer overflow leading to heap overflow
void allocate_and_fill(int count) {
    // VULNERABLE: count * sizeof(int) may overflow
    int *arr = malloc(count * sizeof(int));
    if (arr) {
        for (int i = 0; i < count; i++) {
            arr[i] = 0;
        }
        free(arr);
    }
}

// Test 7: Heap overflow via strcat
void concatenate_on_heap(const char *s1, const char *s2) {
    char *buffer = malloc(strlen(s1) + 1);
    strcpy(buffer, s1);
    // VULNERABLE: No space allocated for s2
    strcat(buffer, s2);
    free(buffer);
}

// Test 8: Heap overflow through realloc misuse
void grow_buffer_unsafe(char **buf, size_t current, size_t needed) {
    if (needed > current) {
        *buf = realloc(*buf, needed);
    }
    // VULNERABLE: Writing beyond if realloc failed
    (*buf)[needed - 1] = '\0';
}
