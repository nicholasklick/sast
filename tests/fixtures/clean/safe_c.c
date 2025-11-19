// Clean C code with no vulnerabilities
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

// Safe String Copy - Using strncpy with null termination
void safe_string_copy(char *dest, const char *src, size_t dest_size) {
    if (dest == NULL || src == NULL || dest_size == 0) {
        return;
    }
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
}

// Safe String Input - Using fgets instead of gets
void safe_string_input(char *buffer, size_t size) {
    if (fgets(buffer, size, stdin) != NULL) {
        // Remove newline
        buffer[strcspn(buffer, "\n")] = '\0';
    }
}

// Safe Integer Addition - Overflow check
int safe_add(int a, int b, int *result) {
    if ((b > 0 && a > INT_MAX - b) || (b < 0 && a < INT_MIN - b)) {
        return 0; // Overflow detected
    }
    *result = a + b;
    return 1; // Success
}

// Safe Memory Allocation
void* safe_malloc(size_t size) {
    void *ptr = malloc(size);
    if (ptr == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    return ptr;
}

// Safe Array Access - Bounds checking
int safe_array_access(int *array, size_t array_size, size_t index, int *value) {
    if (array == NULL || index >= array_size) {
        return 0; // Out of bounds
    }
    *value = array[index];
    return 1; // Success
}

// Safe File Operations - Error checking
FILE* safe_fopen(const char *filename, const char *mode) {
    FILE *fp = fopen(filename, mode);
    if (fp == NULL) {
        fprintf(stderr, "Failed to open file: %s\n", filename);
    }
    return fp;
}

// Safe Format String - Using snprintf
void safe_format_string(char *buffer, size_t size, const char *format, const char *value) {
    snprintf(buffer, size, "%s: %s", format, value);
}

// Safe Pointer Check
int safe_dereference(int *ptr) {
    if (ptr == NULL) {
        return -1;
    }
    return *ptr;
}

// Safe Resource Management
void safe_resource_cleanup(FILE *fp) {
    if (fp != NULL) {
        fclose(fp);
    }
}

// Safe String Comparison
int safe_string_compare(const char *s1, const char *s2) {
    if (s1 == NULL || s2 == NULL) {
        return -1;
    }
    return strcmp(s1, s2);
}
