// Use-After-Free vulnerabilities in C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Test 1: Basic use after free
void basic_uaf() {
    char *buffer = malloc(100);
    strcpy(buffer, "sensitive data");
    free(buffer);
    // VULNERABLE: Use after free
    printf("%s\n", buffer);
}

// Test 2: Use after free in conditional
void conditional_uaf(int condition) {
    char *ptr = malloc(64);
    if (condition) {
        free(ptr);
    }
    // VULNERABLE: ptr may be freed
    ptr[0] = 'A';
}

// Test 3: Use after free through alias
void aliased_uaf() {
    int *original = malloc(sizeof(int));
    int *alias = original;
    *original = 42;
    free(original);
    // VULNERABLE: alias points to freed memory
    printf("%d\n", *alias);
}

// Test 4: Use after free in loop
void loop_uaf() {
    char *buffers[10];
    for (int i = 0; i < 10; i++) {
        buffers[i] = malloc(32);
    }
    free(buffers[5]);
    // VULNERABLE: Accessing freed buffer
    for (int i = 0; i < 10; i++) {
        buffers[i][0] = 'X';
    }
}

// Test 5: Return after free
char* return_after_free() {
    char *data = malloc(100);
    strcpy(data, "test");
    free(data);
    // VULNERABLE: Returning freed pointer
    return data;
}

// Test 6: Use after realloc failure
void realloc_uaf(size_t new_size) {
    char *ptr = malloc(100);
    char *new_ptr = realloc(ptr, new_size);
    if (new_ptr == NULL) {
        // VULNERABLE: ptr may be invalid after failed realloc
        // (depends on implementation)
        free(ptr);
    }
    // VULNERABLE: using ptr without checking new_ptr
    strcpy(ptr, "data");
}
