// Memory Safety vulnerabilities in C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* use_after_free() {
    // VULNERABLE: Use after free
    char *ptr = malloc(100);
    strcpy(ptr, "hello");
    free(ptr);
    return ptr;  // Returning freed memory
}

void double_free(char *ptr) {
    // VULNERABLE: Double free
    free(ptr);
    free(ptr);
}

void memory_leak() {
    // VULNERABLE: Memory leak - no free
    char *buffer = malloc(1024);
    strcpy(buffer, "leaked data");
    // No free(buffer)
}

int* dangling_pointer() {
    // VULNERABLE: Returning pointer to stack variable
    int local = 42;
    return &local;
}

void null_dereference(int *ptr) {
    // VULNERABLE: No NULL check before dereference
    int value = *ptr;
    printf("%d\n", value);
}

void heap_overflow(size_t size) {
    // VULNERABLE: Integer overflow in allocation
    char *buffer = malloc(size + 100);
    memset(buffer, 0, size + 100);
}
