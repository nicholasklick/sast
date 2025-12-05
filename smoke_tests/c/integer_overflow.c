// Integer Overflow vulnerabilities in C
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>

// Test 1: Integer overflow in allocation size
void* allocate_buffer(int count, int element_size) {
    // VULNERABLE: count * element_size can overflow
    int total_size = count * element_size;
    return malloc(total_size);
}

// Test 2: Signed integer overflow
int add_values(int a, int b) {
    // VULNERABLE: No overflow check before addition
    return a + b;
}

// Test 3: Integer overflow in loop bound
void process_items(unsigned int count) {
    // VULNERABLE: count + 1 can wrap to 0
    for (unsigned int i = 0; i < count + 1; i++) {
        printf("Processing item %u\n", i);
    }
}

// Test 4: Integer truncation
void copy_with_length(char *dest, char *src, size_t len) {
    // VULNERABLE: Truncation when casting size_t to int
    int safe_len = (int)len;
    if (safe_len > 0) {
        memcpy(dest, src, safe_len);
    }
}

// Test 5: Multiplication overflow in array indexing
int get_element(int *array, int row, int col, int width) {
    // VULNERABLE: row * width can overflow
    int index = row * width + col;
    return array[index];
}

// Test 6: Underflow in unsigned subtraction
void process_range(unsigned int start, unsigned int end) {
    // VULNERABLE: If start > end, this underflows
    unsigned int count = end - start;
    printf("Processing %u items\n", count);
}
