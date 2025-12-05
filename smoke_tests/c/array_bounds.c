// Array Out-of-Bounds vulnerabilities in C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Test 1: Simple array index out of bounds
void access_out_of_bounds(int index) {
    int arr[10];
    // VULNERABLE: No bounds check
    arr[index] = 42;
}

// Test 2: Negative array index
void negative_index(int *arr, int idx) {
    // VULNERABLE: idx could be negative
    printf("%d\n", arr[idx]);
}

// Test 3: User-controlled array index
void user_controlled_index(int user_idx) {
    int values[100] = {0};
    // VULNERABLE: user_idx not validated
    int result = values[user_idx];
    printf("Value: %d\n", result);
}

// Test 4: Loop bound mismatch
void process_array_wrong_bound(int *arr, int declared_size, int actual_size) {
    // VULNERABLE: Using wrong size for bounds
    for (int i = 0; i < actual_size; i++) {
        arr[i] = i;  // May exceed declared_size
    }
}

// Test 5: VLA with user input size
void vla_overflow(int size) {
    // VULNERABLE: size could be very large or negative
    int arr[size];
    for (int i = 0; i < size; i++) {
        arr[i] = 0;
    }
}

// Test 6: Multi-dimensional array bounds
void matrix_access(int row, int col) {
    int matrix[10][10];
    // VULNERABLE: No bounds checking on row or col
    matrix[row][col] = 1;
}

// Test 7: String as array with wrong size
void string_overread(const char *str) {
    char local[8];
    // VULNERABLE: str might be longer than 7 chars
    for (int i = 0; i < 10; i++) {
        local[i] = str[i];
    }
}

// Test 8: Arithmetic overflow in index calculation
void computed_index(int base, int offset) {
    int arr[1000];
    // VULNERABLE: base + offset could overflow or be out of bounds
    int idx = base + offset;
    arr[idx] = 0;
}

// Test 9: Using sizeof incorrectly for bounds
void sizeof_confusion(int *ptr, size_t count) {
    // VULNERABLE: sizeof(ptr) is pointer size, not array size
    for (size_t i = 0; i < sizeof(ptr); i++) {
        ptr[i] = 0;
    }
}

// Test 10: Reading uninitialized array elements
void partial_init_read() {
    int arr[10] = {1, 2, 3};  // Only first 3 initialized to non-zero
    // VULNERABLE: Logical issue - arr[5] is 0, may be unexpected
    if (arr[15]) {  // VULNERABLE: Out of bounds
        printf("Non-zero\n");
    }
}
