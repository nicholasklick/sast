// Array/Buffer Bounds vulnerabilities in C++
#include <iostream>
#include <array>
#include <vector>
#include <cstring>

// Test 1: Static array out of bounds
void static_array_oob(int index) {
    int arr[10];
    // VULNERABLE: No bounds checking
    arr[index] = 42;
}

// Test 2: Negative array index
void negative_index(int* arr, int idx) {
    // VULNERABLE: Negative index not checked
    if (idx < 100) {
        arr[idx] = 0;  // idx could be negative
    }
}

// Test 3: Off-by-one in loop
void off_by_one_loop() {
    int arr[10];
    // VULNERABLE: Should be i < 10
    for (int i = 0; i <= 10; i++) {
        arr[i] = i;
    }
}

// Test 4: Pointer arithmetic overflow
void pointer_overflow(char* buffer, size_t offset) {
    // VULNERABLE: offset could cause wrap-around
    char* ptr = buffer + offset;
    *ptr = 'A';
}

// Test 5: Vector access without bounds check
void vector_unchecked(std::vector<int>& vec, size_t idx) {
    // VULNERABLE: operator[] doesn't check bounds
    vec[idx] = 42;
    // Safe: vec.at(idx) = 42;  // Would throw
}

// Test 6: std::array unchecked access
void array_unchecked(std::array<int, 10>& arr, size_t idx) {
    // VULNERABLE: No bounds checking
    arr[idx] = 0;
}

// Test 7: Calculated index overflow
void calculated_index(int* arr, unsigned int x, unsigned int y) {
    // VULNERABLE: x * y could overflow
    unsigned int idx = x * y;
    arr[idx] = 0;
}

// Test 8: String buffer overflow
void string_overflow(const char* input) {
    char buffer[64];
    // VULNERABLE: No length check
    strcpy(buffer, input);
}

// Test 9: memcpy size mismatch
void memcpy_overflow(char* dest, const char* src, size_t src_len) {
    char buffer[64];
    // VULNERABLE: src_len not compared to buffer size
    memcpy(buffer, src, src_len);
}

// Test 10: VLA stack overflow (C99 extension)
void vla_overflow(int size) {
    // VULNERABLE: User-controlled VLA size
    int arr[size];  // Could overflow stack
    arr[0] = 0;
}

// Test 11: Iterator invalidation
void iterator_invalid() {
    std::vector<int> vec = {1, 2, 3};
    auto it = vec.begin();
    vec.push_back(4);  // May reallocate
    // VULNERABLE: Iterator may be invalidated
    *it = 10;
}

// Test 12: Two-dimensional array miscalculation
void matrix_oob(int rows, int cols) {
    int matrix[10][10];
    // VULNERABLE: rows/cols could exceed bounds
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            matrix[i][j] = i + j;
        }
    }
}

// Test 13: Signed/unsigned comparison in bounds check
void signed_unsigned_compare(int* arr, int index) {
    size_t size = 10;
    // VULNERABLE: Negative index passes check
    if (index < size) {  // index implicitly converted to unsigned
        arr[index] = 0;
    }
}

// Test 14: Buffer read overrun
void read_overrun(const char* data, size_t len) {
    // VULNERABLE: Reading beyond buffer
    for (size_t i = 0; i <= len; i++) {
        std::cout << data[i];
    }
}
