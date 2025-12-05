// Integer Overflow vulnerabilities in C++
#include <iostream>
#include <vector>
#include <cstdint>
#include <limits>

// Test 1: Integer overflow in allocation
void* allocate_items(size_t count, size_t item_size) {
    // VULNERABLE: count * item_size can overflow
    size_t total = count * item_size;
    return new char[total];
}

// Test 2: Signed integer overflow
int add_checked(int a, int b) {
    // VULNERABLE: No overflow check
    return a + b;
}

// Test 3: Overflow in loop counter
void process_count(unsigned int count) {
    // VULNERABLE: count + 1 can wrap to 0
    for (unsigned int i = 0; i < count + 1; i++) {
        std::cout << "Item " << i << std::endl;
    }
}

// Test 4: Overflow in vector sizing
void create_vector(int size) {
    // VULNERABLE: Negative size becomes huge positive
    std::vector<int> vec(size);
}

// Test 5: Overflow in array indexing
int get_element(const std::vector<int>& arr, int row, int width, int col) {
    // VULNERABLE: row * width can overflow
    int index = row * width + col;
    return arr[index];
}

// Test 6: Underflow in unsigned arithmetic
void subtract_unsigned(unsigned int a, unsigned int b) {
    // VULNERABLE: If b > a, result wraps around
    unsigned int result = a - b;
    std::cout << "Result: " << result << std::endl;
}

// Test 7: Implicit conversion overflow
void narrow_conversion(long long big_value) {
    // VULNERABLE: Truncation of large value
    int small_value = big_value;
    std::cout << "Converted: " << small_value << std::endl;
}

// Test 8: Overflow in size calculation
void allocate_buffer(int width, int height, int depth) {
    // VULNERABLE: Multiple multiplications can overflow
    size_t size = width * height * depth;
    char* buffer = new char[size];
    delete[] buffer;
}
