// Buffer Overflow vulnerabilities in C++
#include <iostream>
#include <cstring>
#include <string>

void unsafe_strcpy(const char* input) {
    // VULNERABLE: Buffer overflow via strcpy
    char buffer[64];
    strcpy(buffer, input);
}

void unsafe_array_access(int* arr, size_t index) {
    // VULNERABLE: No bounds checking
    std::cout << arr[index] << std::endl;
}

class UnsafeBuffer {
    char data[100];
public:
    void copy(const char* src) {
        // VULNERABLE: Unbounded copy
        strcpy(data, src);
    }

    char get(int index) {
        // VULNERABLE: No bounds check
        return data[index];
    }
};

void stack_smash(char* user_input) {
    // VULNERABLE: Stack buffer overflow
    char local[32];
    memcpy(local, user_input, strlen(user_input));
}
