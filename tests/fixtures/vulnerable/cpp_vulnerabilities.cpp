// C++ Vulnerability Test Fixtures
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <cstring>

// 1. Buffer Overflow - strcpy
void bufferOverflowStrcpy(const char* input) {
    char buffer[64];
    strcpy(buffer, input); // No bounds checking
}

// 2. Use After Free
void useAfterFree() {
    int* ptr = new int(42);
    delete ptr;
    std::cout << *ptr << std::endl; // Using deleted pointer
}

// 3. Double Delete
void doubleDelete() {
    int* ptr = new int(42);
    delete ptr;
    delete ptr; // Deleting same pointer twice
}

// 4. Memory Leak
void memoryLeak() {
    int* ptr = new int[100];
    // Forgot to delete[]
}

// 5. SQL Injection
std::string sqlInjection(const std::string& userId) {
    std::string query = "SELECT * FROM users WHERE id = '" + userId + "'";
    return query;
}

// 6. Command Injection
void commandInjection(const std::string& filename) {
    std::string command = "cat " + filename;
    system(command.c_str());
}

// 7. Hardcoded Credentials - API Key
const char* API_KEY = "sk_live_cpp1234567890abcdef";

// 8. Hardcoded Credentials - Password
void connectToDatabase() {
    std::string password = "CppSecret456!";
    // connect(password);
}

// 9. Path Traversal
std::string pathTraversal(const std::string& filename) {
    std::string path = "/var/data/" + filename;
    std::ifstream file(path);
    std::string content;
    std::getline(file, content);
    return content;
}

// 10. Integer Overflow
int integerOverflow(int a, int b) {
    return a + b; // No overflow check
}

// 11. Null Pointer Dereference
void nullPointerDeref(int* ptr) {
    *ptr = 42; // No null check
}

// 12. Race Condition
class Counter {
    int count = 0;
public:
    void increment() {
        // No mutex protection
        count++;
    }
};

// 13. Uninitialized Variable
void uninitializedVar() {
    int x;
    std::cout << x << std::endl; // Using uninitialized variable
}

// 14. Out of Bounds Access
void outOfBounds() {
    std::vector<int> vec = {1, 2, 3};
    std::cout << vec[10] << std::endl; // Out of bounds
}

// 15. Weak Random Number Generation
int weakRandom() {
    return rand(); // Predictable PRNG
}

// 16. Unsafe Type Cast
void unsafeCast(void* ptr) {
    int* iptr = (int*)ptr; // C-style cast without type safety
    *iptr = 42;
}

// 17. Stack Buffer Overflow
void stackBufferOverflow(const char* input) {
    char buffer[10];
    sprintf(buffer, "%s", input); // No bounds check
}

// 18. Format String Vulnerability
void formatStringVuln(const char* userInput) {
    printf(userInput); // User input in format string
}

// 19. TOCTOU Race Condition
void toctou(const std::string& filename) {
    if (std::ifstream(filename).good()) {
        // File can be modified/deleted here
        std::ifstream file(filename);
    }
}

// 20. Unsafe String Operations
void unsafeStrcat(char* dest, const char* src) {
    strcat(dest, src); // No bounds checking
}

// 21. Template Injection (in web context)
std::string renderTemplate(const std::string& userInput) {
    return "<html><body><h1>Welcome " + userInput + "</h1></body></html>";
}

// 22. SSRF Vulnerability (conceptual)
std::string fetchUrl(const std::string& url) {
    // Using libcurl or similar without validation
    return "Content from: " + url;
}

// 23. Unsafe Iterator Usage
void unsafeIterator() {
    std::vector<int> vec = {1, 2, 3};
    auto it = vec.begin();
    vec.push_back(4); // May invalidate iterator
    std::cout << *it << std::endl; // Undefined behavior
}

// 24. Exception Safety Violation
void exceptionUnsafe() {
    int* ptr = new int(42);
    // Code that might throw exception
    delete ptr; // May not be reached if exception thrown
}

// 25. Virtual Function in Constructor
class Base {
public:
    Base() {
        init(); // Calling virtual function in constructor
    }
    virtual void init() {}
};
