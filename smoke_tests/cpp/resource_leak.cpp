// Resource Leak vulnerabilities in C++
#include <iostream>
#include <fstream>
#include <memory>
#include <mutex>

// Test 1: Raw pointer memory leak
void memory_leak() {
    int* ptr = new int(42);
    // VULNERABLE: ptr is never deleted
}

// Test 2: Array memory leak
void array_leak() {
    int* arr = new int[100];
    // VULNERABLE: arr is never deleted
}

// Test 3: Memory leak on exception path
void exception_leak() {
    int* ptr = new int(42);
    throw std::runtime_error("error");
    // VULNERABLE: ptr leaked if exception thrown
    delete ptr;
}

// Test 4: File handle leak
void file_leak(const std::string& filename) {
    std::ifstream* file = new std::ifstream(filename);
    if (!file->is_open()) {
        return;  // VULNERABLE: file object leaked
    }
    // Process file...
    // VULNERABLE: file never deleted
}

// Test 5: Conditional memory leak
void conditional_leak(bool condition) {
    int* ptr = new int(42);
    if (condition) {
        return;  // VULNERABLE: ptr leaked on this path
    }
    delete ptr;
}

// Test 6: Memory leak in loop
void loop_leak(int count) {
    for (int i = 0; i < count; i++) {
        std::string* s = new std::string("item");
        std::cout << *s << std::endl;
        // VULNERABLE: s leaked each iteration
    }
}

// Test 7: Mutex not unlocked (using raw mutex)
std::mutex mtx;
void mutex_leak() {
    mtx.lock();
    // VULNERABLE: mutex not unlocked if exception thrown
    throw std::runtime_error("error");
    mtx.unlock();
}

// Test 8: Missing virtual destructor
class Base {
public:
    ~Base() {}  // VULNERABLE: Should be virtual
};

class Derived : public Base {
    int* data;
public:
    Derived() : data(new int(42)) {}
    ~Derived() { delete data; }
};

void virtual_destructor_leak() {
    Base* b = new Derived();
    delete b;  // VULNERABLE: Derived destructor not called
}

// Test 9: Resource leak in container
void container_leak() {
    std::vector<int*> ptrs;
    ptrs.push_back(new int(1));
    ptrs.push_back(new int(2));
    // VULNERABLE: Raw pointers in container not deleted
}

// Test 10: Socket/handle leak (simulated)
class Connection {
public:
    void* handle;
    Connection() : handle(malloc(100)) {}
    // VULNERABLE: No destructor to free handle
};
