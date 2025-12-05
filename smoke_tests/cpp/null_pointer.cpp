// Null Pointer Dereference vulnerabilities in C++
#include <iostream>
#include <memory>
#include <string>
#include <optional>

// Test 1: Unchecked pointer dereference
void unchecked_deref(int* ptr) {
    // VULNERABLE: ptr may be null
    std::cout << *ptr << std::endl;
}

// Test 2: Unchecked new result (nothrow)
void nothrow_new() {
    int* ptr = new(std::nothrow) int[1000000000];
    // VULNERABLE: new(nothrow) returns nullptr on failure
    *ptr = 42;
}

// Test 3: Dereference before check
void deref_before_check(int* ptr) {
    int val = *ptr;  // VULNERABLE: Dereference before null check
    if (ptr != nullptr) {
        std::cout << val << std::endl;
    }
}

// Test 4: Null from dynamic_cast
class Base { virtual void foo() {} };
class Derived : public Base {};

void dynamic_cast_null(Base* b) {
    Derived* d = dynamic_cast<Derived*>(b);
    // VULNERABLE: dynamic_cast can return nullptr
    d->foo();
}

// Test 5: Unchecked unique_ptr get()
void unique_ptr_get() {
    std::unique_ptr<int> ptr;  // Default constructed, holds nullptr
    // VULNERABLE: ptr.get() returns nullptr
    std::cout << *ptr.get() << std::endl;
}

// Test 6: Unchecked shared_ptr
void shared_ptr_null() {
    std::shared_ptr<std::string> sp;
    // VULNERABLE: sp is null
    std::cout << sp->length() << std::endl;
}

// Test 7: Unchecked optional value
void optional_access() {
    std::optional<int> opt;
    // VULNERABLE: Accessing empty optional
    std::cout << *opt << std::endl;
}

// Test 8: Null this pointer (undefined behavior)
class Widget {
public:
    void process() {
        // VULNERABLE: If called on nullptr
        std::cout << data << std::endl;
    }
private:
    int data = 42;
};

void call_on_null() {
    Widget* w = nullptr;
    w->process();  // VULNERABLE: Null this pointer
}

// Test 9: Array access without null check
void array_access(int* arr, int size) {
    // VULNERABLE: arr may be null
    for (int i = 0; i < size; i++) {
        std::cout << arr[i] << std::endl;
    }
}
