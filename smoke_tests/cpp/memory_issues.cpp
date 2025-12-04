// Memory Safety vulnerabilities in C++
#include <iostream>
#include <memory>

class Resource {
public:
    int* data;
    Resource() : data(new int[100]) {}
    ~Resource() { delete[] data; }
};

int* use_after_free() {
    // VULNERABLE: Use after free
    int* ptr = new int(42);
    delete ptr;
    return ptr;
}

void double_delete() {
    // VULNERABLE: Double delete
    int* p = new int(10);
    delete p;
    delete p;
}

int* dangling_reference() {
    // VULNERABLE: Returning pointer to local
    int local = 42;
    return &local;
}

void memory_leak() {
    // VULNERABLE: Memory leak
    int* data = new int[1000];
    // No delete[]
}

class BadCopy {
    int* ptr;
public:
    BadCopy() : ptr(new int(0)) {}
    ~BadCopy() { delete ptr; }
    // VULNERABLE: Missing copy constructor/assignment causes double-free
};

void null_deref(int* ptr) {
    // VULNERABLE: No null check
    std::cout << *ptr << std::endl;
}
