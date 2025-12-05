// Exception Safety vulnerabilities in C++
#include <iostream>
#include <vector>
#include <memory>
#include <stdexcept>

// Test 1: Exception in constructor - resource leak
class LeakyResource {
    int* data1;
    int* data2;
public:
    LeakyResource() {
        data1 = new int(1);
        // VULNERABLE: If this throws, data1 is leaked
        data2 = new int(2);
        if (true) throw std::runtime_error("error");
    }
    ~LeakyResource() {
        delete data1;
        delete data2;
    }
};

// Test 2: Exception in destructor
class ThrowingDestructor {
public:
    ~ThrowingDestructor() {
        // VULNERABLE: Throwing in destructor during stack unwinding
        throw std::runtime_error("destructor error");
    }
};

// Test 3: Unsafe swap - not noexcept
class UnsafeSwap {
    std::vector<int> data;
public:
    void swap(UnsafeSwap& other) {
        // VULNERABLE: This could throw
        std::vector<int> temp = data;
        data = other.data;
        other.data = temp;
    }
};

// Test 4: Catch by value - slicing
class BaseException : public std::exception {
public:
    virtual const char* what() const noexcept { return "base"; }
};

class DerivedException : public BaseException {
public:
    const char* what() const noexcept override { return "derived"; }
};

void catch_by_value() {
    try {
        throw DerivedException();
    } catch (BaseException e) {  // VULNERABLE: Slicing - catches by value
        std::cout << e.what() << std::endl;  // Prints "base"
    }
}

// Test 5: Missing exception specification
void might_throw() {
    // VULNERABLE: No noexcept specification on function that shouldn't throw
    std::vector<int> v;
    v.push_back(1);
}

// Test 6: Ignoring exception
void ignore_exception() {
    try {
        throw std::runtime_error("critical error");
    } catch (...) {
        // VULNERABLE: Swallowing exception silently
    }
}

// Test 7: Partial construction in array
class ComplexObject {
public:
    ComplexObject() {
        static int count = 0;
        if (++count == 5) throw std::runtime_error("error on 5th");
    }
};

void array_construction() {
    // VULNERABLE: If construction throws, previous objects need cleanup
    ComplexObject* arr = new ComplexObject[10];
    delete[] arr;
}

// Test 8: Exception safety in assignment operator
class UnsafeAssign {
    int* data;
public:
    UnsafeAssign(int val) : data(new int(val)) {}
    ~UnsafeAssign() { delete data; }

    UnsafeAssign& operator=(const UnsafeAssign& other) {
        // VULNERABLE: Not exception safe
        delete data;
        data = new int(*other.data);  // If this throws, object is invalid
        return *this;
    }
};
