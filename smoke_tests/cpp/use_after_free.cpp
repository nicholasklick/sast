// Use-After-Free vulnerabilities in C++
#include <iostream>
#include <memory>
#include <vector>
#include <string>

// Test 1: Basic use after delete
void basic_uaf() {
    int* ptr = new int(42);
    delete ptr;
    // VULNERABLE: Use after free
    std::cout << *ptr << std::endl;
}

// Test 2: Use after delete in class
class Resource {
public:
    int value;
    void print() { std::cout << value << std::endl; }
};

void class_uaf() {
    Resource* r = new Resource();
    r->value = 100;
    delete r;
    // VULNERABLE: Calling method on deleted object
    r->print();
}

// Test 3: Double delete
void double_delete() {
    int* p = new int(5);
    delete p;
    // VULNERABLE: Double delete
    delete p;
}

// Test 4: Use after delete[] for arrays
void array_uaf() {
    int* arr = new int[10];
    delete[] arr;
    // VULNERABLE: Use after delete
    arr[0] = 1;
}

// Test 5: Dangling reference from deleted object
class Container {
public:
    std::string& get_data() { return data; }
private:
    std::string data = "sensitive";
};

std::string& get_dangling_ref() {
    Container* c = new Container();
    std::string& ref = c->get_data();
    delete c;
    // VULNERABLE: Returning dangling reference
    return ref;
}

// Test 6: Use after move
void use_after_move() {
    std::unique_ptr<int> p1 = std::make_unique<int>(42);
    std::unique_ptr<int> p2 = std::move(p1);
    // VULNERABLE: p1 is now null
    std::cout << *p1 << std::endl;
}

// Test 7: Iterator invalidation
void iterator_invalidation() {
    std::vector<int> vec = {1, 2, 3, 4, 5};
    auto it = vec.begin();
    vec.push_back(6);  // May invalidate iterators
    // VULNERABLE: Iterator may be invalid
    std::cout << *it << std::endl;
}

// Test 8: Shared pointer use after reset
void shared_ptr_uaf() {
    auto sp = std::make_shared<int>(42);
    int* raw = sp.get();
    sp.reset();
    // VULNERABLE: raw pointer is now dangling
    std::cout << *raw << std::endl;
}
