// Move Semantics vulnerabilities in C++11+
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <utility>

// Test 1: Use after move
void use_after_move() {
    std::string data = "sensitive data";
    std::string other = std::move(data);
    // VULNERABLE: Using moved-from object
    std::cout << data << std::endl;
}

// Test 2: Double move
void double_move() {
    std::unique_ptr<int> ptr = std::make_unique<int>(42);
    std::unique_ptr<int> first = std::move(ptr);
    // VULNERABLE: Moving already moved object
    std::unique_ptr<int> second = std::move(ptr);
}

// Test 3: Use after move in loop
void move_in_loop() {
    std::string value = "data";
    for (int i = 0; i < 3; ++i) {
        // VULNERABLE: Moving same object multiple times
        process(std::move(value));
    }
}

void process(std::string&& s) {
    std::cout << s << std::endl;
}

// Test 4: Conditional use after move
void conditional_move(bool condition) {
    std::vector<int> vec = {1, 2, 3};
    if (condition) {
        auto other = std::move(vec);
    }
    // VULNERABLE: May be moved-from
    vec.push_back(4);
}

// Test 5: Move in exception-unsafe code
void exception_unsafe_move() {
    std::string data = "important";
    try {
        std::string moved = std::move(data);
        throw std::runtime_error("error");
    } catch (...) {
        // VULNERABLE: data is moved-from, but code assumes it's valid
        std::cout << data << std::endl;
    }
}

// Test 6: Move constructor with partial initialization
class PartialMove {
public:
    std::unique_ptr<int> ptr;
    std::string name;

    PartialMove(PartialMove&& other)
        : ptr(std::move(other.ptr)) {
        // VULNERABLE: If this throws, other.ptr is already moved
        name = std::move(other.name);
    }
};

// Test 7: Self-move assignment
void self_move() {
    std::string s = "data";
    // VULNERABLE: Self-move is undefined behavior
    s = std::move(s);
}

// Test 8: Move from const object (actually copies)
void move_from_const() {
    const std::string data = "constant";
    // VULNERABLE: Doesn't actually move, may mislead developers
    std::string other = std::move(data);
}

// Test 9: Return moved local by reference
std::string&& return_moved_local() {
    std::string local = "local";
    // VULNERABLE: Returning reference to moved local
    return std::move(local);
}

// Test 10: Move in destructor
class UnsafeDestructor {
    std::unique_ptr<int> resource;
public:
    ~UnsafeDestructor() {
        // VULNERABLE: Moving in destructor is suspicious
        auto temp = std::move(resource);
    }
};

// Test 11: Accessing moved object members
struct Container {
    std::vector<int> data;
    size_t size() const { return data.size(); }
};

void access_moved_member() {
    Container c;
    c.data = {1, 2, 3};
    auto vec = std::move(c.data);
    // VULNERABLE: Accessing moved member
    std::cout << c.size() << std::endl;
}
