// Smart Pointer Misuse vulnerabilities in C++
#include <iostream>
#include <memory>
#include <vector>

// Test 1: Circular reference with shared_ptr
class Node {
public:
    std::shared_ptr<Node> next;
    std::shared_ptr<Node> prev;  // VULNERABLE: Should be weak_ptr

    ~Node() {
        std::cout << "Node destroyed" << std::endl;
    }
};

void circular_reference() {
    auto node1 = std::make_shared<Node>();
    auto node2 = std::make_shared<Node>();
    // VULNERABLE: Circular reference causes memory leak
    node1->next = node2;
    node2->prev = node1;
}

// Test 2: Creating shared_ptr from raw pointer multiple times
void double_manage() {
    int* raw = new int(42);
    std::shared_ptr<int> sp1(raw);
    // VULNERABLE: Double delete when both go out of scope
    std::shared_ptr<int> sp2(raw);
}

// Test 3: Using get() and storing raw pointer
void escape_raw_pointer() {
    std::unique_ptr<int> up = std::make_unique<int>(42);
    int* raw = up.get();
    up.reset();
    // VULNERABLE: raw is now dangling
    std::cout << *raw << std::endl;
}

// Test 4: Returning unique_ptr by reference
std::unique_ptr<int>& get_unique() {
    static std::unique_ptr<int> up = std::make_unique<int>(42);
    // VULNERABLE: Allows external code to move/reset
    return up;
}

// Test 5: shared_ptr aliasing with different deleters
void aliasing_different_deleters() {
    auto deleter1 = [](int* p) { delete p; };
    auto deleter2 = [](int* p) { delete[] p; };

    int* raw = new int(42);
    std::shared_ptr<int> sp1(raw, deleter1);
    // VULNERABLE: Same raw pointer with different deletion
    // std::shared_ptr<int> sp2(raw, deleter2);  // Would double-delete
}

// Test 6: shared_ptr from this without enable_shared_from_this
class Unsafe {
public:
    std::shared_ptr<Unsafe> get_shared() {
        // VULNERABLE: Creates independent ownership
        return std::shared_ptr<Unsafe>(this);
    }
};

// Test 7: Dereferencing expired weak_ptr
void expired_weak() {
    std::weak_ptr<int> wp;
    {
        auto sp = std::make_shared<int>(42);
        wp = sp;
    }
    // VULNERABLE: sp is gone, lock() returns empty shared_ptr
    if (auto sp = wp.lock()) {
        std::cout << *sp << std::endl;
    }
    // VULNERABLE: Unchecked dereference
    // std::cout << *wp.lock() << std::endl;  // Undefined if expired
}

// Test 8: unique_ptr array with wrong deleter
void wrong_array_deleter() {
    // VULNERABLE: Using unique_ptr<T> for arrays
    std::unique_ptr<int> up(new int[10]);  // Should be unique_ptr<int[]>
}

// Test 9: Moving shared_ptr while others exist
void move_shared_while_aliased() {
    auto sp1 = std::make_shared<int>(42);
    int* raw = sp1.get();
    auto sp2 = sp1;  // sp2 shares ownership
    sp1 = std::move(sp2);  // OK, but sp2 is now empty
    // VULNERABLE: Code might assume sp2 is still valid
}

// Test 10: shared_ptr to stack object
void shared_from_stack() {
    int stack_var = 42;
    // VULNERABLE: Will try to delete stack memory
    // std::shared_ptr<int> sp(&stack_var);  // Undefined behavior
}

// Test 11: Custom deleter that throws
void throwing_deleter() {
    auto deleter = [](int* p) {
        delete p;
        throw std::runtime_error("Error in deleter");  // VULNERABLE: UB
    };
    std::unique_ptr<int, decltype(deleter)> up(new int(42), deleter);
}
