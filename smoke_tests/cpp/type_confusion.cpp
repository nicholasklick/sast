// Type Confusion vulnerabilities in C++
#include <iostream>
#include <variant>
#include <any>
#include <typeinfo>

// Test 1: reinterpret_cast misuse
void reinterpret_cast_abuse() {
    float f = 3.14f;
    // VULNERABLE: Type punning through reinterpret_cast
    int* ip = reinterpret_cast<int*>(&f);
    std::cout << *ip << std::endl;
}

// Test 2: static_cast to wrong derived type
class Animal { public: virtual ~Animal() {} };
class Dog : public Animal { public: void bark() {} };
class Cat : public Animal { public: void meow() {} };

void wrong_static_cast(Animal* a) {
    // VULNERABLE: static_cast doesn't check at runtime
    Dog* d = static_cast<Dog*>(a);  // May be a Cat
    d->bark();  // Undefined behavior if a is Cat
}

// Test 3: Union type punning
union TypePunner {
    float f;
    int i;
    char bytes[4];
};

void union_pun() {
    TypePunner p;
    p.f = 1.0f;
    // VULNERABLE: Reading inactive union member
    std::cout << p.i << std::endl;
}

// Test 4: Void pointer cast to wrong type
void* create_object(int type) {
    if (type == 0) return new int(42);
    return new std::string("hello");
}

void use_wrong_type() {
    void* obj = create_object(1);  // Creates string
    // VULNERABLE: Casting to wrong type
    int* ip = static_cast<int*>(obj);
    std::cout << *ip << std::endl;
}

// Test 5: std::variant wrong type access
void variant_wrong_access() {
    std::variant<int, std::string> v = "hello";
    // VULNERABLE: Accessing wrong alternative
    try {
        int i = std::get<int>(v);  // Throws, but what if uncaught?
    } catch (...) {}

    // VULNERABLE: get_if returns nullptr but not checked
    int* pi = std::get_if<int>(&v);
    std::cout << *pi << std::endl;  // Null dereference
}

// Test 6: std::any wrong type cast
void any_wrong_cast() {
    std::any a = std::string("hello");
    // VULNERABLE: bad_any_cast exception
    int i = std::any_cast<int>(a);
}

// Test 7: C-style cast bypassing type safety
class Base { public: int x; virtual ~Base() {} };
class Derived1 : public Base { public: int y; };
class Derived2 : public Base { public: double z; };

void c_style_cast_danger(Base* b) {
    // VULNERABLE: C-style cast doesn't check type
    Derived1* d = (Derived1*)b;  // May be Derived2
    d->y = 10;  // Corrupts Derived2::z
}

// Test 8: Aliasing through pointer cast
void aliasing_violation() {
    long long ll = 0x0102030405060708LL;
    // VULNERABLE: Strict aliasing violation
    int* ip = (int*)&ll;
    *ip = 0;  // UB: violates strict aliasing
}
