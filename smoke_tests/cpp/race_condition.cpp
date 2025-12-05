// Race Condition vulnerabilities in C++
#include <iostream>
#include <thread>
#include <mutex>
#include <atomic>
#include <vector>

// Shared state without synchronization
static int counter = 0;
static std::string shared_data;

// Test 1: Data race on primitive
void increment_unsafe() {
    for (int i = 0; i < 1000; i++) {
        // VULNERABLE: Race condition
        counter++;
    }
}

void test_data_race() {
    std::thread t1(increment_unsafe);
    std::thread t2(increment_unsafe);
    t1.join();
    t2.join();
}

// Test 2: Race on std::string
void modify_string(int id) {
    for (int i = 0; i < 100; i++) {
        // VULNERABLE: std::string is not thread-safe
        shared_data += std::to_string(id);
    }
}

// Test 3: Check-then-act race
class LazyInit {
    bool initialized = false;
    int* data = nullptr;
public:
    int* get() {
        // VULNERABLE: Double-checked locking broken without memory barriers
        if (!initialized) {
            data = new int(42);
            initialized = true;
        }
        return data;
    }
};

// Test 4: Vector modification race
static std::vector<int> shared_vec;

void add_to_vector(int value) {
    // VULNERABLE: vector not thread-safe
    shared_vec.push_back(value);
}

// Test 5: Incorrect mutex usage
std::mutex mtx;
int protected_counter = 0;

void increment_wrong_mutex() {
    mtx.lock();
    protected_counter++;
    // VULNERABLE: Returning without unlocking if exception thrown
    if (protected_counter > 100) {
        throw std::runtime_error("overflow");
    }
    mtx.unlock();
}

// Test 6: Lock order deadlock potential
std::mutex mutex1, mutex2;

void thread_func1() {
    std::lock_guard<std::mutex> lock1(mutex1);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    std::lock_guard<std::mutex> lock2(mutex2);  // VULNERABLE: Lock order
}

void thread_func2() {
    std::lock_guard<std::mutex> lock2(mutex2);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    std::lock_guard<std::mutex> lock1(mutex1);  // VULNERABLE: Opposite lock order
}

// Test 7: Race in singleton pattern
class Singleton {
    static Singleton* instance;
public:
    static Singleton* getInstance() {
        // VULNERABLE: Race in lazy initialization
        if (instance == nullptr) {
            instance = new Singleton();
        }
        return instance;
    }
};
Singleton* Singleton::instance = nullptr;

// Test 8: Atomic with wrong memory order
std::atomic<int> atomic_counter{0};

void relaxed_increment() {
    // VULNERABLE: memory_order_relaxed may not be sufficient
    atomic_counter.fetch_add(1, std::memory_order_relaxed);
}
