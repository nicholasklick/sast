// Clean C++ code with no vulnerabilities
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <algorithm>
#include <fstream>

class SafeCppCode {
public:
    // Safe String Handling - Using std::string
    std::string safeStringCopy(const std::string& source) {
        return source;  // Copy constructor handles everything safely
    }

    // Safe Memory Management - Using smart pointers
    std::unique_ptr<int> safeDynamicAllocation(int value) {
        return std::make_unique<int>(value);
    }

    // Safe Array Access - Using vector with at()
    int safeVectorAccess(const std::vector<int>& vec, size_t index) {
        return vec.at(index);  // Throws exception if out of bounds
    }

    // Safe Integer Addition - Overflow check
    bool safeAdd(int a, int b, int& result) {
        if ((b > 0 && a > INT_MAX - b) || (b < 0 && a < INT_MIN - b)) {
            return false;  // Overflow detected
        }
        result = a + b;
        return true;
    }

    // Safe File Operations - RAII
    std::string safeFileRead(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open file");
        }

        std::string content((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
        return content;
    }

    // Safe Resource Management - RAII wrapper
    class SafeResource {
        FILE* file_;
    public:
        explicit SafeResource(const char* filename, const char* mode)
            : file_(fopen(filename, mode)) {
            if (!file_) {
                throw std::runtime_error("Failed to open file");
            }
        }

        ~SafeResource() {
            if (file_) {
                fclose(file_);
            }
        }

        // Delete copy operations
        SafeResource(const SafeResource&) = delete;
        SafeResource& operator=(const SafeResource&) = delete;

        FILE* get() { return file_; }
    };

    // Safe String Operations - Range-based
    std::vector<std::string> safeStringSplit(const std::string& str, char delimiter) {
        std::vector<std::string> result;
        std::stringstream ss(str);
        std::string item;

        while (std::getline(ss, item, delimiter)) {
            result.push_back(item);
        }

        return result;
    }

    // Safe Iterator Usage
    void safeIteratorUse(std::vector<int>& vec) {
        for (auto it = vec.begin(); it != vec.end(); ) {
            if (*it < 0) {
                it = vec.erase(it);  // Properly update iterator
            } else {
                ++it;
            }
        }
    }

    // Safe Exception Handling
    void safeExceptionHandling() {
        try {
            // Potentially throwing operation
            std::vector<int> vec(10);
            int value = vec.at(5);  // Safe access
        } catch (const std::exception& e) {
            std::cerr << "Exception: " << e.what() << std::endl;
        }
    }

    // Safe Thread-Safe Counter
    class SafeCounter {
        std::atomic<int> count_{0};
    public:
        void increment() {
            count_.fetch_add(1, std::memory_order_relaxed);
        }

        int get() const {
            return count_.load(std::memory_order_relaxed);
        }
    };
};
