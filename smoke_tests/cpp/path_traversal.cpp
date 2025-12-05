// Path Traversal vulnerabilities in C++
#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>

// Test 1: Direct file access with user input
void read_user_file(const std::string& filename) {
    // VULNERABLE: No path validation
    std::ifstream file("/var/www/data/" + filename);
    if (file.is_open()) {
        std::string content((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());
        std::cout << content << std::endl;
    }
}

// Test 2: Path traversal in file download
void download_file(const std::string& user_path) {
    std::string base_dir = "/uploads/";
    // VULNERABLE: user_path can contain ../
    std::string full_path = base_dir + user_path;
    std::ifstream file(full_path, std::ios::binary);
    // Process file...
}

// Test 3: Insufficient validation
void read_with_check(const std::string& filename) {
    // VULNERABLE: Only checks prefix, not normalized path
    if (filename.find("..") == std::string::npos) {
        std::ifstream file("/data/" + filename);
        // Still vulnerable to encoded traversal
    }
}

// Test 4: Using filesystem without canonicalization
void access_file_fs(const std::string& user_input) {
    std::filesystem::path base = "/safe/directory";
    std::filesystem::path user_path = user_input;
    // VULNERABLE: Not checking if result is within base
    std::filesystem::path full = base / user_path;
    std::ifstream file(full);
}

// Test 5: Path traversal in file creation
void create_file(const std::string& name, const std::string& content) {
    // VULNERABLE: name could be "../../../etc/cron.d/malicious"
    std::ofstream file("/tmp/uploads/" + name);
    file << content;
}

// Test 6: Symlink following
void read_file_follow_symlink(const std::string& path) {
    // VULNERABLE: May follow symlinks outside allowed directory
    std::ifstream file(path);
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            std::cout << line << std::endl;
        }
    }
}

// Test 7: Archive extraction path traversal (Zip Slip)
void extract_entry(const std::string& entry_name, const std::string& content) {
    std::string extract_dir = "/tmp/extracted/";
    // VULNERABLE: entry_name from archive may contain ../
    std::string full_path = extract_dir + entry_name;
    std::ofstream out(full_path);
    out << content;
}

// Test 8: URL path parameter
void serve_static(const std::string& url_path) {
    // VULNERABLE: URL-decoded path may contain traversal
    std::string file_path = "/var/www/static" + url_path;
    std::ifstream file(file_path);
}
