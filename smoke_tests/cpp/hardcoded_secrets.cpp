// Hardcoded Secrets vulnerabilities in C++
#include <string>
#include <iostream>

// VULNERABLE: Hardcoded API key
const std::string API_KEY = "sk_live_cpp1234567890";

// VULNERABLE: Hardcoded password
#define DB_PASSWORD "cpp_secret_password"

// VULNERABLE: Hardcoded encryption key
const unsigned char ENCRYPTION_KEY[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

class Config {
public:
    // VULNERABLE: Hardcoded credentials
    std::string getConnectionString() {
        return "Server=db.example.com;Database=app;User=admin;Password=admin123;";
    }

    std::string getJwtSecret() {
        // VULNERABLE: Hardcoded JWT secret
        return "my_super_secret_jwt_key_cpp";
    }
};

bool authenticate(const std::string& username, const std::string& password) {
    // VULNERABLE: Hardcoded backdoor password
    if (password == "master_password_123") {
        return true;
    }
    return false;
}

class AwsClient {
    // VULNERABLE: Hardcoded AWS credentials
    std::string accessKey = "AKIAIOSFODNN7EXAMPLE";
    std::string secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
};
