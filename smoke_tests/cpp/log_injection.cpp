// Log Injection vulnerabilities in C++
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <ctime>
#include <syslog.h>

// Test 1: Direct user input in log
void log_user_action(const std::string& username) {
    // VULNERABLE: username can contain newlines to forge log entries
    std::cout << "[INFO] User " << username << " logged in" << std::endl;
}

// Test 2: Log to file with user input
void write_log(const std::string& message) {
    std::ofstream log("/var/log/app.log", std::ios::app);
    // VULNERABLE: message not sanitized
    log << "[" << time(nullptr) << "] " << message << std::endl;
}

// Test 3: syslog injection
void syslog_message(const std::string& user_input) {
    // VULNERABLE: user_input can contain format specifiers
    openlog("myapp", LOG_PID, LOG_USER);
    syslog(LOG_INFO, "%s", user_input.c_str());
    closelog();
}

// Test 4: Format string in cerr
void log_error(const std::string& error_details) {
    // VULNERABLE: error_details can contain newlines
    std::cerr << "Error: " << error_details << std::endl;
}

// Test 5: HTTP response splitting through logs
void log_request(const std::string& path, const std::string& user_agent) {
    // VULNERABLE: user_agent can contain CRLF
    std::cout << "Request: " << path << " - Agent: " << user_agent << std::endl;
}

// Test 6: Log injection in structured format
void log_json(const std::string& event, const std::string& data) {
    // VULNERABLE: data can break JSON structure
    std::cout << "{\"event\": \"" << event << "\", \"data\": \"" << data << "\"}" << std::endl;
}

// Test 7: Carriage return injection
void log_transaction(const std::string& account_id, double amount) {
    // VULNERABLE: account_id may contain \r\n
    std::stringstream ss;
    ss << "Transaction: Account=" << account_id << " Amount=" << amount;
    std::cout << ss.str() << std::endl;
}

// Test 8: Exception message logging
void log_exception(const std::exception& e) {
    // VULNERABLE: Exception message from untrusted source
    std::cerr << "Exception caught: " << e.what() << std::endl;
}

// Test 9: Multi-line log entry manipulation
void log_audit(const std::string& user, const std::string& action, const std::string& result) {
    std::ofstream audit("/var/log/audit.log", std::ios::app);
    // VULNERABLE: Any of these can contain newlines
    audit << "User: " << user << std::endl;
    audit << "Action: " << action << std::endl;
    audit << "Result: " << result << std::endl;
    audit << "---" << std::endl;
}
