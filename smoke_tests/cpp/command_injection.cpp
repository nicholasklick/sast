// Command Injection vulnerabilities in C++
#include <iostream>
#include <cstdlib>
#include <string>

void system_command(const std::string& filename) {
    // VULNERABLE: Command injection via system()
    std::string cmd = "cat " + filename;
    system(cmd.c_str());
}

void popen_command(const std::string& user_input) {
    // VULNERABLE: Command injection via popen()
    std::string command = "grep " + user_input + " /var/log/app.log";
    FILE* pipe = popen(command.c_str(), "r");
    pclose(pipe);
}

void exec_command(const char* arg) {
    // VULNERABLE: Shell execution with user input
    std::string cmd = std::string("sh -c '") + arg + "'";
    system(cmd.c_str());
}

class CommandRunner {
public:
    int run(const std::string& host) {
        // VULNERABLE: User input in shell command
        std::string cmd = "ping -c 1 " + host;
        return system(cmd.c_str());
    }
};
