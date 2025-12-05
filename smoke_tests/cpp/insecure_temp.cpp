// Insecure Temporary File vulnerabilities in C++
#include <iostream>
#include <fstream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

// Test 1: Predictable temp file name
void predictable_temp() {
    // VULNERABLE: Predictable filename
    std::string filename = "/tmp/myapp_temp.txt";
    std::ofstream out(filename);
    out << "sensitive data" << std::endl;
}

// Test 2: tmpnam - deprecated and race-prone
void use_tmpnam() {
    char filename[L_tmpnam];
    // VULNERABLE: Race condition between name creation and file open
    tmpnam(filename);
    FILE* f = fopen(filename, "w");
    if (f) {
        fprintf(f, "data\n");
        fclose(f);
    }
}

// Test 3: tempnam with predictable directory
void use_tempnam() {
    // VULNERABLE: Still has race condition
    char* filename = tempnam("/tmp", "myapp");
    if (filename) {
        FILE* f = fopen(filename, "w");
        if (f) {
            fprintf(f, "data\n");
            fclose(f);
        }
        free(filename);
    }
}

// Test 4: Creating temp in world-writable directory
void world_writable_temp() {
    // VULNERABLE: /tmp is world-writable
    std::ofstream out("/tmp/app_" + std::to_string(getpid()) + ".tmp");
    out << "sensitive" << std::endl;
}

// Test 5: mktemp - race condition
void use_mktemp() {
    char template_name[] = "/tmp/myapp.XXXXXX";
    // VULNERABLE: Creates name but doesn't open file atomically
    char* filename = mktemp(template_name);
    int fd = open(filename, O_CREAT | O_WRONLY, 0600);
    if (fd >= 0) {
        write(fd, "data", 4);
        close(fd);
    }
}

// Test 6: Insecure permissions on temp file
void insecure_permissions() {
    char template_name[] = "/tmp/myapp.XXXXXX";
    int fd = mkstemp(template_name);
    if (fd >= 0) {
        // VULNERABLE: Making file world-readable
        chmod(template_name, 0644);
        write(fd, "sensitive", 9);
        close(fd);
    }
}

// Test 7: Not unlinking temp file
void temp_not_cleaned() {
    char template_name[] = "/tmp/myapp.XXXXXX";
    int fd = mkstemp(template_name);
    if (fd >= 0) {
        write(fd, "data", 4);
        close(fd);
        // VULNERABLE: Temp file not deleted, may contain sensitive data
    }
}

// Test 8: Symlink following
void symlink_vulnerable() {
    const char* filename = "/tmp/myapp.log";
    // VULNERABLE: If attacker creates symlink, will overwrite target
    FILE* f = fopen(filename, "w");
    if (f) {
        fprintf(f, "log data\n");
        fclose(f);
    }
}

// Test 9: Time-based temp filename
void time_based_temp() {
    // VULNERABLE: Predictable based on time
    time_t now = time(nullptr);
    std::string filename = "/tmp/backup_" + std::to_string(now) + ".tmp";
    std::ofstream out(filename);
    out << "backup data" << std::endl;
}

// Test 10: PID-based temp filename
void pid_based_temp() {
    // VULNERABLE: PID is predictable/observable
    pid_t pid = getpid();
    std::string filename = "/tmp/proc_" + std::to_string(pid) + ".tmp";
    std::ofstream out(filename);
    out << "process data" << std::endl;
}

// Test 11: Counter-based temp filename
static int counter = 0;
void counter_based_temp() {
    // VULNERABLE: Counter is predictable
    std::string filename = "/tmp/file_" + std::to_string(counter++) + ".tmp";
    std::ofstream out(filename);
    out << "data" << std::endl;
}
