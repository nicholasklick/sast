// Insecure Temporary File vulnerabilities in C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

// Test 1: Using tmpnam (deprecated and insecure)
void use_tmpnam() {
    char filename[L_tmpnam];
    // VULNERABLE: tmpnam has race condition
    tmpnam(filename);
    FILE *f = fopen(filename, "w");
    if (f) {
        fprintf(f, "sensitive data\n");
        fclose(f);
    }
}

// Test 2: Using tempnam (also insecure)
void use_tempnam() {
    // VULNERABLE: tempnam has race condition
    char *filename = tempnam("/tmp", "app_");
    FILE *f = fopen(filename, "w");
    if (f) {
        fprintf(f, "secret\n");
        fclose(f);
    }
    free(filename);
}

// Test 3: Predictable temp file name
void predictable_temp() {
    char filename[256];
    // VULNERABLE: Predictable filename
    sprintf(filename, "/tmp/myapp_%d.tmp", getpid());
    FILE *f = fopen(filename, "w");
    if (f) {
        fprintf(f, "data\n");
        fclose(f);
    }
}

// Test 4: Temp file in world-writable directory without proper permissions
void insecure_permissions() {
    // VULNERABLE: Creates file with default (potentially world-readable) permissions
    FILE *f = fopen("/tmp/myapp_config.tmp", "w");
    if (f) {
        fprintf(f, "password=secret123\n");
        fclose(f);
    }
}

// Test 5: Not using O_EXCL
void missing_o_excl() {
    char template[] = "/tmp/myapp_XXXXXX";
    // VULNERABLE: Should use mkstemp or O_EXCL
    int fd = open(template, O_CREAT | O_WRONLY, 0600);
    if (fd >= 0) {
        write(fd, "data", 4);
        close(fd);
    }
}

// Test 6: Symlink attack vulnerable
void check_then_write(const char *path) {
    struct stat st;
    // VULNERABLE: TOCTOU - symlink can be created between stat and open
    if (stat(path, &st) == -1) {
        // File doesn't exist, create it
        FILE *f = fopen(path, "w");
        if (f) {
            fprintf(f, "new file\n");
            fclose(f);
        }
    }
}

// Test 7: Using mktemp (deprecated)
void use_mktemp() {
    char template[] = "/tmp/myapp_XXXXXX";
    // VULNERABLE: mktemp has race condition, use mkstemp instead
    mktemp(template);
    FILE *f = fopen(template, "w");
    if (f) {
        fprintf(f, "data\n");
        fclose(f);
    }
}

// Test 8: Temp file not deleted
void temp_file_leak() {
    char template[] = "/tmp/myapp_XXXXXX";
    int fd = mkstemp(template);
    if (fd >= 0) {
        write(fd, "sensitive", 9);
        close(fd);
        // VULNERABLE: Temp file not unlinked, remains on disk
    }
}
