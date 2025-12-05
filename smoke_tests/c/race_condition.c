// Race Condition vulnerabilities in C
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

// Shared state without synchronization
static int counter = 0;
static char *shared_buffer = NULL;

// Test 1: Data race on shared counter
void* increment_counter(void *arg) {
    for (int i = 0; i < 1000; i++) {
        // VULNERABLE: Race condition on counter
        counter++;
    }
    return NULL;
}

void test_counter_race() {
    pthread_t t1, t2;
    pthread_create(&t1, NULL, increment_counter, NULL);
    pthread_create(&t2, NULL, increment_counter, NULL);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
}

// Test 2: Check-then-use race (TOCTOU)
int safe_open_file(const char *path) {
    struct stat st;
    // VULNERABLE: TOCTOU - file may change between stat and open
    if (stat(path, &st) == 0) {
        if (S_ISREG(st.st_mode)) {
            return open(path, O_RDONLY);
        }
    }
    return -1;
}

// Test 3: Race in lazy initialization
char* get_buffer() {
    // VULNERABLE: Race condition in lazy init
    if (shared_buffer == NULL) {
        shared_buffer = malloc(1024);
    }
    return shared_buffer;
}

// Test 4: Signal handler race
static volatile int signal_flag = 0;

void signal_handler(int sig) {
    // VULNERABLE: Non-atomic access in signal handler
    signal_flag = 1;
}

void wait_for_signal() {
    while (!signal_flag) {
        // VULNERABLE: signal_flag access not synchronized
        sleep(1);
    }
}

// Test 5: File-based TOCTOU
void process_if_writable(const char *filename) {
    // VULNERABLE: TOCTOU race condition
    if (access(filename, W_OK) == 0) {
        // File permissions may have changed
        FILE *f = fopen(filename, "w");
        if (f) {
            fprintf(f, "data\n");
            fclose(f);
        }
    }
}

// Test 6: Race in temp file creation
void create_temp_file() {
    char template[] = "/tmp/myapp_XXXXXX";
    // VULNERABLE: Race between tmpnam and open
    char *name = tmpnam(template);
    FILE *f = fopen(name, "w");
    if (f) {
        fprintf(f, "temporary data\n");
        fclose(f);
    }
}
