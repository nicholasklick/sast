// Signal Handler vulnerabilities in C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

// Global state accessed by signal handler
static char *global_buffer = NULL;
static FILE *log_file = NULL;

// Test 1: Non-reentrant function in signal handler
void unsafe_handler_printf(int sig) {
    // VULNERABLE: printf is not async-signal-safe
    printf("Caught signal %d\n", sig);
}

// Test 2: malloc/free in signal handler
void unsafe_handler_malloc(int sig) {
    // VULNERABLE: malloc is not async-signal-safe
    char *buf = malloc(100);
    if (buf) {
        strcpy(buf, "signal received");
        free(buf);
    }
}

// Test 3: Calling exit() variants
void unsafe_handler_exit(int sig) {
    // VULNERABLE: exit() is not async-signal-safe
    exit(1);
}

// Test 4: Modifying shared data without atomics
static int counter = 0;
void unsafe_handler_shared(int sig) {
    // VULNERABLE: Non-atomic modification of shared data
    counter++;
}

// Test 5: Using stdio functions
void unsafe_handler_stdio(int sig) {
    // VULNERABLE: fopen, fprintf not async-signal-safe
    FILE *f = fopen("/tmp/signal.log", "a");
    if (f) {
        fprintf(f, "Signal %d\n", sig);
        fclose(f);
    }
}

// Test 6: Calling strlen/strcpy
void unsafe_handler_string(int sig) {
    // VULNERABLE: String functions may not be async-signal-safe
    if (global_buffer) {
        size_t len = strlen(global_buffer);
        strcpy(global_buffer, "cleared");
    }
}

// Test 7: Mutex operations in handler
#include <pthread.h>
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void unsafe_handler_mutex(int sig) {
    // VULNERABLE: pthread_mutex_lock can deadlock in handler
    pthread_mutex_lock(&lock);
    // Critical section
    pthread_mutex_unlock(&lock);
}

// Test 8: Longjmp from signal handler
#include <setjmp.h>
static jmp_buf jump_buffer;

void unsafe_handler_longjmp(int sig) {
    // VULNERABLE: longjmp from signal handler is dangerous
    longjmp(jump_buffer, 1);
}

// Test 9: Accessing FILE* in handler
void unsafe_handler_file(int sig) {
    // VULNERABLE: FILE operations not async-signal-safe
    if (log_file) {
        fflush(log_file);
    }
}

void setup_handlers() {
    signal(SIGINT, unsafe_handler_printf);
    signal(SIGTERM, unsafe_handler_malloc);
    signal(SIGHUP, unsafe_handler_stdio);
}
