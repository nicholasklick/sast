// Signal Handler vulnerabilities in C++
#include <iostream>
#include <csignal>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <mutex>

// Global state (problematic in signal handlers)
std::mutex g_mutex;
char* g_buffer = nullptr;
int g_count = 0;

// Test 1: Non-reentrant function in signal handler
void handler_with_printf(int sig) {
    // VULNERABLE: printf is not async-signal-safe
    printf("Received signal %d\n", sig);
}

// Test 2: Memory allocation in signal handler
void handler_with_malloc(int sig) {
    // VULNERABLE: malloc is not async-signal-safe
    char* buf = (char*)malloc(100);
    if (buf) {
        strcpy(buf, "signal");
        free(buf);
    }
}

// Test 3: Mutex in signal handler
void handler_with_mutex(int sig) {
    // VULNERABLE: Can deadlock if signal interrupts locked section
    std::lock_guard<std::mutex> lock(g_mutex);
    g_count++;
}

// Test 4: cout in signal handler
void handler_with_cout(int sig) {
    // VULNERABLE: iostream is not async-signal-safe
    std::cout << "Signal received: " << sig << std::endl;
}

// Test 5: exit() in signal handler
void handler_with_exit(int sig) {
    // VULNERABLE: exit() calls atexit handlers, not async-signal-safe
    printf("Exiting...\n");
    exit(1);
}

// Test 6: Accessing non-volatile global
void handler_accessing_global(int sig) {
    // VULNERABLE: g_count should be volatile sig_atomic_t
    g_count = 1;
}

// Test 7: Calling other signal handlers
void handler_calling_signal(int sig) {
    // VULNERABLE: signal() is not async-signal-safe
    signal(SIGTERM, SIG_DFL);
}

// Test 8: Freeing memory in signal handler
void handler_with_free(int sig) {
    // VULNERABLE: free() is not async-signal-safe
    if (g_buffer) {
        free(g_buffer);
        g_buffer = nullptr;
    }
}

// Test 9: File operations in signal handler
void handler_with_file(int sig) {
    // VULNERABLE: fopen is not async-signal-safe
    FILE* f = fopen("/tmp/signal.log", "a");
    if (f) {
        fprintf(f, "Signal %d\n", sig);
        fclose(f);
    }
}

// Test 10: Complex object operations
void handler_with_string(int sig) {
    // VULNERABLE: std::string operations not async-signal-safe
    std::string msg = "Signal: ";
    msg += std::to_string(sig);
}

// Test 11: longjmp from signal handler
#include <setjmp.h>
jmp_buf jump_buffer;

void handler_with_longjmp(int sig) {
    // VULNERABLE: Undefined behavior in C++ (unwinds stack without destructors)
    longjmp(jump_buffer, 1);
}

// Test 12: new/delete in signal handler
void handler_with_new(int sig) {
    // VULNERABLE: operator new is not async-signal-safe
    int* p = new int(sig);
    delete p;
}

// Setup function showing various unsafe handlers
void setup_handlers() {
    signal(SIGINT, handler_with_printf);
    signal(SIGTERM, handler_with_malloc);
    signal(SIGUSR1, handler_with_mutex);
    signal(SIGUSR2, handler_with_cout);
}
