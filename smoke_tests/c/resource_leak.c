// Resource Leak vulnerabilities in C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <pthread.h>

// Test 1: File descriptor leak
void file_descriptor_leak(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return;

    char buffer[256];
    read(fd, buffer, sizeof(buffer));
    // VULNERABLE: fd is never closed
}

// Test 2: Memory leak on error path
char* read_file_content(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;

    char *buffer = malloc(1024);
    if (!buffer) {
        // VULNERABLE: f is not closed on this path
        return NULL;
    }

    fread(buffer, 1, 1024, f);
    fclose(f);
    return buffer;
}

// Test 3: Socket leak
void connect_to_server(const char *host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    // Connection logic...
    // VULNERABLE: socket never closed
}

// Test 4: Multiple resource leak
void process_files(const char *in_path, const char *out_path) {
    FILE *in = fopen(in_path, "r");
    if (!in) return;

    FILE *out = fopen(out_path, "w");
    if (!out) {
        // VULNERABLE: in is not closed
        return;
    }

    char buffer[256];
    while (fgets(buffer, sizeof(buffer), in)) {
        fputs(buffer, out);
    }

    fclose(out);
    // VULNERABLE: in is not closed
}

// Test 5: Mutex leak
pthread_mutex_t *create_mutex() {
    pthread_mutex_t *mutex = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(mutex, NULL);
    // VULNERABLE: mutex_destroy never called, mutex never freed
    return mutex;
}

// Test 6: Memory leak in loop
void process_items(int count) {
    for (int i = 0; i < count; i++) {
        char *item = malloc(100);
        sprintf(item, "Item %d", i);
        printf("%s\n", item);
        // VULNERABLE: item is never freed in each iteration
    }
}

// Test 7: Conditional memory leak
void conditional_alloc(int flag) {
    char *data = malloc(256);
    if (flag) {
        // Early return without free
        // VULNERABLE: memory leak
        return;
    }
    free(data);
}

// Test 8: FILE pointer leak
void log_message(const char *msg) {
    FILE *log = fopen("/var/log/app.log", "a");
    if (!log) return;

    fprintf(log, "%s\n", msg);
    // VULNERABLE: log file handle never closed
}

// Test 9: opendir leak
void list_directory(const char *path) {
    DIR *dir = opendir(path);
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        printf("%s\n", entry->d_name);
    }
    // VULNERABLE: closedir never called
}
