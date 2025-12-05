// Uninitialized Memory vulnerabilities in C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Test 1: Uninitialized local variable
int use_uninitialized() {
    int value;
    // VULNERABLE: value is uninitialized
    return value + 1;
}

// Test 2: Uninitialized array
void print_array() {
    int arr[10];
    // VULNERABLE: arr elements are uninitialized
    for (int i = 0; i < 10; i++) {
        printf("%d\n", arr[i]);
    }
}

// Test 3: Partially initialized struct
struct UserData {
    char name[64];
    int age;
    char email[128];
};

void process_user() {
    struct UserData user;
    user.age = 25;
    // VULNERABLE: name and email are uninitialized
    printf("Name: %s, Age: %d\n", user.name, user.age);
}

// Test 4: Uninitialized pointer
void use_pointer() {
    char *ptr;
    // VULNERABLE: ptr is uninitialized
    *ptr = 'A';
}

// Test 5: Conditional initialization
int conditional_init(int flag) {
    int result;
    if (flag) {
        result = 42;
    }
    // VULNERABLE: result may be uninitialized if flag is 0
    return result;
}

// Test 6: Uninitialized malloc buffer
void use_malloc_buffer() {
    char *buffer = malloc(100);
    // VULNERABLE: malloc does not initialize memory
    printf("%s\n", buffer);
    free(buffer);
}

// Test 7: Uninitialized in switch without default
int switch_init(int code) {
    int value;
    switch (code) {
        case 1:
            value = 10;
            break;
        case 2:
            value = 20;
            break;
        // No default case
    }
    // VULNERABLE: value uninitialized if code is not 1 or 2
    return value;
}

// Test 8: Reading from uninitialized struct member
struct Config {
    int timeout;
    int retries;
};

int get_timeout(struct Config *cfg) {
    struct Config local;
    if (cfg == NULL) {
        cfg = &local;
    }
    // VULNERABLE: local.timeout may be uninitialized
    return cfg->timeout;
}
