// Double Free vulnerabilities in C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Test 1: Basic double free
void basic_double_free() {
    char *ptr = malloc(100);
    free(ptr);
    // VULNERABLE: Double free
    free(ptr);
}

// Test 2: Double free through alias
void aliased_double_free() {
    int *ptr1 = malloc(sizeof(int));
    int *ptr2 = ptr1;
    free(ptr1);
    // VULNERABLE: ptr2 is same as ptr1
    free(ptr2);
}

// Test 3: Conditional double free
void conditional_double_free(int flag) {
    char *buffer = malloc(64);
    if (flag) {
        free(buffer);
    }
    // VULNERABLE: May double free if flag was true
    free(buffer);
}

// Test 4: Double free in error handling
int process_data(const char *input) {
    char *data = malloc(strlen(input) + 1);
    if (!data) return -1;

    strcpy(data, input);

    if (strlen(data) == 0) {
        free(data);
        return -1;
    }

    // Process...
    if (data[0] == 'X') {
        free(data);
        return -2;
    }

    // VULNERABLE: data may already be freed
    free(data);
    return 0;
}

// Test 5: Double free in loop
void loop_double_free(int n) {
    char *ptr = malloc(100);
    for (int i = 0; i < n; i++) {
        if (i == 5) {
            free(ptr);
        }
    }
    // VULNERABLE: ptr freed inside loop
    free(ptr);
}

// Test 6: Double free across functions
static char *global_ptr = NULL;

void set_and_free() {
    global_ptr = malloc(50);
    free(global_ptr);
}

void use_and_free() {
    set_and_free();
    // VULNERABLE: global_ptr already freed
    free(global_ptr);
}
