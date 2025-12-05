// Null Pointer Dereference vulnerabilities in C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Test 1: Unchecked malloc return
void unchecked_malloc() {
    char *buffer = malloc(1000000000);
    // VULNERABLE: malloc may return NULL
    buffer[0] = 'A';
}

// Test 2: Null check on wrong path
void wrong_null_check(char *ptr) {
    char c = *ptr;  // VULNERABLE: Dereference before check
    if (ptr != NULL) {
        printf("%c\n", c);
    }
}

// Test 3: Null from function return
char* get_optional_data(int id);

void process_optional(int id) {
    char *data = get_optional_data(id);
    // VULNERABLE: data may be NULL
    printf("Data: %s\n", data);
}

// Test 4: Null in struct member
struct Node {
    int value;
    struct Node *next;
};

void traverse_list(struct Node *head) {
    struct Node *current = head;
    while (current->value != -1) {  // VULNERABLE: current may be NULL
        printf("%d\n", current->value);
        current = current->next;
    }
}

// Test 5: Null after realloc
void grow_buffer(char **buf, size_t new_size) {
    *buf = realloc(*buf, new_size);
    // VULNERABLE: realloc may return NULL
    (*buf)[0] = '\0';
}

// Test 6: Conditional null dereference
void conditional_deref(int *ptr, int condition) {
    int value;
    if (condition) {
        value = *ptr;  // OK if ptr is valid
    }
    // VULNERABLE: ptr may be NULL regardless of condition
    printf("%d\n", *ptr);
}

// Test 7: Null from failed fopen
void read_file(const char *filename) {
    FILE *f = fopen(filename, "r");
    // VULNERABLE: fopen may return NULL
    char buffer[256];
    fgets(buffer, sizeof(buffer), f);
    fclose(f);
}
