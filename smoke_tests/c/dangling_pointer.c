// Dangling Pointer vulnerabilities in C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Test 1: Return pointer to local variable
int* return_local_address() {
    int local = 42;
    // VULNERABLE: Returning address of local variable
    return &local;
}

// Test 2: Pointer to stack variable escapes scope
int* get_array_element() {
    int arr[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    // VULNERABLE: arr goes out of scope
    return &arr[5];
}

// Test 3: Storing pointer to local in global
static int *global_ptr;

void set_global_to_local() {
    int local = 100;
    // VULNERABLE: global_ptr will dangle after function returns
    global_ptr = &local;
}

// Test 4: Dangling pointer through struct
struct Container {
    int *data;
};

void fill_container(struct Container *c) {
    int local_data = 42;
    // VULNERABLE: c->data will dangle
    c->data = &local_data;
}

// Test 5: Dangling pointer in callback
typedef void (*Callback)(int*);

void register_callback_with_local(Callback cb) {
    int local = 10;
    // VULNERABLE: callback receives dangling pointer after return
    cb(&local);
}

// Test 6: Returning pointer to static buffer (thread-unsafe, can dangle logically)
char* get_formatted_name(const char *first, const char *last) {
    static char buffer[256];
    // VULNERABLE: Subsequent calls overwrite buffer
    snprintf(buffer, sizeof(buffer), "%s %s", first, last);
    return buffer;
}

// Test 7: Pointer to reallocated memory
void use_old_pointer() {
    int *arr = malloc(10 * sizeof(int));
    int *elem = &arr[5];
    arr = realloc(arr, 1000 * sizeof(int));
    // VULNERABLE: elem may now be dangling if realloc moved the block
    *elem = 42;
}

// Test 8: Dangling pointer from freed struct
struct Node {
    int value;
    struct Node *next;
};

struct Node* remove_node(struct Node *head) {
    struct Node *old_head = head;
    head = head->next;
    free(old_head);
    // VULNERABLE: Returning pointer to freed memory's next field
    return old_head->next;
}
