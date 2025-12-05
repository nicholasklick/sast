// Type Confusion vulnerabilities in C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Test 1: Union type confusion
union Data {
    int as_int;
    float as_float;
    char as_bytes[4];
};

void type_pun_union() {
    union Data d;
    d.as_float = 3.14f;
    // VULNERABLE: Accessing as wrong type
    printf("As int: %d\n", d.as_int);
}

// Test 2: Void pointer cast to wrong type
void process_data(void *data, int type) {
    if (type == 1) {
        // Expecting int*
        int *ip = (int*)data;
        printf("%d\n", *ip);
    } else if (type == 2) {
        // Expecting char*
        char *cp = (char*)data;
        printf("%s\n", cp);
    }
    // VULNERABLE: If caller passes wrong type flag
}

// Test 3: Struct type confusion through void pointer
struct TypeA {
    int x;
    int y;
};

struct TypeB {
    char name[8];
    int id;
};

void handle_object(void *obj, int obj_type) {
    // VULNERABLE: No runtime type checking
    struct TypeA *a = (struct TypeA*)obj;
    printf("x = %d, y = %d\n", a->x, a->y);
}

// Test 4: Function pointer type confusion
typedef int (*IntFunc)(int);
typedef void (*VoidFunc)(void);

void call_function(void *func_ptr, int type) {
    if (type == 0) {
        // VULNERABLE: Calling with wrong signature
        ((IntFunc)func_ptr)(42);
    } else {
        ((VoidFunc)func_ptr)();
    }
}

// Test 5: Array element type confusion
void process_array(void *arr, int element_size, int count) {
    // VULNERABLE: element_size may not match actual array type
    for (int i = 0; i < count; i++) {
        int *elem = (int*)((char*)arr + i * element_size);
        printf("%d\n", *elem);
    }
}

// Test 6: Signed/unsigned confusion
void compare_values(int signed_val, unsigned int unsigned_val) {
    // VULNERABLE: Signed/unsigned comparison
    if (signed_val < unsigned_val) {
        printf("Signed is less\n");
    }
}

// Test 7: Size_t truncation
void copy_data(void *dest, void *src, size_t len) {
    // VULNERABLE: Truncating size_t to int
    int actual_len = (int)len;
    memcpy(dest, src, actual_len);
}

// Test 8: Pointer to different sized types
void swap_pointers() {
    long long big = 0x123456789ABCDEF0LL;
    // VULNERABLE: Treating 8-byte value as 4-byte
    int *small_ptr = (int*)&big;
    printf("%x\n", *small_ptr);
}
