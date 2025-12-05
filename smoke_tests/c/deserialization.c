// Insecure Deserialization Test Cases

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Test 1: Deserializing binary data without validation
typedef struct {
    char username[64];
    int role;
    void (*handler)(void);
} UserData;

void deserialize_user_data(const char *binary_data, size_t len) {
    UserData *user = (UserData *)malloc(sizeof(UserData));
    // VULNERABLE: Memcpy without validation, could overwrite function pointer
    memcpy(user, binary_data, len);
    free(user);
}

// Test 2: Reading object from file
void load_object_from_file(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (fp) {
        UserData user;
        // VULNERABLE: Reading untrusted binary data
        fread(&user, sizeof(UserData), 1, fp);
        fclose(fp);
    }
}

// Test 3: Parsing serialized structure
void parse_serialized_struct(const void *data) {
    // VULNERABLE: Casting untrusted data to struct
    UserData *user = (UserData *)data;
    // Use the potentially malicious data
}

// Test 4: Network deserialization
void receive_network_object(int socket_fd) {
    UserData user;
    // VULNERABLE: Receiving and using binary data from network
    recv(socket_fd, &user, sizeof(user), 0);
}

// Test 5: Shared memory deserialization
void read_from_shared_memory(void *shm_ptr) {
    UserData *user = (UserData *)shm_ptr;
    // VULNERABLE: Trusting data from shared memory
    // Could be modified by malicious process
}
