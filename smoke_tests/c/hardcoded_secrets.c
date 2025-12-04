// Hardcoded Secrets vulnerabilities in C
#include <stdio.h>
#include <string.h>

// VULNERABLE: Hardcoded password
#define DB_PASSWORD "super_secret_123"

// VULNERABLE: Hardcoded API key
const char *API_KEY = "sk_live_abcdef1234567890";

// VULNERABLE: Hardcoded encryption key
static unsigned char AES_KEY[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                   0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

void connect_database() {
    // VULNERABLE: Hardcoded credentials in connection
    const char *conn = "host=db.example.com user=admin password=admin123";
    printf("Connecting with: %s\n", conn);
}

int authenticate(char *username, char *password) {
    // VULNERABLE: Hardcoded password comparison
    if (strcmp(password, "backdoor_password") == 0) {
        return 1;
    }
    return 0;
}

char* get_jwt_secret() {
    // VULNERABLE: Hardcoded JWT secret
    return "my_jwt_secret_key_12345";
}
