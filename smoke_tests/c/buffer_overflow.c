// Buffer Overflow vulnerabilities in C
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void unsafe_strcpy(char *user_input) {
    // VULNERABLE: Buffer overflow via strcpy
    char buffer[64];
    strcpy(buffer, user_input);
    printf("%s\n", buffer);
}

void unsafe_sprintf(char *name, int id) {
    // VULNERABLE: sprintf without bounds checking
    char buffer[32];
    sprintf(buffer, "User: %s, ID: %d", name, id);
}

void unsafe_gets() {
    // VULNERABLE: gets() is always dangerous
    char buffer[100];
    gets(buffer);
}

void unsafe_scanf() {
    // VULNERABLE: scanf without field width
    char buffer[50];
    scanf("%s", buffer);
}

void stack_buffer_overflow(char *input) {
    // VULNERABLE: Fixed-size stack buffer
    char local[16];
    memcpy(local, input, strlen(input));
}
