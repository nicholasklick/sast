// Command Injection vulnerabilities in C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void system_injection(char *filename) {
    // VULNERABLE: Command injection via system()
    char cmd[256];
    sprintf(cmd, "cat %s", filename);
    system(cmd);
}

void popen_injection(char *user_input) {
    // VULNERABLE: Command injection via popen()
    char command[512];
    snprintf(command, sizeof(command), "grep %s /var/log/messages", user_input);
    FILE *fp = popen(command, "r");
    pclose(fp);
}

void exec_injection(char *arg) {
    // VULNERABLE: Passing user input to exec
    char *args[] = {"/bin/sh", "-c", arg, NULL};
    execv("/bin/sh", args);
}

int shell_command(char *host) {
    // VULNERABLE: Shell command with user input
    char buffer[256];
    sprintf(buffer, "ping -c 4 %s", host);
    return system(buffer);
}
