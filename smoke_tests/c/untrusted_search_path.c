// Untrusted Search Path vulnerabilities in C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>

// Test 1: system() with unqualified command
void run_command() {
    // VULNERABLE: Relies on PATH, attacker could place malicious binary
    system("ls -la");
}

// Test 2: execlp with unqualified path
void exec_unqualified() {
    // VULNERABLE: Searches PATH for executable
    execlp("python", "python", "script.py", NULL);
}

// Test 3: popen with unqualified command
void pipe_command() {
    // VULNERABLE: Relies on PATH
    FILE *fp = popen("grep pattern file.txt", "r");
    if (fp) {
        char buffer[256];
        while (fgets(buffer, sizeof(buffer), fp)) {
            printf("%s", buffer);
        }
        pclose(fp);
    }
}

// Test 4: dlopen with relative path
void load_library() {
    // VULNERABLE: Relative path, could load malicious library
    void *handle = dlopen("libplugin.so", RTLD_NOW);
    if (handle) {
        // Use library
        dlclose(handle);
    }
}

// Test 5: Loading library from current directory
void load_from_cwd() {
    // VULNERABLE: Current directory in search path
    void *handle = dlopen("./mylib.so", RTLD_NOW);
    if (handle) {
        dlclose(handle);
    }
}

// Test 6: Using PATH from environment
void run_from_path() {
    char *path = getenv("PATH");
    char cmd[256];
    // VULNERABLE: Building command from potentially tainted PATH
    snprintf(cmd, sizeof(cmd), "%s/myprogram", path);
    system(cmd);
}

// Test 7: LD_LIBRARY_PATH manipulation
void check_lib_path() {
    // VULNERABLE: LD_LIBRARY_PATH can be attacker-controlled
    char *lib_path = getenv("LD_LIBRARY_PATH");
    if (lib_path) {
        printf("Library path: %s\n", lib_path);
    }
}

// Test 8: execvp with user input
void exec_user_command(char *cmd, char **args) {
    // VULNERABLE: execvp searches PATH
    execvp(cmd, args);
}

// Test 9: Loading config from relative path
void load_config() {
    // VULNERABLE: Relative path, could load malicious config
    FILE *f = fopen("config/settings.conf", "r");
    if (f) {
        // Parse config
        fclose(f);
    }
}

// Test 10: Shell script execution
void run_script() {
    // VULNERABLE: /bin/sh may be symlinked, script uses PATH
    system("/bin/sh ./setup.sh");
}
