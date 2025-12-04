// Path Traversal vulnerabilities in C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

FILE* open_file_unsafe(char *filename) {
    // VULNERABLE: No path validation
    char path[256];
    sprintf(path, "/var/data/%s", filename);
    return fopen(path, "r");
}

int read_config_unsafe(char *config_name) {
    // VULNERABLE: Direct path concatenation
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "/etc/app/%s.conf", config_name);
    FILE *fp = fopen(filepath, "r");
    if (fp) {
        fclose(fp);
        return 1;
    }
    return 0;
}

void serve_static_file(char *requested_path) {
    // VULNERABLE: Serving files based on user input
    char full_path[1024];
    strcpy(full_path, "/var/www/static/");
    strcat(full_path, requested_path);
    FILE *f = fopen(full_path, "r");
}

int delete_temp_file(char *name) {
    // VULNERABLE: Arbitrary file deletion
    char path[256];
    sprintf(path, "/tmp/%s", name);
    return remove(path);
}
