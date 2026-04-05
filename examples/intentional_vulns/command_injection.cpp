/**
 * intentional_vulns/command_injection.cpp
 * ────────────────────────────────────────
 * Deliberate command injection for Vigilant-X validation.
 * BUG: User-controlled filename is passed directly to system()
 *      via sprintf with no sanitization.
 */
#include <cstdlib>
#include <cstring>
#include <cstdio>

void compress_file(const char* user_filename) {
    char cmd[256];
    // BUG: sprintf allows shell metacharacters from user_filename
    // e.g. user_filename = "file.txt; rm -rf /"
    sprintf(cmd, "gzip -c %s > /tmp/archive.gz", user_filename);
    system(cmd);  // OS command injection
}

void list_directory(const char* user_dir) {
    char cmd[128];
    // BUG: another command injection via strcpy + system
    strcpy(cmd, "ls -la ");
    strcat(cmd, user_dir);  // BUG: also a potential buffer overflow
    system(cmd);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }
    // argv[1] is attacker-controlled
    compress_file(argv[1]);
    list_directory(argv[1]);
    return 0;
}
