#include <cstring>
#include <cstdlib>
#include <cstdio>

int main() {
    char* buf = (char*)malloc(64);
    buf[128] = 'A'; // Explicit heap buffer overflow
    printf("Done\n");
    return 0;
}
