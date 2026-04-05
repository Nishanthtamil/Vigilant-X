/**
 * intentional_vulns/heap_overflow.cpp
 * ────────────────────────────────────
 * Deliberate heap buffer overflow for Vigilant-X validation.
 * BUG: memcpy copies user_len bytes into a 64-byte heap buffer
 *      without any bounds check.
 */
#include <cstdlib>
#include <cstring>
#include <cstdio>

struct Request {
    char header[16];
    size_t payload_len;
    const char* payload;
};

char* process_request(const Request& req) {
    // Fixed-size destination buffer on the heap
    char* buf = (char*)malloc(64);
    if (!buf) return nullptr;

    // BUG: payload_len can exceed 64 → heap buffer overflow
    memcpy(buf, req.payload, req.payload_len);
    buf[63] = '\0';  // null-terminate attempt (too late if overflow happened)
    return buf;
}

void handle_network_input(const char* raw_input, size_t raw_len) {
    Request req;
    strncpy(req.header, "REQ", sizeof(req.header));
    req.payload = raw_input;
    req.payload_len = raw_len;  // attacker controls this

    char* result = process_request(req);
    if (result) {
        printf("Processed: %.64s\n", result);
        free(result);
    }
}

int main() {
    // Simulated attacker input: 256 bytes into a 64-byte buffer
    char evil_input[256];
    memset(evil_input, 'A', sizeof(evil_input));
    handle_network_input(evil_input, sizeof(evil_input));
    return 0;
}
