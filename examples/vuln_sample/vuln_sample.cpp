// ─────────────────────────────────────────────────────────────────────────────
// Vigilant-X Example: Synthetic Heap Buffer Overflow
//
// This file deliberately contains a cross-module vulnerability for testing.
// Module A (input.cpp) reads user input without bounds checking.
// Module B (buffer.cpp) uses that input in an unbounded memcpy call.
//
// Vigilant-X should:
//   1. Detect the SOURCE in input.cpp (user-controlled argv[1])
//   2. Trace the PDG edge to the SINK in buffer.cpp (memcpy)
//   3. Prove the overflow with Z3: input_length > 64 → PROVEN
//   4. Generate a repro.cpp and confirm crash via ASan
//   5. Suggest fix: std::span<char, 64> or std::string_view
// ─────────────────────────────────────────────────────────────────────────────

#include <cstring>
#include <cstdlib>
#include <cstdio>

// ── Module B: buffer.cpp ──────────────────────────────────────────────────────
// Sink: unbounded memcpy into a fixed-size stack buffer
void process_data(const char* data, size_t len) {
    char buf[64];  // Fixed-size: 64 bytes
    // VULNERABILITY: no bounds check before memcpy
    // If len > 64, this is a heap/stack buffer overflow.
    memcpy(buf, data, len);
    buf[63] = '\0';
    printf("Processed: %s\n", buf);
}

// ── Module A: input.cpp ───────────────────────────────────────────────────────
// Source: user-controlled argv[1] fed into process_data
int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input>\n", argv[0]);
        return 1;
    }
    const char* user_input = argv[1];
    size_t user_len = strlen(user_input);

    // No bounds check — passes arbitrary length to process_data
    // Z3 witness: user_len = 65 → overflows 64-byte buffer
    process_data(user_input, user_len);

    return 0;
}

// ── Suggested C++20 Fix ───────────────────────────────────────────────────────
// Replace:
//   void process_data(const char* data, size_t len) {
//       char buf[64];
//       memcpy(buf, data, len);  // ← unbounded
//
// With:
//   #include <span>
//   #include <algorithm>
//   void process_data(std::span<const char> data) {
//       std::array<char, 64> buf{};
//       auto safe_len = std::min(data.size(), buf.size() - 1);
//       std::copy_n(data.begin(), safe_len, buf.begin());
//   }
