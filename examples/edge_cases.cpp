#include <iostream>
#include <memory>
#include <vector>
#include <cstring>

// Edge Case 1: Template-based sink
// Joern (full) should handle this, but the stub CPG and Z3 heuristics 
// likely won't see 'SafeBuffer<64>::copy' as a vulnerable memcpy-like sink.
template<size_t N>
struct SafeBuffer {
    char data[N];
    void copy(const char* src, size_t len) {
        // VULNERABILITY: No check if len < N
        std::memcpy(data, src, len);
    }
};

void test_template_vuln(const char* input, size_t len) {
    SafeBuffer<32> buf;
    buf.copy(input, len);
}

// Edge Case 2: RAII and Smart Pointers
// Will the concolic engine correctly track the lifetime through std::unique_ptr?
void test_raii_uaf(const char* input) {
    auto ptr = std::make_unique<char[]>(32);
    std::strncpy(ptr.get(), input, 31);
    
    char* raw = ptr.get();
    ptr.reset(); // ptr is freed here
    
    // VULNERABILITY: Use after reset()
    // The Z3 'free' heuristic looks for 'free(ptr)' or 'delete ptr', 
    // not 'ptr.reset()'.
    std::cout << "Raw ptr after reset: " << raw << std::endl;
}

// Edge Case 3: Macro-hidden Sink
// Heuristics looking for 'memcpy' or 'strcpy' will miss this.
#define MY_COPY(dst, src, n) std::memmove(dst, src, n)

void test_macro_vuln(const char* input, size_t len) {
    char buf[16];
    MY_COPY(buf, input, len);
}

// Edge Case 4: Complex Data Flow (C++20 std::span)
// Modern C++ types might not be correctly modeled in the graph or Z3.
#include <span>
void test_span_vuln(std::span<char> s, const char* input) {
    // VULNERABILITY: If s.size() < strlen(input)
    std::strcpy(s.data(), input);
}

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    
    test_template_vuln(argv[1], 128);
    test_raii_uaf(argv[1]);
    test_macro_vuln(argv[1], 128);
    
    char stack_buf[16];
    test_span_vuln(std::span<char>(stack_buf, 16), argv[1]);
    
    return 0;
}
