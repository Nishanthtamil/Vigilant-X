#include <iostream>
#include <memory>
#include <vector>
#include <cstring>
#include <algorithm>

// 1. Macro-hidden Sink
// Traditional tools look for 'memcpy', but we use a macro.
#define DANGEROUS_COPY(dest, src, size) std::memcpy(dest, src, size)

void test_macro_overflow(const char* input, size_t len) {
    char buffer[32];
    if (len > 0) {
        // VULNERABILITY: No check if len > 32
        DANGEROUS_COPY(buffer, input, len);
        std::cout << "Macro copy done: " << buffer << std::endl;
    }
}

// 2. RAII / Smart Pointer Use-After-Free
// Traditional Z3 heuristics look for 'free()', but we use 'unique_ptr::reset()'.
void test_raii_uaf(const char* input) {
    auto smart_ptr = std::make_unique<char[]>(64);
    std::strncpy(smart_ptr.get(), input, 63);
    
    char* raw_alias = smart_ptr.get();
    smart_ptr.reset(); // The memory is freed here.
    
    // VULNERABILITY: Accessing raw_alias after smart_ptr.reset()
    std::cout << "UAF Access: " << raw_alias[0] << std::endl;
}

// 3. Library Summary / Bridge Case
// Traditional tools lose the taint path inside 'std::copy'.
void test_std_copy_overflow(const char* input, size_t len) {
    char small_buf[16];
    // VULNERABILITY: std::copy doesn't check bounds.
    // Our 'Library Summary' should bridge the flow from input to small_buf.
    std::copy(input, input + len, small_buf);
    small_buf[15] = '\0';
    std::cout << "Std::copy done: " << small_buf << std::endl;
}

// 4. Custom Semantic Sink
// A function that doesn't look like a sink but behaves like one.
void internal_log_buffer(char* target, const char* msg) {
    // Hidden overflow in a 'safe-looking' internal function
    std::strcpy(target, msg);
}

void test_semantic_sink(const char* user_controlled) {
    char local_stack[8];
    internal_log_buffer(local_stack, user_controlled);
}

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    
    const char* tainted = argv[1];
    size_t length = std::strlen(tainted);
    
    test_macro_overflow(tainted, length);
    test_raii_uaf(tainted);
    test_std_copy_overflow(tainted, length);
    test_semantic_sink(tainted);
    
    return 0;
}
