#include <iostream>
#include <cstring>
#include <cstdlib>
#include <string>

// 1. Buffer Overflow (Classic Taint)
void test_buffer_overflow(const char* user_input) {
    char buf[16];
    // VULNERABILITY: strcpy doesn't check size.
    // If strlen(user_input) >= 16, this is a stack overflow.
    std::strcpy(buf, user_input);
    std::cout << "Buffer contents: " << buf << std::endl;
}

// 2. Use-After-Free
void test_uaf(const char* data) {
    char* ptr = (char*)std::malloc(32);
    std::strncpy(ptr, data, 31);
    ptr[31] = '\0';
    std::free(ptr);
    // VULNERABILITY: Use after free.
    std::cout << "UAF content: " << ptr << std::endl;
}

// 3. Uninitialized Memory Read
void test_uninitialized_read() {
    char* ptr = (char*)std::malloc(32);
    // VULNERABILITY: Read without initialization.
    // MSan should catch this.
    if (ptr[0] == 'A') {
        std::cout << "Uninitialized start with A" << std::endl;
    }
    std::free(ptr);
}

// 4. Integer Overflow in Allocation
void test_integer_overflow(int count) {
    // VULNERABILITY: Multiplication can overflow.
    // Z3 should detect this if count is controlled by user.
    // If count = 2^30, 4 * count overflows to 0.
    size_t size = count * 4;
    char* ptr = (char*)std::malloc(size);
    if (ptr) {
        std::memset(ptr, 0, size);
        std::cout << "Allocated " << size << " bytes" << std::endl;
        std::free(ptr);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <string> <number>" << std::endl;
        return 1;
    }

    test_buffer_overflow(argv[1]);
    test_uaf(argv[1]);
    test_uninitialized_read();
    test_integer_overflow(std::atoi(argv[2]));

    return 0;
}
