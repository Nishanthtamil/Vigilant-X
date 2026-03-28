
#include <iostream>

void CWE457_good(bool flag) {
    int val = 0;
    if (flag) {
        val = 10;
    }
    // GOOD: val is initialized
    std::cout << val << std::endl;
}

int main(int argc, char *argv[]) {
    // Test the safe path
    CWE457_good(false);
    return 0;
}
