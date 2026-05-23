// test_main.cpp — entry point for the ntm unit test binary.
#include "ntm_test.hpp"

int main()
{
    std::cout << "ntm unit tests\n"
              << "══════════════\n";
    return ntmtest::runAll();
}
