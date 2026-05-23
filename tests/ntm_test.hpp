#pragma once
// ntm_test.hpp — minimal self-contained unit test framework.
// No external dependencies.  Usage:
//
//   TEST_CASE("descriptive name") { REQUIRE(expr); REQUIRE_EQ(a, b); }
//   int main() { return ntmtest::runAll(); }

#include <cstring>
#include <functional>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace ntmtest
{

struct TestCase
{
    std::string name;
    std::function<void()> fn;
};

inline std::vector<TestCase> &registry()
{
    static std::vector<TestCase> r;
    return r;
}

struct Registrar
{
    Registrar(const char *name, std::function<void()> fn)
    {
        registry().push_back({name, std::move(fn)});
    }
};

inline int runAll()
{
    int pass = 0, fail = 0;
    for (auto &tc : registry())
    {
        try
        {
            tc.fn();
            std::cout << "  PASS  " << tc.name << "\n";
            ++pass;
        }
        catch (const std::exception &e)
        {
            std::cout << "  FAIL  " << tc.name << "\n"
                      << "        " << e.what() << "\n";
            ++fail;
        }
        catch (...)
        {
            std::cout << "  FAIL  " << tc.name << "\n"
                      << "        (unknown exception)\n";
            ++fail;
        }
    }
    std::cout << "\n" << pass << " passed, " << fail << " failed\n";
    return fail > 0 ? 1 : 0;
}

// Internal assertion helper — throws on failure.
[[noreturn]] inline void failWith(const char *expr, const char *file, int line,
                                  const std::string &extra = {})
{
    std::ostringstream oss;
    oss << "REQUIRE failed: " << expr << "  at " << file << ":" << line;
    if (!extra.empty()) oss << "\n        " << extra;
    throw std::runtime_error(oss.str());
}

inline void requireTrue(bool cond, const char *expr, const char *file, int line)
{
    if (!cond) failWith(expr, file, line);
}

template <class A, class B>
void requireEq(const A &a, const B &b,
               const char *exprA, const char *exprB,
               const char *file, int line)
{
    if (!(a == b))
    {
        std::ostringstream extra;
        extra << "lhs=" << a << "  rhs=" << b;
        failWith((std::string(exprA) + " == " + exprB).c_str(), file, line, extra.str());
    }
}

template <class A, class B>
void requireNe(const A &a, const B &b,
               const char *exprA, const char *exprB,
               const char *file, int line)
{
    if (a == b)
    {
        std::ostringstream extra;
        extra << "both equal: " << a;
        failWith((std::string(exprA) + " != " + exprB).c_str(), file, line, extra.str());
    }
}

} // namespace ntmtest

// Macros — use __LINE__ so the same value is used consistently within one
// macro expansion (unlike __COUNTER__ which increments on every use).
// Each TEST_CASE must be on a distinct line (which is always the case in practice).
#define NTM_CONCAT2(a,b) a##b
#define NTM_CONCAT(a,b)  NTM_CONCAT2(a,b)

#define TEST_CASE(name_str) \
    static void NTM_CONCAT(_ntm_tc_, __LINE__)(); \
    static ::ntmtest::Registrar NTM_CONCAT(_ntm_reg_, __LINE__) \
        {name_str, NTM_CONCAT(_ntm_tc_, __LINE__)}; \
    static void NTM_CONCAT(_ntm_tc_, __LINE__)()

#define REQUIRE(cond) \
    ::ntmtest::requireTrue(!!(cond), #cond, __FILE__, __LINE__)

#define REQUIRE_EQ(a, b) \
    ::ntmtest::requireEq((a), (b), #a, #b, __FILE__, __LINE__)

#define REQUIRE_NE(a, b) \
    ::ntmtest::requireNe((a), (b), #a, #b, __FILE__, __LINE__)
