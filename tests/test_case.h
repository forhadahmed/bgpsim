/*
 * TEST/PASS/FAIL/ASSERT style for C test programs: TEST() names a case,
 * ASSERT() fails the case and returns from its function, PASS() ends it.
 */

#ifndef TEST_CASE_H
#define TEST_CASE_H

#include "test_result.h"

static int tests_run = 0;
static const char *current_test_name = NULL;

#define TEST(name)                          \
    do {                                    \
        current_test_name = (name);         \
        TEST_PRINT_TEST(current_test_name); \
        tests_run++;                        \
    } while (0)

#define PASS()                                                  \
    do {                                                        \
        test_result_record(1, current_test_name, "case", NULL); \
    } while (0)

#define FAIL(msg)                                                \
    do {                                                         \
        test_result_record(0, current_test_name, "case", (msg)); \
    } while (0)

#define ASSERT(cond, msg) \
    do {                  \
        if (!(cond)) {    \
            FAIL(msg);    \
            return;       \
        }                 \
    } while (0)

#endif /* TEST_CASE_H */
