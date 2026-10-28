/*
 * Pass/fail counting for the C test programs that report with test_result().
 * Each test program is one translation unit, so the counters belong to that
 * program.
 */

#ifndef TEST_RESULT_H
#define TEST_RESULT_H

#include "test_output.h"

static int tests_passed = 0;
static int tests_failed = 0;

/*
 * All case/check pass/fail counting has one owner.
 */
static inline void test_result_record(int passed, const char *name, const char *kind, const char *detail) {
    test_output_result(passed ? "pass" : "fail", name, kind, name, detail);
    if (passed) {
        tests_passed++;
    } else {
        tests_failed++;
    }
}

static inline void test_result(int passed, const char *test_name) {
    test_result_record(passed, test_name, "check", NULL);
}

#endif /* TEST_RESULT_H */
