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

/*
 * A strict expected failure (xfail) for a product gap that a todo tracks. The check still runs every time. While the
 * product fails in exactly the documented way, it reports xfail and names the todo. An unexpected pass (XPASS) fails,
 * so the marker cannot outlive the fix. Any other outcome is an ordinary failure, so a broken setup never hides behind
 * the xfail.
 */
static inline void test_xfail(int passed, int documented_failure, const char *name, const char *todo) {
    char detail[256];

    if (!passed && documented_failure) {
        snprintf(detail, sizeof(detail), "expected failure, tracked in %s", todo);
        test_output_result("xfail", name, "check", name, detail);
        return;
    }
    snprintf(detail, sizeof(detail),
             passed ? "unexpected pass (XPASS): make this a regular check and close %s"
                    : "fails differently from the expected failure tracked in %s", todo);
    test_result_record(0, name, "check", detail);
}

#endif /* TEST_RESULT_H */
