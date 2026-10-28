#include <stdlib.h>
#include "test_case.h"

static const char escaped_name[] = "quoted \"name\"\\path\n\r\t\b\f\001\037";

static void assertion_failure(void) {
    TEST("asserting case");
    ASSERT(0, "assertion detail");
    PASS();
}

/*
 * An intentionally failing fixture also consumed by test_results.collect().
 */
static void fixture(const char *detail) {
    TEST("stable \"case\"\\name");
    FAIL(detail);
    TEST("passing case");
    PASS();
    test_result(1, "raw check");
    test_result(0, "raw failure");
    TEST_PRINT_RESULT(1, "printed check");
    TEST_PRINT_SKIP("skipped check");
    TEST_PRINT_PASS(escaped_name);
}

static int occurrences(const char *text, const char *needle) {
    int count = 0;
    for (const char *p = text; (p = strstr(p, needle)) != NULL; p += strlen(needle)) count++;
    return count;
}

static char *capture_fixture(const char *detail, int *counted_correctly) {
    FILE *capture = tmpfile();
    if (!capture) return NULL;
    fflush(stdout);
    int saved_stdout = dup(STDOUT_FILENO);
    if (saved_stdout < 0 || dup2(fileno(capture), STDOUT_FILENO) < 0) {
        if (saved_stdout >= 0) close(saved_stdout);
        fclose(capture);
        return NULL;
    }
    int         passed = tests_passed, failed = tests_failed, run = tests_run;
    const char *name = current_test_name;
    fixture(detail);
    assertion_failure();
    TEST_PRINT_PASS("unicode \302\205 \342\200\250 \342\200\251");
    *counted_correctly = tests_passed == passed + 2 && tests_failed == failed + 3 && tests_run == run + 3;
    tests_passed = passed;
    tests_failed = failed;
    tests_run = run;
    current_test_name = name;
    fflush(stdout);
    if (dup2(saved_stdout, STDOUT_FILENO) < 0) abort();
    close(saved_stdout);
    long  length = ftell(capture);
    char *output = length < 0 ? NULL : malloc((size_t)length + 1);
    if (output) {
        rewind(capture);
        if (fread(output, 1, (size_t)length, capture) != (size_t)length) {
            free(output);
            output = NULL;
        } else {
            output[length] = '\0';
        }
    }
    fclose(capture);
    return output;
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "--fixture") == 0) {
        fixture(argv[2]);
        return tests_failed ? 1 : 0;
    }
    int   first_counts = 0, second_counts = 0;
    char *first = capture_fixture("first \"detail\"\\line\n\001", &first_counts);
    char *second = capture_fixture("different detail", &second_counts);
    test_result(first && second, "Result protocol fixture output is captured");
    if (!first || !second) {
        free(first);
        free(second);
        return 1;
    }
    test_result(first_counts && second_counts, "Shared counters count cases and checks once");
    const char *identity = "\"name\":\"stable \\\"case\\\"\\\\name\",\"kind\":\"case\",\"key\":\"stable \\\"case\\\"\\\\name\"";
    test_result(strstr(first, identity) && strstr(second, identity),
                "Changing failure details preserves case name and key");
    test_result(occurrences(first, "\"kind\":\"case\"") == 3 &&
                occurrences(first, "\"kind\":\"check\"") == 6 &&
                occurrences(first, "@@BGPSIM_RESULT ") == 9,
                "Only TEST cases are cases; raw results and skips are checks");
    test_result(strstr(first, "\"detail\":\"first \\\"detail\\\"\\\\line\\n\\u0001\"") != NULL,
                "Failure detail escapes quotes, backslashes and controls");
    test_result(strstr(first, "quoted \\\"name\\\"\\\\path\\n\\r\\t\\b\\f\\u0001\\u001f") != NULL,
                "JSON names and keys escape every control character class");
    test_result(strstr(first, "unicode \\u0085 \\u2028 \\u2029") != NULL,
                "Unicode line separators cannot split native JSON records");
    test_result(strstr(first, "[FAIL] stable \"case\"\\name\n") &&
                strstr(first, "[PASS] passing case\n") && strstr(first, "[SKIP] skipped check\n") &&
                !strstr(first, "\x1b["),
                "Piped human output retains badges without ANSI color");
    free(first);
    free(second);
    return tests_failed ? 1 : 0;
}
