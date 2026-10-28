/*
 * Shared native result protocol and human-readable styling for C tests.
 *
 * Keep result lines consistent across the test tree:
 * - use [PASS] / [FAIL] / [SKIP] badges
 * - avoid per-file ANSI macro duplication
 */

#ifndef TEST_OUTPUT_H
#define TEST_OUTPUT_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static inline int test_output_use_color(void) {
    return isatty(fileno(stdout));
}

static inline const char *test_badge_pass(void) {
    return test_output_use_color() ? "\x1b[32m[PASS]\x1b[0m" : "[PASS]";
}

static inline const char *test_badge_fail(void) {
    return test_output_use_color() ? "\x1b[31m[FAIL]\x1b[0m" : "[FAIL]";
}

static inline const char *test_badge_test(void) {
    return test_output_use_color() ? "\x1b[33m[TEST]\x1b[0m" : "[TEST]";
}

#define TEST_BADGE_PASS (test_badge_pass())
#define TEST_BADGE_FAIL (test_badge_fail())
#define TEST_BADGE_TEST (test_badge_test())

static inline void test_output_json_string(const char *value) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
        // Python's collector splits Unicode line separators, even in JSON.
        if (p[0] == 0xc2 && p[1] == 0x85) {
            fputs("\\u0085", stdout);
            p++;
            continue;
        }
        if (p[0] == 0xe2 && p[1] == 0x80 && (p[2] == 0xa8 || p[2] == 0xa9)) {
            fputs(p[2] == 0xa8 ? "\\u2028" : "\\u2029", stdout);
            p += 2;
            continue;
        }
        switch (*p) {
        case '"': fputs("\\\"", stdout); break;
        case '\\': fputs("\\\\", stdout); break;
        case '\b': fputs("\\b", stdout); break;
        case '\f': fputs("\\f", stdout); break;
        case '\n': fputs("\\n", stdout); break;
        case '\r': fputs("\\r", stdout); break;
        case '\t': fputs("\\t", stdout); break;
        default:
            if (*p < 0x20) {
                printf("\\u%04x", (unsigned)*p);
            } else {
                putchar(*p);
            }
        }
    }
    putchar('"');
}

static inline void test_output_result(const char *status, const char *name,
                                      const char *kind, const char *key,
                                      const char *detail) {
    if (!name || !*name) name = "Unnamed result";
    if (!key || !*key) key = name;
    flockfile(stdout);
    fputs("@@BGPSIM_RESULT {\"status\":", stdout);
    test_output_json_string(status);
    fputs(",\"name\":", stdout);
    test_output_json_string(name);
    fputs(",\"kind\":", stdout);
    test_output_json_string(kind);
    fputs(",\"key\":", stdout);
    test_output_json_string(key);
    if (detail && *detail) {
        fputs(",\"detail\":", stdout);
        test_output_json_string(detail);
    }
    fputs("}\n", stdout);
    const char *badge = strcmp(status, "pass") == 0 ? TEST_BADGE_PASS :
                        strcmp(status, "fail") == 0 ? TEST_BADGE_FAIL :
                        test_output_use_color() ? "\x1b[33m[SKIP]\x1b[0m" : "[SKIP]";
    /*
     * Non-badge text for unusual names avoids a second legacy result when
     * the collector splits lines or strips ANSI escapes/leading whitespace.
     */
    int unusual_name = name[0] == ' ';
    for (const unsigned char *p = (const unsigned char *)name; *p; p++) {
        unusual_name |= (*p < 0x20 && *p != '\n' && *p != '\r') || *p >= 0x7f;
    }
    if (unusual_name) {
        printf("%s: ", badge);
        test_output_json_string(name);
        putchar('\n');
    } else {
        printf("%s ", badge);
        for (const char *p = name; *p; p++) {
            if (*p == '\n') fputs("\\n", stdout);
            else if (*p == '\r') fputs("\\r", stdout);
            else putchar((unsigned char)*p);
        }
        putchar('\n');
    }
    if (detail && *detail) {
        fputs("  Detail: ", stdout);
        test_output_json_string(detail);
        putchar('\n');
    }
    fflush(stdout);
    funlockfile(stdout);
}

static inline void test_output_check(const char *status, const char *name) {
    test_output_result(status, name, "check", name, NULL);
}

#define TEST_PRINT_PASS(name) test_output_check("pass", (name))
#define TEST_PRINT_FAIL(name) test_output_check("fail", (name))
#define TEST_PRINT_TEST(name) printf("%s %s\n", TEST_BADGE_TEST, (name))
#define TEST_PRINT_SKIP(name) test_output_check("skip", (name))
#define TEST_PRINT_RESULT(passed, name) \
    do {                                \
        if (passed) {                   \
            TEST_PRINT_PASS(name);      \
        } else {                        \
            TEST_PRINT_FAIL(name);      \
        }                               \
    } while (0)

#endif /* TEST_OUTPUT_H */
