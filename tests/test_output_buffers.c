#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "output.h"
#include "test_result.h"

typedef struct {
    output_buffer_t stdout_buffer;
    output_buffer_t stderr_buffer;
} capture_t;

static void capture_write(void *opaque, output_stream_t stream, const char *data, size_t len) {
    capture_t *capture = opaque;

    if (!capture || !data || len == 0) {
        return;
    }

    if (stream == OUTPUT_STREAM_STDERR) {
        output_buffer_write(&capture->stderr_buffer, data, len);
    } else {
        output_buffer_write(&capture->stdout_buffer, data, len);
    }
}

static void capture_init(capture_t *capture) {
    output_buffer_init(&capture->stdout_buffer);
    output_buffer_init(&capture->stderr_buffer);
}

static void capture_free(capture_t *capture) {
    output_buffer_free(&capture->stdout_buffer);
    output_buffer_free(&capture->stderr_buffer);
}

static void test_output_buffer_lifecycle(void) {
    output_buffer_t buffer;
    int             passed = 0;

    output_buffer_init(&buffer);
    output_buffer_write(&buffer, "hello", 5);
    output_buffer_write(&buffer, " world", 6);

    if (buffer.data != NULL &&
        buffer.len == 11 &&
        strcmp(buffer.data, "hello world") == 0) {
        output_buffer_reset(&buffer);
        passed = buffer.len == 0 && buffer.data != NULL && buffer.data[0] == '\0';
    }

    test_result(passed, "Output buffer appends and reset preserves valid empty state");
    output_buffer_free(&buffer);
}

static void test_output_buffer_growth(void) {
    output_buffer_t buffer;
    int             passed = 0;

    output_buffer_init(&buffer);
    for (int i = 0; i < 300; i++) {
        output_buffer_write(&buffer, "1234567890", 10);
    }

    passed = buffer.len == 3000 && buffer.cap >= buffer.len + 1;
    test_result(passed, "Output buffer grows to accommodate large writes");
    output_buffer_free(&buffer);
}

static void test_output_push_routes_printf(void) {
    capture_t       capture;
    output_t        output = { .write = capture_write, .opaque = &capture };
    const output_t *previous;
    int             passed = 0;

    capture_init(&capture);
    previous = output_push(&output);
    output_printf("alpha");
    err_printf(NULL, "beta");
    output_pop(previous);

    passed = capture.stdout_buffer.data != NULL &&
             capture.stderr_buffer.data != NULL &&
             strcmp(capture.stdout_buffer.data, "alpha") == 0 &&
             strcmp(capture.stderr_buffer.data, "beta") == 0;

    test_result(passed, "Current output route captures stdout and stderr formatting helpers");
    capture_free(&capture);
}

static void test_output_push_null_inherits_current(void) {
    capture_t       capture;
    output_t        output = { .write = capture_write, .opaque = &capture };
    const output_t *previous_outer;
    const output_t *previous_inner;
    int             passed = 0;

    capture_init(&capture);
    previous_outer = output_push(&output);
    previous_inner = output_push(NULL);
    out_printf(NULL, "outer");
    output_pop(previous_inner);
    output_pop(previous_outer);

    passed = capture.stdout_buffer.data != NULL &&
             strcmp(capture.stdout_buffer.data, "outer") == 0;

    test_result(passed, "Pushing NULL inherits the current output route");
    capture_free(&capture);
}

static void test_output_current_restores_after_pop(void) {
    capture_t       capture;
    output_t        output = { .write = capture_write, .opaque = &capture };
    const output_t *previous;
    int             passed = 0;

    capture_init(&capture);
    previous = output_push(&output);
    passed = output_current() == &output;
    output_pop(previous);
    passed = passed && output_current() == output_default();

    test_result(passed, "Output push/pop restores the previous route");
    capture_free(&capture);
}

static void test_output_write_ignores_empty_payloads(void) {
    capture_t capture;
    output_t  output = { .write = capture_write, .opaque = &capture };
    int       passed = 0;

    capture_init(&capture);
    output_write(&output, OUTPUT_STREAM_STDOUT, "", 0);
    output_write(&output, OUTPUT_STREAM_STDERR, NULL, 4);

    passed = capture.stdout_buffer.len == 0 &&
             capture.stderr_buffer.len == 0;

    test_result(passed, "Output write ignores empty and NULL payloads");
    capture_free(&capture);
}

int main(void) {
    printf("\n=== Output Buffer Tests ===\n\n");

    test_output_buffer_lifecycle();
    test_output_buffer_growth();
    test_output_push_routes_printf();
    test_output_push_null_inherits_current();
    test_output_current_restores_after_pop();
    test_output_write_ignores_empty_payloads();

    printf("\n=================================\n");
    printf("Tests passed: %d\nTests failed: %d\n", tests_passed, tests_failed);
    printf("=================================\n");

    return tests_failed > 0 ? 1 : 0;
}
