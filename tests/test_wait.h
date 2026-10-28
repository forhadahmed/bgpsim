/*
 * Waiting in C tests: check a condition at once, then again after a pause that
 * starts at 1 ms and doubles up to 50 ms, until a deadline. A test never sleeps for a fixed time and then asserts: it
 * waits for the state it needs, or for an event that orders after it (a barrier). The deadline is reached only when a
 * test fails, so it is generous enough for a loaded machine.
 */
#ifndef BGPSIM_TEST_WAIT_H
#define BGPSIM_TEST_WAIT_H

#include <time.h>
#include <stdint.h>
#include <unistd.h>

#define WAIT_TIMEOUT_MS     30000  /* Default deadline of a wait                    */
#define WAIT_FIRST_DELAY_US 1000   /* First pause between two checks of a condition */
#define WAIT_MAX_DELAY_US   50000  /* The pause doubles up to this                  */

static inline int64_t wait_now_ms(void) {
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

/*
 * Pause before the next check of a condition: delay_us, cut to what is left of the deadline, then double it up to
 * WAIT_MAX_DELAY_US. Returns 0 once the deadline has passed.
 */
static inline int wait_backoff(int64_t deadline_ms, useconds_t *delay_us) {
    int64_t left_ms = deadline_ms - wait_now_ms();

    if (left_ms <= 0) {
        return 0;
    }
    usleep((int64_t)*delay_us < left_ms * 1000 ? *delay_us : (useconds_t)(left_ms * 1000));
    *delay_us = *delay_us * 2 > WAIT_MAX_DELAY_US ? WAIT_MAX_DELAY_US : *delay_us * 2;
    return 1;
}

/*
 * Wait until predicate(opaque) holds or timeout_ms passes. Returns 1 when the predicate held.
 */
static inline int wait_until(int (*predicate)(void *opaque), void *opaque, int timeout_ms) {
    int64_t    deadline = wait_now_ms() + timeout_ms;
    useconds_t delay = WAIT_FIRST_DELAY_US;

    while (!predicate(opaque)) {
        if (!wait_backoff(deadline, &delay)) {
            return predicate(opaque);
        }
    }
    return 1;
}

#endif /* BGPSIM_TEST_WAIT_H */
