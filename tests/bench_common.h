#ifndef BENCH_COMMON_H
#define BENCH_COMMON_H

#include <time.h>
#include <stdio.h>

static inline double now_ms(void) {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

static inline void format_size(double bytes, char *buf, size_t buf_len) {
    if (bytes >= (1024.0 * 1024.0)) {
        snprintf(buf, buf_len, "%.2fmb", bytes / (1024.0 * 1024.0));
    } else {
        snprintf(buf, buf_len, "%.2fkb", bytes / 1024.0);
    }
}

static inline void format_time(double ms, char *buf, size_t buf_len) {
    if (ms < 1.0) {
        snprintf(buf, buf_len, "<1ms");
    } else {
        snprintf(buf, buf_len, "%.0fms", ms);
    }
}

#endif /* BENCH_COMMON_H */
