#ifndef OUTPUT_H
#define OUTPUT_H

#include <stdio.h>
#include <stddef.h>

// Output Types

typedef enum {
    OUTPUT_STREAM_STDOUT = 1,
    OUTPUT_STREAM_STDERR = 2
} output_stream_t;

typedef struct output {
    void (*write)(void *opaque, output_stream_t stream, const char *data, size_t len);
    void *opaque;
} output_t;

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} output_buffer_t;

// Output Routing

const output_t *output_default(void);
const output_t *output_current(void);
/*
 * NULL inherits the current route; at top level it resolves to default stdio.
 */
const output_t *output_push(const output_t *output);
void output_pop(const output_t *previous_output);

void output_write(const output_t *output, output_stream_t stream, const char *data, size_t len);
int output_stream_printf(const output_t *output, output_stream_t stream, const char *format, ...)
    __attribute__((format(printf, 3, 4)));
int out_printf(const output_t *output, const char *format, ...) __attribute__((format(printf, 2, 3)));
int err_printf(const output_t *output, const char *format, ...) __attribute__((format(printf, 2, 3)));

int output_printf(const char *format, ...) __attribute__((format(printf, 1, 2)));
int output_fprintf(FILE *file, const char *format, ...) __attribute__((format(printf, 2, 3)));
int output_fputs(const char *s, FILE *file);
int output_puts(const char *s);
int output_putchar(int ch);

void output_buffer_init(output_buffer_t *buffer);
void output_buffer_reset(output_buffer_t *buffer);
void output_buffer_free(output_buffer_t *buffer);
void output_buffer_write(output_buffer_t *buffer, const char *data, size_t len);

#endif /* OUTPUT_H */

// Optional stdio remap

#ifdef OUTPUT_STDIO_REMAP
#define printf(...) output_printf(__VA_ARGS__)
#define fprintf(file, ...) output_fprintf((file), __VA_ARGS__)
#define fputs(str, file) output_fputs((str), (file))
#define puts(str) output_puts((str))
#define putchar(ch) output_putchar((ch))
#endif
