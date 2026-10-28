#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include "output.h"

static void output_stdio_writer(void *opaque, output_stream_t stream, const char *data, size_t len) {
    FILE *file = stream == OUTPUT_STREAM_STDERR ? stderr : stdout;

    (void)opaque;

    if (len == 0) {
        return;
    }

    fwrite(data, 1, len, file);
    fflush(file);
}

static const output_t k_output_stdio = {
    .write = output_stdio_writer,
    .opaque = NULL
};

static _Thread_local const output_t *g_output_current = NULL;

const output_t *output_default(void) {
    return &k_output_stdio;
}

const output_t *output_current(void) {
    return g_output_current ? g_output_current : output_default();
}

const output_t *output_push(const output_t *output) {
    const output_t *previous_output = g_output_current;
    const output_t *effective_output = output ? output : output_current();

    g_output_current = effective_output;
    return previous_output;
}

void output_pop(const output_t *previous_output) {
    g_output_current = previous_output;
}

void output_write(const output_t *output, output_stream_t stream, const char *data, size_t len) {
    const output_t *effective_output = output ? output : output_current();

    if (!effective_output || !effective_output->write || !data || len == 0) {
        return;
    }

    effective_output->write(effective_output->opaque, stream, data, len);
}

static int output_vprintf(const output_t *output, output_stream_t stream, const char *format, va_list ap) {
    va_list ap_copy;
    int     len;
    char    stack_buf[1024];
    char   *heap_buf = NULL;
    char   *buf = stack_buf;
    size_t  buf_size = sizeof(stack_buf);

    va_copy(ap_copy, ap);
    len = vsnprintf(stack_buf, sizeof(stack_buf), format, ap_copy);
    va_end(ap_copy);

    if (len < 0) {
        return len;
    }

    if ((size_t)len >= sizeof(stack_buf)) {
        buf_size = (size_t)len + 1;
        heap_buf = malloc(buf_size);
        if (!heap_buf) {
            return -1;
        }

        va_copy(ap_copy, ap);
        vsnprintf(heap_buf, buf_size, format, ap_copy);
        va_end(ap_copy);
        buf = heap_buf;
    }

    output_write(output, stream, buf, (size_t)len);
    free(heap_buf);
    return len;
}

int output_stream_printf(const output_t *output, output_stream_t stream, const char *format, ...) {
    va_list ap;
    int     rc;

    va_start(ap, format);
    rc = output_vprintf(output, stream, format, ap);
    va_end(ap);
    return rc;
}

int out_printf(const output_t *output, const char *format, ...) {
    va_list ap;
    int     rc;

    va_start(ap, format);
    rc = output_vprintf(output, OUTPUT_STREAM_STDOUT, format, ap);
    va_end(ap);
    return rc;
}

int err_printf(const output_t *output, const char *format, ...) {
    va_list ap;
    int     rc;

    va_start(ap, format);
    rc = output_vprintf(output, OUTPUT_STREAM_STDERR, format, ap);
    va_end(ap);
    return rc;
}

int output_printf(const char *format, ...) {
    va_list ap;
    int     rc;

    va_start(ap, format);
    rc = output_vprintf(NULL, OUTPUT_STREAM_STDOUT, format, ap);
    va_end(ap);
    return rc;
}

int output_fprintf(FILE *file, const char *format, ...) {
    va_list ap;
    int     rc;

    va_start(ap, format);
    if (file == stdout) {
        rc = output_vprintf(NULL, OUTPUT_STREAM_STDOUT, format, ap);
    } else if (file == stderr) {
        rc = output_vprintf(NULL, OUTPUT_STREAM_STDERR, format, ap);
    } else {
        rc = vfprintf(file, format, ap);
        fflush(file);
    }
    va_end(ap);
    return rc;
}

int output_fputs(const char *s, FILE *file) {
    size_t len = s ? strlen(s) : 0;

    if (file == stdout) {
        output_write(NULL, OUTPUT_STREAM_STDOUT, s, len);
        return len > 0 ? 0 : EOF;
    }

    if (file == stderr) {
        output_write(NULL, OUTPUT_STREAM_STDERR, s, len);
        return len > 0 ? 0 : EOF;
    }

    return fputs(s, file);
}

int output_puts(const char *s) {
    if (s != NULL) {
        output_write(NULL, OUTPUT_STREAM_STDOUT, s, strlen(s));
    }
    output_write(NULL, OUTPUT_STREAM_STDOUT, "\n", 1);
    return 0;
}

int output_putchar(int ch) {
    unsigned char c = (unsigned char)ch;

    output_write(NULL, OUTPUT_STREAM_STDOUT, (const char *)&c, 1);
    return ch;
}

void output_buffer_init(output_buffer_t *buffer) {
    if (!buffer) {
        return;
    }

    buffer->data = NULL;
    buffer->len = 0;
    buffer->cap = 0;
}

void output_buffer_reset(output_buffer_t *buffer) {
    if (!buffer) {
        return;
    }

    buffer->len = 0;
    if (buffer->data) {
        buffer->data[0] = '\0';
    }
}

void output_buffer_free(output_buffer_t *buffer) {
    if (!buffer) {
        return;
    }

    free(buffer->data);
    buffer->data = NULL;
    buffer->len = 0;
    buffer->cap = 0;
}

void output_buffer_write(output_buffer_t *buffer, const char *data, size_t len) {
    size_t needed;
    size_t new_cap;
    char  *new_data;

    if (!buffer || !data || len == 0) {
        return;
    }

    needed = buffer->len + len + 1;
    if (needed > buffer->cap) {
        new_cap = buffer->cap ? buffer->cap : 256;
        while (new_cap < needed) {
            new_cap *= 2;
        }

        new_data = realloc(buffer->data, new_cap);
        if (!new_data) {
            return;
        }

        buffer->data = new_data;
        buffer->cap = new_cap;
    }

    memcpy(buffer->data + buffer->len, data, len);
    buffer->len += len;
    buffer->data[buffer->len] = '\0';
}
