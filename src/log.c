#define OUTPUT_STDIO_REMAP

#include <time.h>
#include <stdio.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "log.h"
#include "output.h"
#include "linenoise.h"

static FILE *log_file = NULL;
static int log_to_file = 0;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t stdout_mutex = PTHREAD_MUTEX_INITIALIZER;
static char log_filename[256] = {0};

/*
 * Linenoise state for coordinating async output
 */
static struct linenoiseState *current_linenoise_state = NULL;
static pthread_mutex_t linenoise_state_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * SIGINT counter for double Ctrl+C confirmation
 */
static volatile sig_atomic_t sigint_count = 0;

/*
 * Initialize logging
 * logfile: path to log file (if NULL, logs fall back to stderr)
 * is_tty: controls whether interactive startup messages should be written
 *         alongside the normal file log
 */
void log_init(const char *logfile, int is_tty) {
    pthread_mutex_lock(&log_mutex);

    if (logfile != NULL) {
        strncpy(log_filename, logfile, sizeof(log_filename) - 1);
        log_filename[sizeof(log_filename) - 1] = '\0';

        log_file = fopen(logfile, "a");
        if (log_file == NULL) {
            fprintf(stderr, "Warning: Could not open log file %s, " "logging to stderr\n", logfile);
            log_to_file = 0;
        } else {
            /*
             * If a log file was opened successfully, always use it. Server
             * mode redirects stderr to /dev/null, so falling back to stderr
             * would silently discard daemon logs.
             */
            log_to_file = 1;
            // Disable buffering for log file to ensure immediate writes
            setbuf(log_file, NULL);

            /*
             * Keep the startup banner only for interactive TTY use so daemon
             * logs do not grow extra noise on every restart.
             */
            if (is_tty) {
                time_t     now = time(NULL);
                struct tm *tm_info = localtime(&now);
                char       time_buf[32];
                strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
                fprintf(log_file, "[%s] BGP Simulator started - logging to %s\n", time_buf, logfile);
            }
        }
    } else {
        log_to_file = 0;
    }

    pthread_mutex_unlock(&log_mutex);
}

/*
 * Close log file
 */
void log_close(void) {
    pthread_mutex_lock(&log_mutex);

    if (log_file != NULL) {
        fclose(log_file);
        log_file = NULL;
    }
    log_to_file = 0;

    pthread_mutex_unlock(&log_mutex);
}

/*
 * Log a message to file only (or stderr if no file is configured)
 * Thread-safe file logging with log_mutex.
 *
 * For terminal output, use log_terminal() instead.
 */
void log_write(const char *format, ...) {
    pthread_mutex_lock(&log_mutex);

    FILE *output = log_to_file ? log_file : stderr;

    if (output != NULL) {
        // Add timestamp
        time_t     now = time(NULL);
        struct tm *tm_info = localtime(&now);
        char       time_buf[32];
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

        fprintf(output, "[%s] ", time_buf);

        // Log the message
        va_list args;
        va_start(args, format);
        vfprintf(output, format, args);
        va_end(args);

        // Ensure newline if not present
        size_t len = strlen(format);
        if (len > 0 && format[len-1] != '\n') {
            fprintf(output, "\n");
        }

        fflush(output);
    }

    pthread_mutex_unlock(&log_mutex);
}

/*
 * Register the current linenoise state for async output coordination
 */
void register_linenoise(struct linenoiseState *state) {
    pthread_mutex_lock(&linenoise_state_mutex);
    current_linenoise_state = state;
    pthread_mutex_unlock(&linenoise_state_mutex);
}

/*
 * Unregister the linenoise state
 */
void unregister_linenoise(void) {
    pthread_mutex_lock(&linenoise_state_mutex);
    current_linenoise_state = NULL;
    pthread_mutex_unlock(&linenoise_state_mutex);
}

/*
 * Print event message to terminal only (not logged to file)
 * This function is for terminal-only output that should not be logged to file.
 * For most logging needs, use bgp_log() which writes to both file and terminal.
 *
 * Uses stdout_mutex to prevent message interleaving when multiple BGP router
 * threads output messages simultaneously. If linenoise is active, it hides
 * the prompt before printing and shows it after.
 */
void log_terminal(const char *format, ...) {
    pthread_mutex_lock(&stdout_mutex);

    // Hide linenoise prompt if active
    pthread_mutex_lock(&linenoise_state_mutex);
    struct linenoiseState *ln_state = current_linenoise_state;
    if (ln_state != NULL) {
        linenoiseHide(ln_state);
    }
    pthread_mutex_unlock(&linenoise_state_mutex);

    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    fflush(stdout);

    // Show linenoise prompt if it was hidden
    pthread_mutex_lock(&linenoise_state_mutex);
    if (ln_state != NULL && ln_state == current_linenoise_state) {
        linenoiseShow(ln_state);
    }
    pthread_mutex_unlock(&linenoise_state_mutex);

    pthread_mutex_unlock(&stdout_mutex);
}

/*
 * Lock stdout for atomic multi-line output
 */
void stdout_lock(void) {
    pthread_mutex_lock(&stdout_mutex);

    // Hide linenoise prompt if active
    pthread_mutex_lock(&linenoise_state_mutex);
    if (current_linenoise_state != NULL) {
        linenoiseHide(current_linenoise_state);
    }
    pthread_mutex_unlock(&linenoise_state_mutex);
}

/*
 * Unlock stdout after atomic multi-line output
 */
void stdout_unlock(void) {
    fflush(stdout);

    // Show linenoise prompt if it was hidden
    pthread_mutex_lock(&linenoise_state_mutex);
    if (current_linenoise_state != NULL) {
        linenoiseShow(current_linenoise_state);
    }
    pthread_mutex_unlock(&linenoise_state_mutex);

    pthread_mutex_unlock(&stdout_mutex);
}

/*
 * Show log lines (last N lines or all)
 * count: number of lines to show (0 = all)
 */
void show_log(int count) {
    show_log_with_output(count, NULL);
}

void show_log_with_output(int count, const output_t *output) {
    FILE           *fp;
    char          **lines = NULL;
    char            buffer[1024];
    int             line_count = 0;
    int             capacity = 100;
    const char     *filename;
    const output_t *previous_output = output_push(output);

    // Determine log file to use
    if (log_filename[0] != '\0') {
        filename = log_filename;
    } else {
        // Default to bgpsim.log even if not in TTY mode
        filename = "bgpsim.log";
    }

    fp = fopen(filename, "r");
    if (fp == NULL) {
        printf("\nLog file not found or empty: %s\n\n", filename);
        output_pop(previous_output);
        return;
    }

    // Allocate initial buffer for lines
    lines = (char **)malloc((size_t)capacity * sizeof(char *));
    if (lines == NULL) {
        fclose(fp);
        fprintf(stderr, "Memory allocation error\n");
        output_pop(previous_output);
        return;
    }

    // Read all lines into memory
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        // Expand buffer if needed
        if (line_count >= capacity) {
            capacity *= 2;
            char **new_lines = (char **)realloc(lines, (size_t)capacity * sizeof(char *));
            if (new_lines == NULL) {
                // Free existing lines
                for (int i = 0; i < line_count; i++) {
                    free(lines[i]);
                }
                free(lines);
                fclose(fp);
                fprintf(stderr, "Memory allocation error\n");
                output_pop(previous_output);
                return;
            }
            lines = new_lines;
        }

        // Store line
        lines[line_count] = strdup(buffer);
        if (lines[line_count] == NULL) {
            // Free existing lines
            for (int i = 0; i < line_count; i++) {
                free(lines[i]);
            }
            free(lines);
            fclose(fp);
            fprintf(stderr, "Memory allocation error\n");
            output_pop(previous_output);
            return;
        }
        line_count++;
    }

    fclose(fp);

    if (line_count == 0) {
        printf("\nLog file is empty\n\n");
        free(lines);
        output_pop(previous_output);
        return;
    }

    // Determine starting point
    int start = 0;
    if (count > 0 && count < line_count) {
        start = line_count - count;
    }

    // Lock stdout for atomic output
    stdout_lock();

    // Display header
    printf("\n");
    if (count == 0) {
        printf("=== All Log Entries (%d lines) ===\n", line_count);
    } else {
        printf("=== Last %d Log Entries ===\n", line_count - start);
    }
    printf("\n");

    // Display lines
    for (int i = start; i < line_count; i++) {
        printf("%s", lines[i]);
    }

    printf("\n");

    stdout_unlock();

    // Free memory
    for (int i = 0; i < line_count; i++) {
        free(lines[i]);
    }
    free(lines);
    output_pop(previous_output);
}

/*
 * Reset SIGINT counter (called after each CLI command)
 */
void reset_sigint_count(void) {
    sigint_count = 0;
}

/*
 * Get current SIGINT count
 */
int get_sigint_count(void) {
    return sigint_count;
}

/*
 * Increment SIGINT count (called by signal handler)
 */
void increment_sigint_count(void) {
    sigint_count++;
}
