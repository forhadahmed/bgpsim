#ifndef LOG_H
#define LOG_H

#include "output.h"

/*
 * Thread-Safe Logging System
 *
 * Provides separate, thread-safe logging to file and terminal with proper
 * mutex synchronization. Designed for multi-threaded applications.
 *
 * File Logging (log_file):
 *   - Uses log_mutex for thread-safe file writes
 *   - Writes timestamped messages to log file or stderr
 *   - Automatically adds newlines if missing
 *
 * Terminal Output (log_terminal):
 *   - Uses stdout_mutex for thread-safe terminal writes
 *   - Coordinates with linenoise for prompt management
 *   - Does NOT write to log file
 */

/*
 * Forward declaration for linenoise
 */
struct linenoiseState;

/*
 * Initialize logging system.
 * If logfile is provided, log_write() appends there regardless of TTY mode.
 * The is_tty flag only controls whether interactive startup messages belong in
 * the log file.
 */
void log_init(const char *logfile, int is_tty);

/*
 * Close logging system
 */
void log_close(void);

/*
 * Write to log file only (or stderr in non-TTY mode)
 * Thread-safe with log_mutex.
 */
void log_write(const char *format, ...) __attribute__((format(printf, 1, 2)));

/*
 * Write to terminal only (not logged to file)
 * Thread-safe with stdout_mutex.
 */
void log_terminal(const char *format, ...) __attribute__((format(printf, 1, 2)));

/*
 * Manual lock/unlock for atomic multi-line terminal output
 */
void stdout_lock(void);
void stdout_unlock(void);

/*
 * Register linenoise state for async output coordination
 */
void register_linenoise(struct linenoiseState *state);

/*
 * Unregister linenoise state
 */
void unregister_linenoise(void);

/*
 * Show log lines (last N lines or all)
 */
void show_log(int count);
void show_log_with_output(int count, const output_t *output);

/*
 * SIGINT handling for CLI
 */
void reset_sigint_count(void);
int get_sigint_count(void);
void increment_sigint_count(void);

// Convenience macro for compatibility
#define LOG_INFO(...) log_write(__VA_ARGS__)

#endif /* LOG_H */
