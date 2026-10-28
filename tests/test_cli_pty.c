/*
 * Interactive CLI PTY Tests
 * Exercises real linenoise TAB/? behavior through a PTY using data-driven
 * cases for both final line state and visible completion/help output.
 */

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include "util.h"
#include "parser.h"
#include "commands.h"
#include "linenoise.h"
#include "test_wait.h"
#include "test_result.h"

#define CHUNK(str) { str, sizeof(str) - 1 }

typedef struct {
    /*
     * One burst of keystrokes to inject. The next burst goes once the child has read all of this one and redrawn
     * (wait_editor_idle()).
     */
    const char *data;
    size_t      len;
} input_chunk_t;

typedef struct {
    /*
     * Simple transcript assertions keep the cases data-driven and make
     * failures readable without encoding display logic into test code.
     */
    const char *needle;
    int         should_exist;
} transcript_expectation_t;

typedef struct {
    /*
     * Each case describes an interactive edit session end-to-end:
     * starting mode, typed input bursts, final accepted line, and visible
     * transcript snippets that should (or should not) appear.
     */
    const char                     *name;
    cli_mode_t                      mode;
    config_mode_t                   config_mode;
    const input_chunk_t            *chunks;
    size_t                          chunk_count;
    const char                     *expected_result;
    const transcript_expectation_t *transcript_expectations;
    size_t                          transcript_expectation_count;
} pty_case_t;

static int write_all(int fd, const char *buf, size_t len) {
    while (len > 0) {
        ssize_t nwritten = write(fd, buf, len);
        if (nwritten < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        buf += nwritten;
        len -= (size_t)nwritten;
    }
    return 0;
}

static const char *prompt_for_session(cli_mode_t mode, config_mode_t config_mode) {
    /*
     * Match the no-context fallback prompts from cli.c so the harness can
     * validate mode-specific completion behavior without needing live router,
     * neighbor, or ribout objects.
     */
    if (mode == CLI_MODE_EXEC) {
        return BGPSIM "> ";
    }

    switch (config_mode) {
    case CONFIG_MODE_ROUTER_BGP:
        return BGPSIM "(config-router)# ";
    case CONFIG_MODE_NEIGHBOR:
        return BGPSIM "(config-neighbor)# ";
    case CONFIG_MODE_RIBOUT:
        return BGPSIM "(config-ribout)# ";
    case CONFIG_MODE_GLOBAL:
    default:
        return BGPSIM "(config)# ";
    }
}

static void respond_to_terminal_queries(int fd,
                                        const char *transcript,
                                        size_t transcript_len,
                                        size_t *query_scan_offset) {
    size_t scan_limit;
    size_t i;

    if (transcript_len < 4) {
        *query_scan_offset = 0;
        return;
    }

    /*
     * linenoise occasionally asks the terminal for cursor position using
     * ESC[6n while redrawing completions. If the harness misses that query,
     * the child looks "hung" even though the CLI logic is fine.
     *
     * Leave the last 3 bytes unconsumed so ESC[6n split across reads is seen
     * on the next append instead of being missed.
     */
    scan_limit = transcript_len - 4;
    i = *query_scan_offset;

    while (i <= scan_limit) {
        if (memcmp(transcript + i, "\x1b[6n", 4) == 0) {
            (void)write_all(fd, "\x1b[1;1R", 6);
            i += 4;
            continue;
        }
        i++;
    }

    *query_scan_offset = transcript_len - 3;
}

static int append_pty_output(int master_fd,
                             char *transcript,
                             size_t transcript_size,
                             size_t *transcript_len,
                             size_t *query_scan_offset,
                             int timeout_ms) {
    fd_set         readfds;
    struct timeval tv;

    FD_ZERO(&readfds);
    FD_SET(master_fd, &readfds);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int ready = select(master_fd + 1, &readfds, NULL, NULL, &tv);
    if (ready <= 0 || !FD_ISSET(master_fd, &readfds)) {
        return 0;
    }

    ssize_t nread = read(master_fd, transcript + *transcript_len, transcript_size - *transcript_len - 1);
    if (nread <= 0) {
        return 0;
    }

    *transcript_len += (size_t)nread;
    transcript[*transcript_len] = '\0';
    respond_to_terminal_queries(master_fd, transcript, *transcript_len, query_scan_offset);
    return 1;
}

static int wait_for_marker(int master_fd,
                           char *transcript,
                           size_t transcript_size,
                           size_t *transcript_len,
                           size_t *query_scan_offset,
                           const char *marker,
                           int timeout_ms) {
    int elapsed_ms = 0;

    // Keep polling until the expected prompt/result marker becomes visible.
    while (elapsed_ms <= timeout_ms) {
        if (strstr(transcript, marker) != NULL) {
            return 1;
        }
        if (!append_pty_output(master_fd, transcript, transcript_size,
                               transcript_len, query_scan_offset, 100)) {
            elapsed_ms += 100;
            continue;
        }
    }

    return strstr(transcript, marker) != NULL;
}

/*
 * The child is blocked reading its terminal: /proc/<pid>/syscall names the system call a sleeping task is in.
 * Without /proc (macOS), a short quiet window after the input drained stands in for it.
 */
#ifdef __linux__
#define IDLE_QUIET_MS 0
#else
#define IDLE_QUIET_MS 50
#endif
static int child_waits_in_read(pid_t pid) {
#ifndef __linux__
    (void)pid;
    return 1;
#else
    char  path[64];
    long  nr = -1;
    FILE *file;

    snprintf(path, sizeof(path), "/proc/%d/syscall", (int)pid);
    file = fopen(path, "r");
    if (file == NULL) {
        return 0;
    }
    if (fscanf(file, "%ld", &nr) != 1) {
        nr = -1;  /* "running" */
    }
    fclose(file);
    return nr == SYS_read;
#endif
}

typedef struct {
    pid_t   pid;
    int     master_fd;
    int     slave_fd;  /* The parent's descriptor of the child's terminal, to see what input waits for it */
    char   *transcript;
    size_t  transcript_size;
    size_t *transcript_len;
    size_t *query_scan_offset;
} editor_wait_t;

/*
 * The child has exited (it is not reaped here: run_edit_session() waits for it).
 */
static int child_exited(pid_t pid) {
    siginfo_t info;

    memset(&info, 0, sizeof(info));
    return waitid(P_PID, (id_t)pid, &info, WEXITED | WNOHANG | WNOWAIT) == 0 && info.si_pid == pid;
}

/*
 * Read all the output there is (answering terminal queries), then report whether the child has read all its input
 * and waits for more, with no new output: it has handled the last burst and redrawn. A child that has exited (after
 * the line that ends a case) has handled it too.
 */
static int editor_idle(void *opaque) {
    editor_wait_t *wait = opaque;
    int            queued = 0;

    while (append_pty_output(wait->master_fd, wait->transcript, wait->transcript_size, wait->transcript_len,
                             wait->query_scan_offset, 0)) {
    }
    if (child_exited(wait->pid)) {
        return 1;
    }
    return ioctl(wait->slave_fd, FIONREAD, &queued) == 0 && queued == 0 && child_waits_in_read(wait->pid) &&
           !append_pty_output(wait->master_fd, wait->transcript, wait->transcript_size, wait->transcript_len,
                              wait->query_scan_offset, IDLE_QUIET_MS);
}

static int extract_result_line(const char *transcript, char *result, size_t result_size) {
    const char *marker = strstr(transcript, "RESULT:");
    size_t      len;

    if (!marker || result_size == 0) {
        return 0;
    }

    marker += strlen("RESULT:");
    len = strcspn(marker, "\r\n");
    if (len >= result_size) {
        len = result_size - 1;
    }

    memcpy(result, marker, len);
    result[len] = '\0';
    return 1;
}

static int transcript_matches(const char *transcript,
                              const transcript_expectation_t *expectations,
                              size_t expectation_count) {
    for (size_t i = 0; i < expectation_count; i++) {
        int contains = strstr(transcript, expectations[i].needle) != NULL;
        if (contains != expectations[i].should_exist) {
            return 0;
        }
    }
    return 1;
}

static void child_edit_session(cli_mode_t mode, config_mode_t config_mode) {
    struct linenoiseState state;
    char                  buffer[MAX_LINE_LENGTH];
    char                 *line;
    const char           *prompt = prompt_for_session(mode, config_mode);

    /*
     * The child owns the real linenoise edit loop. The parent never calls
     * completion or parser helpers directly; it only drives this child
     * through the PTY and inspects what a user would have seen.
     */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    tab_completion_init(&mode);
    tab_completion_set_config_mode(config_mode);
    linenoiseSetCompletionCallback(tab_completion_callback);

    if (linenoiseEditStart(&state, STDIN_FILENO, STDOUT_FILENO,
                           buffer, sizeof(buffer), prompt) == -1) {
        _exit(2);
    }

    while (1) {
        line = linenoiseEditFeed(&state);
        /*
         * linenoiseEditMore means the current burst was consumed but the line
         * is still being edited. Keep feeding until Enter accepts a line.
         */
        if (line == linenoiseEditMore) {
            continue;
        }
        if (line == NULL) {
            linenoiseEditStop(&state);
            if (errno == EOVERFLOW) {
                printf("\nRESULT:<oversized input rejected>\n");
                _exit(0);
            }
            _exit(3);
        }

        linenoiseEditStop(&state);
        printf("\nRESULT:%s\n", line);
        fflush(stdout);
        free(line);
        _exit(0);
    }
}

static pid_t spawn_child_pty(const char *self_path,
                             const char *mode_arg,
                             const char *config_arg,
                             const struct winsize *ws,
                             int *master_fd_out,
                             int *slave_fd_out) {
    pid_t pid;
    int   master_fd;
    int   slave_fd;
    char *slave_name;

    master_fd = posix_openpt(O_RDWR | O_NOCTTY);
    if (master_fd < 0) {
        return -1;
    }

    if (grantpt(master_fd) != 0 || unlockpt(master_fd) != 0) {
        close(master_fd);
        return -1;
    }

    slave_name = ptsname(master_fd);
    if (slave_name == NULL) {
        close(master_fd);
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        close(master_fd);
        return -1;
    }

    if (pid == 0) {
        close(master_fd);
        if (setsid() < 0) {
            _exit(127);
        }

        slave_fd = open(slave_name, O_RDWR | O_NOCTTY);
        if (slave_fd < 0) {
            _exit(127);
        }

#ifdef TIOCSCTTY
        (void)ioctl(slave_fd, TIOCSCTTY, 0);
#endif
        if (ws != NULL) {
            (void)ioctl(slave_fd, TIOCSWINSZ, ws);
        }

        if (dup2(slave_fd, STDIN_FILENO) < 0 ||
            dup2(slave_fd, STDOUT_FILENO) < 0 ||
            dup2(slave_fd, STDERR_FILENO) < 0) {
            _exit(127);
        }

        if (slave_fd > STDERR_FILENO) {
            close(slave_fd);
        }

        execl(self_path, self_path, "--child", mode_arg, config_arg, (char *)NULL);
        _exit(127);
    }

    *master_fd_out = master_fd;
    *slave_fd_out = open(slave_name, O_RDWR | O_NOCTTY);
    return pid;
}

static int run_edit_session(const char *self_path,
                            cli_mode_t mode,
                            config_mode_t config_mode,
                            const input_chunk_t *chunks,
                            size_t chunk_count,
                            char *result,
                            size_t result_size,
                            char *transcript,
                            size_t transcript_size) {
    int         master_fd;
    int         slave_fd = -1;
    pid_t       pid;
    int         status = 0;
    size_t      transcript_len = 0;
    size_t      query_scan_offset = 0;
    char        mode_arg[16];
    char        config_arg[16];
    const char *prompt = prompt_for_session(mode, config_mode);
    struct winsize ws = {
        .ws_row = 24,
        .ws_col = 80,
        .ws_xpixel = 0,
        .ws_ypixel = 0
    };

    if (transcript_size == 0) {
        return 0;
    }

    /*
     * Parent side of the harness:
     * 1. Spawn a fresh copy of this binary in --child mode under a PTY.
     * 2. Wait for the expected prompt so raw mode/completion is live.
     * 3. Inject the case's input bursts.
     * 4. Read until the child prints RESULT:<accepted line>.
     */
    transcript[0] = '\0';
    snprintf(mode_arg, sizeof(mode_arg), "%d", mode);
    snprintf(config_arg, sizeof(config_arg), "%d", config_mode);

    pid = spawn_child_pty(self_path, mode_arg, config_arg, &ws, &master_fd, &slave_fd);
    if (pid < 0) {
        return 0;
    }
    editor_wait_t editor = {pid, master_fd, slave_fd, transcript, transcript_size, &transcript_len,
                            &query_scan_offset};

    if (slave_fd < 0 ||
        !wait_for_marker(master_fd, transcript, transcript_size,
                         &transcript_len, &query_scan_offset, prompt, WAIT_TIMEOUT_MS)) {
        kill(pid, SIGTERM);
        waitpid(pid, &status, 0);
        close(master_fd);
        if (slave_fd >= 0) {
            close(slave_fd);
        }
        return 0;
    }

    for (size_t i = 0; i < chunk_count; i++) {
        if (write_all(master_fd, chunks[i].data, chunks[i].len) < 0 ||
            !wait_until(editor_idle, &editor, WAIT_TIMEOUT_MS)) {
            kill(pid, SIGTERM);
            waitpid(pid, &status, 0);
            close(master_fd);
            close(slave_fd);
            return 0;
        }
    }
    close(slave_fd);  /* The terminal closes with the child, as it did before */

    if (!wait_for_marker(master_fd, transcript, transcript_size,
                         &transcript_len, &query_scan_offset, "RESULT:", WAIT_TIMEOUT_MS)) {
        kill(pid, SIGTERM);
        waitpid(pid, &status, 0);
        close(master_fd);
        return 0;
    }

    waitpid(pid, &status, 0);
    close(master_fd);

    return extract_result_line(transcript, result, result_size);
}

static void run_pty_case(const char *self_path, const pty_case_t *test_case) {
    char result[256];
    char transcript[8192];
    int got_result = run_edit_session(self_path,
                                      test_case->mode,
                                      test_case->config_mode,
                                      test_case->chunks,
                                      test_case->chunk_count,
                                      result, sizeof(result),
                                      transcript, sizeof(transcript));
    int result_matches = got_result &&
                         strcmp(result, test_case->expected_result) == 0;
    int transcript_matches_case = transcript_matches(
        transcript,
        test_case->transcript_expectations,
        test_case->transcript_expectation_count);
    int passed = result_matches && transcript_matches_case;

    if (!passed) {
        /*
         * When RESULT is missing, that usually means the child editor never
         * accepted the line or the PTY exchange stalled on a redraw query.
         * Dump the full transcript so future regressions are diagnosable.
         */
        fprintf(stderr, "%s transcript:\n%s\nresult='%s'\n",
                test_case->name, transcript, got_result ? result : "<none>");
    }

    test_result(passed, test_case->name);
}

int main(int argc, char *argv[]) {
    static const input_chunk_t ambiguous_help_case[] = {
        CHUNK("conf?"),
        CHUNK("ig\r"),
    };
    static const transcript_expectation_t ambiguous_help_expectations[] = {
        {BGPSIM "> ", 1},
        {"  config", 1},
        {"  configure", 1},
    };

    static const input_chunk_t preview_question_mark_case[] = {
        CHUNK("conf\t\t?"),
        CHUNK("terminal\r"),
    };
    static const transcript_expectation_t preview_question_mark_expectations[] = {
        {"  terminal", 1},
    };

    static const input_chunk_t preview_space_case[] = {
        CHUNK("conf\t\t "),
        CHUNK("terminal\r"),
    };

    static const input_chunk_t preview_character_case[] = {
        CHUNK("conf\t\tx\r"),
    };

    static const input_chunk_t preview_escape_case[] = {
        CHUNK("conf\t\t\x1b"),
        CHUNK("terminal\r"),
    };

    static const input_chunk_t optional_tail_case[] = {
        CHUNK("show log ?"),
        CHUNK("all\r"),
    };
    static const transcript_expectation_t optional_tail_expectations[] = {
        {"  <cr>", 1},
        {"  all", 1},
    };

    static const input_chunk_t configure_help_case[] = {
        CHUNK("configure ?"),
        CHUNK("terminal\r"),
    };
    static const transcript_expectation_t configure_help_expectations[] = {
        {"  terminal", 1},
    };

    static const input_chunk_t no_help_global_case[] = {
        CHUNK("no ?"),
        CHUNK("router bgp 65000\r"),
    };
    static const transcript_expectation_t no_help_global_expectations[] = {
        {BGPSIM "(config)# ", 1},
        {"  router", 1},
        {"  ribout", 1},
        {"  show", 0},
        {"  exit", 0},
        {"  end", 0},
    };

    static const input_chunk_t no_help_unsupported_case[] = {
        CHUNK("no ex?\r"),
    };
    static const transcript_expectation_t no_help_unsupported_expectations[] = {
        {"  exit", 0},
    };

    static const input_chunk_t config_tree_help_case[] = {
        CHUNK("?"),
        CHUNK("show bgp summary\r"),
    };
    static const transcript_expectation_t config_tree_help_expectations[] = {
        {BGPSIM "(config-neighbor)# ", 1},
        {"  address-family", 1},
        {"address-family commands", 1},
        {"  router", 1},
        {"  show", 1},
        {"show commands", 1},
    };

    static const input_chunk_t config_exec_help_case[] = {
        CHUNK("show bgp ?"),
        CHUNK("summary\r"),
    };
    static const transcript_expectation_t config_exec_help_expectations[] = {
        {"  summary", 1},
        {"  neighbors", 1},
        {"  neighbors    Show all BGP neighbors", 1},
    };

    static const input_chunk_t no_help_neighbor_case[] = {
        CHUNK("no ?"),
        CHUNK("router bgp 65000\r"),
    };
    static const transcript_expectation_t no_help_neighbor_expectations[] = {
        {BGPSIM "(config-neighbor)# ", 1},
        {"  advertise", 1},
        {"  router", 1},
        {"  show", 0},
        {"  exit", 0},
    };

    static const pty_case_t cases[] = {
        {
            "Ambiguous help preserves the raw buffer and lists both matches",
            CLI_MODE_EXEC,
            CONFIG_MODE_GLOBAL,
            ambiguous_help_case,
            sizeof(ambiguous_help_case) / sizeof(ambiguous_help_case[0]),
            "config",
            ambiguous_help_expectations,
            sizeof(ambiguous_help_expectations) /
                sizeof(ambiguous_help_expectations[0])
        },
        {
            "Question mark commits a TAB-cycled preview before showing help",
            CLI_MODE_EXEC,
            CONFIG_MODE_GLOBAL,
            preview_question_mark_case,
            sizeof(preview_question_mark_case) /
                sizeof(preview_question_mark_case[0]),
            "configure terminal",
            preview_question_mark_expectations,
            sizeof(preview_question_mark_expectations) /
                sizeof(preview_question_mark_expectations[0])
        },
        {
            "Space after an accepted completion does not double-insert",
            CLI_MODE_EXEC,
            CONFIG_MODE_GLOBAL,
            preview_space_case,
            sizeof(preview_space_case) / sizeof(preview_space_case[0]),
            "configure terminal",
            NULL,
            0
        },
        {
            "Ordinary characters commit the selected completion before insertion",
            CLI_MODE_EXEC,
            CONFIG_MODE_GLOBAL,
            preview_character_case,
            sizeof(preview_character_case) / sizeof(preview_character_case[0]),
            "configure x",
            NULL,
            0
        },
        {
            "Escape cancels the current completion preview",
            CLI_MODE_EXEC,
            CONFIG_MODE_GLOBAL,
            preview_escape_case,
            sizeof(preview_escape_case) / sizeof(preview_escape_case[0]),
            "confterminal",
            NULL,
            0
        },
        {
            "Optional-tail help lists both <cr> and the optional continuation",
            CLI_MODE_EXEC,
            CONFIG_MODE_GLOBAL,
            optional_tail_case,
            sizeof(optional_tail_case) / sizeof(optional_tail_case[0]),
            "show log all",
            optional_tail_expectations,
            sizeof(optional_tail_expectations) /
                sizeof(optional_tail_expectations[0])
        },
        {
            "Direct help after a complete keyword shows the next token",
            CLI_MODE_EXEC,
            CONFIG_MODE_GLOBAL,
            configure_help_case,
            sizeof(configure_help_case) / sizeof(configure_help_case[0]),
            "configure terminal",
            configure_help_expectations,
            sizeof(configure_help_expectations) /
                sizeof(configure_help_expectations[0])
        },
        {
            "Config-mode 'no ?' only lists commands that support negation",
            CLI_MODE_CONFIG,
            CONFIG_MODE_GLOBAL,
            no_help_global_case,
            sizeof(no_help_global_case) / sizeof(no_help_global_case[0]),
            "no router bgp 65000",
            no_help_global_expectations,
            sizeof(no_help_global_expectations) /
                sizeof(no_help_global_expectations[0])
        },
        {
            "Unsupported negated prefixes do not advertise completions",
            CLI_MODE_CONFIG,
            CONFIG_MODE_GLOBAL,
            no_help_unsupported_case,
            sizeof(no_help_unsupported_case) /
                sizeof(no_help_unsupported_case[0]),
            "no ex",
            no_help_unsupported_expectations,
            sizeof(no_help_unsupported_expectations) /
                sizeof(no_help_unsupported_expectations[0])
        },
        {
            "Config-mode '?' shows current, parent, and exec command roots",
            CLI_MODE_CONFIG,
            CONFIG_MODE_NEIGHBOR,
            config_tree_help_case,
            sizeof(config_tree_help_case) /
                sizeof(config_tree_help_case[0]),
            "show bgp summary",
            config_tree_help_expectations,
            sizeof(config_tree_help_expectations) /
                sizeof(config_tree_help_expectations[0])
        },
        {
            "Nested config-mode 'show bgp ?' exposes exec fallback continuations",
            CLI_MODE_CONFIG,
            CONFIG_MODE_NEIGHBOR,
            config_exec_help_case,
            sizeof(config_exec_help_case) /
                sizeof(config_exec_help_case[0]),
            "show bgp summary",
            config_exec_help_expectations,
            sizeof(config_exec_help_expectations) /
                sizeof(config_exec_help_expectations[0])
        },
        {
            "Nested config-mode 'no ?' shows reachable negated config commands only",
            CLI_MODE_CONFIG,
            CONFIG_MODE_NEIGHBOR,
            no_help_neighbor_case,
            sizeof(no_help_neighbor_case) /
                sizeof(no_help_neighbor_case[0]),
            "no router bgp 65000",
            no_help_neighbor_expectations,
            sizeof(no_help_neighbor_expectations) /
                sizeof(no_help_neighbor_expectations[0])
        }
    };

    /*
     * The same binary serves as both the parent harness and the interactive
     * child editor so the PTY path stays close to the shipped CLI code.
     */
    if (argc > 1 && strcmp(argv[1], "--child") == 0) {
        cli_mode_t    mode = CLI_MODE_EXEC;
        config_mode_t config_mode = CONFIG_MODE_GLOBAL;

        if (argc > 2) {
            mode = (cli_mode_t)atoi(argv[2]);
        }
        if (argc > 3) {
            config_mode = (config_mode_t)atoi(argv[3]);
        }

        child_edit_session(mode, config_mode);
        return 0;
    }

    printf("Interactive CLI PTY Tests\n");
    printf("=================================\n\n");

    /*
     * All interactive expectations live in the case table above. Adding new
     * CLI behaviors should normally mean appending one more row, not writing
     * more harness logic.
     */
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        run_pty_case(argv[0], &cases[i]);
    }

    char oversized[BGPSIM_COMMAND_SIZE + 32], result[128];
    memset(oversized, 'x', sizeof(oversized));
    oversized[sizeof(oversized) - 1] = '\r';
    input_chunk_t chunk = {oversized, sizeof(oversized)};
    char         *transcript = malloc(1024 * 1024);
    int rejected = transcript && run_edit_session(argv[0], CLI_MODE_EXEC, CONFIG_MODE_GLOBAL, &chunk, 1,
                                                  result, sizeof(result), transcript, 1024 * 1024) &&
                   strcmp(result, "<oversized input rejected>") == 0;
    test_result(rejected, "An oversized terminal paste cannot execute its truncated prefix");
    free(transcript);

    printf("\n=================================\n");
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    printf("=================================\n");

    return (tests_failed == 0) ? 0 : 1;
}
