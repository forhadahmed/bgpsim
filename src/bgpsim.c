#include <poll.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "cli.h"
#include "log.h"
#include "util.h"
#include "bgpsim.h"
#include "parser.h"
#include "control.h"
#include "linenoise.h"

static volatile sig_atomic_t g_shutdown_requested = 0;

static void print_banner_field(int use_color, const char *label, const char *value) {
    const char *c_label = use_color ? CLR_CYAN : "";
    const char *c_reset = use_color ? CLR_RESET : "";

    if (!label || !value) {
        return;
    }

    printf("%s%s%s %s\n", c_label, label, c_reset, value);
}

static void print_banner(const char *mode, const char *session_name,
                         const char *logfile_path, const char *config_file,
                         const char *socket_path, pid_t pid) {
    int         use_color = terminal_color_enabled(0, isatty(STDOUT_FILENO));
    const char *c_name = use_color ? CLR_BLUE : "";
    const char *c_reset = use_color ? CLR_RESET : "";
    char        pid_buf[32];

    printf("\n%s[%s]%s\n\n", c_name, BGPSIM, c_reset);
    print_banner_field(use_color, "mode:", mode);
    print_banner_field(use_color, "session:", session_name);
    print_banner_field(use_color, "logs:", logfile_path);
    print_banner_field(use_color, "config:", config_file);
    print_banner_field(use_color, "socket:", socket_path);
    if (pid > 0) {
        snprintf(pid_buf, sizeof(pid_buf), "%d", (int)pid);
        print_banner_field(use_color, "pid:", pid_buf);
    }
    printf("\n");
}

static int bgpsim_is_client_exit_command(const char *line) {
    return strcmp(line, "quit") == 0 || strcmp(line, "disconnect") == 0;
}

static void bgpsim_signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        g_shutdown_requested = 1;
    }
}

static void bgpsim_control_stdout_cb(void *opaque, output_stream_t stream, const char *data, size_t len) {
    FILE *file = stream == OUTPUT_STREAM_STDERR ? stderr : stdout;

    (void)opaque;

    if (!data || len == 0) {
        return;
    }

    fwrite(data, 1, len, file);
    fflush(file);
}

static void bgpsim_client_event_cb(void *opaque, const char *data, size_t len) {
    (void)opaque;

    if (!data || len == 0) {
        return;
    }

    log_terminal("%.*s", (int)len, data);
}

static void bgpsim_control_ignore_event(void *opaque, const char *data, size_t len) {
    (void)opaque;
    (void)data;
    (void)len;
}

/*
 * Run one command (-e) on an attached session. Returns 1 when the command fails or the connection is lost, else 0.
 */
static int bgpsim_run_exec(bgpsim_control_client_t *client, const char *command) {
    cli_mode_t    mode = CLI_MODE_EXEC;
    cli_session_t session;
    int           status = 0;

    cli_session_init(&session);

    if (!command || bgpsim_is_client_exit_command(command)) {
        return 0;
    }

    if (bgpsim_control_client_execute(client, command, &mode, &session, bgpsim_control_stdout_cb,
                                      bgpsim_control_ignore_event, NULL, &status) != 0) {
        fprintf(stderr, "Error: Lost control connection\n");
        return 1;
    }

    return status != 0;
}

static int bgpsim_read_interactive_line(bgpsim_control_client_t *client, const char *prompt, cli_mode_t *mode,
                                        config_mode_t config_mode, char *buffer,
                                        size_t buffer_len, char **out_line) {
    struct linenoiseState ls;
    struct pollfd         pfds[2];
    int                   control_fd = bgpsim_control_client_fd(client);
    char                 *line = NULL;

    *out_line = NULL;
    if (linenoiseEditStart(&ls, STDIN_FILENO, STDOUT_FILENO, buffer, buffer_len, prompt) == -1) {
        return -1;
    }

    register_linenoise(&ls);
    tab_completion_init(mode);
    tab_completion_set_config_mode(config_mode);

    while (!g_shutdown_requested) {
        pfds[0].fd = STDIN_FILENO;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;
        pfds[1].fd = control_fd;
        pfds[1].events = POLLIN;
        pfds[1].revents = 0;

        if (poll(pfds, 2, -1) < 0) {
            if (errno == EINTR) {
                continue;
            }
            unregister_linenoise();
            linenoiseEditStop(&ls);
            return -1;
        }

        if (pfds[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            if (bgpsim_control_client_drain_events(client, bgpsim_client_event_cb, NULL) != 0) {
                unregister_linenoise();
                linenoiseEditStop(&ls);
                errno = ECONNRESET;
                return -1;
            }
        }

        if (pfds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            line = linenoiseEditFeed(&ls);
            if (line != linenoiseEditMore) {
                break;
            }
        }
    }

    unregister_linenoise();
    linenoiseEditStop(&ls);
    *out_line = line;
    return 0;
}

static int bgpsim_run_attached_repl(bgpsim_control_client_t *client, const char *session_name) {
    cli_mode_t    mode = CLI_MODE_EXEC;
    cli_session_t session;
    int           is_tty = isatty(STDIN_FILENO);

    cli_session_init(&session);

    if (is_tty) {
        linenoiseHistorySetMaxLen(100);
        linenoiseSetCompletionCallback(tab_completion_callback);
    }

    while (!g_shutdown_requested) {
        char  prompt[128];
        char  buffer[MAX_LINE_LENGTH];
        char *line = NULL;
        char *command;
        int   status = 0;

        cli_build_prompt(mode, &session, prompt, sizeof(prompt),
                         terminal_color_enabled(0, is_tty && isatty(STDOUT_FILENO)));

        if (is_tty) {
            if (bgpsim_read_interactive_line(client, prompt, &mode, session.config_mode, buffer,
                                             sizeof(buffer), &line) != 0) {
                if (errno == ECONNRESET) {
                    fprintf(stderr, "Error: Lost control connection\n");
                    return 1;
                }
                break;
            }

            if (line == NULL) {
                if (errno == EOVERFLOW) {
                    fprintf(stderr, "Error: command is too long (maximum %d bytes)\n", BGPSIM_COMMAND_SIZE - 1);
                    continue;
                }
                if (errno == EAGAIN) {
                    increment_sigint_count();
                    if (get_sigint_count() == 1) {
                        log_terminal("\n\n%s\n\n", BGPSIM_MSG_INTERRUPT_CONFIRM);
                        continue;
                    }
                    log_terminal("\n%s\n", BGPSIM_MSG_FORCE_SHUTDOWN);
                } else {
                    log_terminal("\n");
                }
                break;
            }

            if (line[0] != '\0') {
                linenoiseHistoryAdd(line);
            }
            command = line;
        } else {
            if (session_name) {
                cli_build_prompt(mode, &session, prompt, sizeof(prompt), 0);
                fputs(prompt, stdout);
                fflush(stdout);
            }

            size_t  capacity = 0;
            ssize_t length = getline(&line, &capacity, stdin);
            if (length < 0) {
                free(line);
                break;
            }
            if (length && line[length - 1] == '\n') line[--length] = '\0';
            if (length && line[length - 1] == '\r') line[--length] = '\0';
            if (!command_input_valid(line, (size_t)length)) {
                fprintf(stderr, "Error: invalid command input or command too long\n");
                free(line);
                continue;
            }
            command = line;
        }

        while (*command == ' ' || *command == '\t') {
            command++;
        }

        if (*command == '\0') {
            free(line);
            continue;
        }

        if (bgpsim_is_client_exit_command(command) || (mode == CLI_MODE_EXEC && strcmp(command, "exit") == 0)) {
            free(line);
            return 0;
        }

        if (bgpsim_control_client_execute(client, command, &mode, &session, bgpsim_control_stdout_cb,
                                          bgpsim_client_event_cb, NULL, &status) != 0) {
            free(line);
            fprintf(stderr, "Error: Lost control connection\n");
            return 1;
        }

        free(line);
        reset_sigint_count();
    }

    return 0;
}

static void bgpsim_print_usage(const char *argv0) {
    printf("Usage: %s [options] [config_file]\n", argv0);
    printf("\nOptions:\n");
    printf("  -s [name]       Run in server mode with optional session name\n");
    printf("  -c [name]       Attach to a running session\n");
    printf("  -e <command>    Execute one command over the control socket and exit\n");
    printf("  -l <file>       Explicit log file path\n");
    printf("  --passive       Enable passive listener support\n");
    printf("  -h, --help      Show this help message\n");
    printf("\nDefault config file: %s\n", BGPSIM_CONF_FILE);
}

int main(int argc, char *argv[]) {
    bgp_sim_t   sim;
    const char *config_file = BGPSIM_CONF_FILE;
    int         server_mode = 0;
    int         connect_mode = 0;
    int         passive_mode = 0;
    const char *exec_command = NULL;
    char        session_name[64] = BGPSIM;
    char        socket_path[256];
    char        logfile_path[256] = "";
    int         explicit_logfile = 0;
    int         session_name_set = 0;
    int         config_file_set = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            bgpsim_print_usage(argv[0]);
            return 0;
        }

        if (strcmp(argv[i], "-s") == 0) {
            server_mode = 1;
            continue;
        }

        if (strcmp(argv[i], "-c") == 0) {
            connect_mode = 1;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                strncpy(session_name, argv[++i], sizeof(session_name) - 1);
                session_name[sizeof(session_name) - 1] = '\0';
                session_name_set = 1;
            }
            continue;
        }

        if (strcmp(argv[i], "-e") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: -e requires a command string\n");
                return 1;
            }
            exec_command = argv[++i];
            continue;
        }

        if (strcmp(argv[i], "-l") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: -l requires a log file path\n");
                return 1;
            }
            strncpy(logfile_path, argv[++i], sizeof(logfile_path) - 1);
            logfile_path[sizeof(logfile_path) - 1] = '\0';
            explicit_logfile = 1;
            continue;
        }

        if (strcmp(argv[i], "--passive") == 0) {
            passive_mode = 1;
            continue;
        }

        if (connect_mode && !session_name_set) {
            strncpy(session_name, argv[i], sizeof(session_name) - 1);
            session_name[sizeof(session_name) - 1] = '\0';
            session_name_set = 1;
            continue;
        }

        if (server_mode && !session_name_set && argv[i][0] != '-' && strstr(argv[i], ".conf") == NULL) {
            strncpy(session_name, argv[i], sizeof(session_name) - 1);
            session_name[sizeof(session_name) - 1] = '\0';
            session_name_set = 1;
            continue;
        }

        if (!config_file_set) {
            config_file = argv[i];
            config_file_set = 1;
            continue;
        }

        fprintf(stderr, "Error: Unexpected argument: %s\n", argv[i]);
        return 1;
    }

    if (server_mode && connect_mode) {
        fprintf(stderr, "Error: -s and -c are mutually exclusive\n");
        return 1;
    }

    if (exec_command && !connect_mode) {
        fprintf(stderr, "Error: -e is only supported with -c\n");
        return 1;
    }

    if (connect_mode && config_file_set) {
        fprintf(stderr, "Error: Connect mode does not accept a config file\n");
        return 1;
    }

    bgpsim_control_build_socket_path(session_name, socket_path, sizeof(socket_path));

    if (connect_mode) {
        bgpsim_control_client_t client;
        int                     rc;

        if (bgpsim_control_client_open(&client, socket_path) != 0) {
            fprintf(stderr, "Error: Failed to connect to session '%s' at %s: %s\n", session_name, socket_path,
                    strerror(errno));
            return 1;
        }

        if (!exec_command && isatty(STDIN_FILENO)) {
            print_banner("connect", session_name, NULL, NULL, socket_path, 0);
        }

        rc = exec_command ? bgpsim_run_exec(&client, exec_command) : bgpsim_run_attached_repl(&client, session_name);
        bgpsim_control_client_close(&client);
        return rc;
    }

    if (!explicit_logfile) {
        if (server_mode && strcmp(session_name, BGPSIM) != 0) {
            snprintf(logfile_path, sizeof(logfile_path), "/tmp/" BGPSIM "_%s.log", session_name);
        } else {
            snprintf(logfile_path, sizeof(logfile_path), "%s", BGPSIM_LOG_PATH);
        }
    }

    if (check_socket_active(socket_path)) {
        fprintf(stderr, "Error: Session '%s' is already running\n", session_name);
        fprintf(stderr, "Socket: %s\n", socket_path);
        return 1;
    }

    if (server_mode) {
        pid_t pid = fork();

        if (pid < 0) {
            fprintf(stderr, "Error: Failed to fork daemon process\n");
            return 1;
        }

        if (pid > 0) {
            print_banner(passive_mode ? "active + passive" : "active",
                         session_name, logfile_path, NULL, socket_path, pid);
            return 0;
        }

        if (setsid() < 0 || chdir("/") < 0) {
            return 1;
        }

        {
            int nullfd = open("/dev/null", O_RDWR);
            int logfd = open(logfile_path, O_WRONLY | O_CREAT | O_APPEND, 0644);

            if (nullfd >= 0) {
                (void)dup2(nullfd, STDIN_FILENO);
            }
            if (logfd >= 0) {
                (void)dup2(logfd, STDOUT_FILENO);
                (void)dup2(logfd, STDERR_FILENO);
            } else if (nullfd >= 0) {
                (void)dup2(nullfd, STDOUT_FILENO);
                (void)dup2(nullfd, STDERR_FILENO);
            }
            if (logfd > 2) {
                close(logfd);
            }
            if (nullfd > 2) {
                close(nullfd);
            }
        }
    }

    signal(SIGINT, bgpsim_signal_handler);
    signal(SIGTERM, bgpsim_signal_handler);

    log_init(logfile_path, !server_mode && isatty(STDIN_FILENO));

    if (!server_mode && isatty(STDIN_FILENO)) {
        print_banner(passive_mode ? "active + passive" : "active", session_name, logfile_path, config_file, NULL, 0);
    }

    bgp_init_simulator(&sim);
    sim.passive_mode = passive_mode;

    if (access(config_file, F_OK) == 0) {
        if (parse_config_file(config_file, &sim) < 0) {
            fprintf(stderr, "Warning: Failed to parse configuration file '%s'\n", config_file);
        }
    } else if (!server_mode) {
        printf("%s not found. Use 'config' to get started.\n\n", config_file);
    }

    if (bgpsim_control_init(&sim, socket_path) != 0) {
        fprintf(stderr, "Error: Failed to start runtime/control server: %s\n", strerror(errno));
        bgp_shutdown_sim(&sim);
        log_close();
        return 1;
    }

    if (server_mode) {
        while (!sim.shutdown && !g_shutdown_requested) {
            sleep(1);
        }
        bgpsim_control_shutdown();
    } else {
        bgpsim_control_client_t client;
        int                     rc;

        if (bgpsim_control_client_open(&client, socket_path) != 0) {
            fprintf(stderr, "Error: Failed to attach local client: %s\n", strerror(errno));
            bgpsim_control_shutdown();
            bgp_shutdown_sim(&sim);
            log_close();
            return 1;
        }

        rc = bgpsim_run_attached_repl(&client, session_name);
        bgpsim_control_client_close(&client);
        bgpsim_control_shutdown();
        bgp_shutdown_sim(&sim);
        log_close();
        return rc;
    }

    bgp_shutdown_sim(&sim);
    log_close();
    return 0;
}
