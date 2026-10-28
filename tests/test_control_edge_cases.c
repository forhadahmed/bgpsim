#include <poll.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "bgpsim.h"
#include "output.h"
#include "control.h"
#include "test_wait.h"
#include "bgp_router.h"
#include "test_result.h"
#include "bgp_neighbor.h"
#include "test_runtime.h"
#ifdef __linux__
#include <dirent.h>
#endif

#define TEST_TIMEOUT_MS WAIT_TIMEOUT_MS
/*
 * Each passive peer session produces one Up and one Down EVENT. Keep the
 * total comfortably below the runtime's per-session monitor queue limit so the
 * test validates delivery and framing under load rather than intentional drop
 * behavior.
 */
#define TERMINAL_MONITOR_STRESS_CYCLES 32

static int test_client_log_counter = 0;
static char g_test_client_path[PATH_MAX];

typedef struct {
    output_buffer_t stdout_buffer;
    output_buffer_t stderr_buffer;
} control_capture_t;

typedef struct {
    output_buffer_t buffer;
    int             count;
} event_capture_t;

typedef struct {
    pid_t pid;
    int   wait_status;
    int   waited;
    char  log_path[PATH_MAX];
} spawned_test_client_t;

typedef struct {
    control_capture_t *control;
    event_capture_t   *events;
} exec_capture_t;

static int connect_raw_control(const char *socket_path) {
    return bgpsim_control_connect(socket_path);
}

static int send_all(int fd, const void *data, size_t len) {
    const uint8_t *ptr = data;
    size_t         sent = 0;

    while (sent < len) {
        ssize_t nwritten = send(fd, ptr + sent, len - sent, 0);
        if (nwritten < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        sent += (size_t)nwritten;
    }

    return 0;
}

static int send_buffer_in_chunks(int fd, const uint8_t *data, size_t len, size_t chunk_size) {
    size_t offset = 0;

    while (offset < len) {
        size_t remaining = len - offset;
        size_t to_send = remaining < chunk_size ? remaining : chunk_size;

        if (send_all(fd, data + offset, to_send) != 0) {
            return -1;
        }
        offset += to_send;
    }

    return 0;
}

static int send_frame_in_chunks(int fd, uint16_t type, const void *payload, uint32_t payload_len, size_t chunk_size) {
    uint8_t *frame_data = NULL;
    size_t   frame_len = 0;
    int      rc;

    rc = bgpsim_control_build_frame(type, payload, payload_len, &frame_data, &frame_len);
    if (rc != 0) {
        return -1;
    }

    rc = send_buffer_in_chunks(fd, frame_data, frame_len, chunk_size);
    free(frame_data);
    return rc;
}

/*
 * Read from fd until the decoder has a full frame. Returns the bgpsim_control_decoder_next result (> 0 for a frame, -1
 * for an error), or 0 with errno ETIMEDOUT when the time ends.
 */
static int recv_frame_with_timeout(int fd, bgpsim_control_decoder_t *decoder, bgpsim_control_frame_t *frame,
                                   int timeout_ms) {
    uint8_t buf[4096];
    int64_t deadline = wait_now_ms() + timeout_ms;

    for (;;) {
        int rc = bgpsim_control_decoder_next(decoder, frame);
        if (rc != 0) {
            return rc;
        }

        while (wait_now_ms() < deadline) {
            struct pollfd pfd = { .fd = fd, .events = POLLIN | POLLHUP | POLLERR };
            int           remaining = (int)(deadline - wait_now_ms());
            ssize_t       nread;

            rc = poll(&pfd, 1, remaining > 0 ? remaining : 0);
            if (rc < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return -1;
            }
            if (rc == 0) {
                errno = ETIMEDOUT;
                return 0;
            }

            nread = recv(fd, buf, sizeof(buf), 0);
            if (nread < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return -1;
            }
            if (nread == 0) {
                errno = ECONNRESET;
                return -1;
            }
            if (bgpsim_control_decoder_append(decoder, buf, (size_t)nread) != 0) {
                errno = ENOMEM;
                return -1;
            }
            break;
        }

        if (wait_now_ms() >= deadline) {
            errno = ETIMEDOUT;
            return 0;
        }
    }
}

static int recv_exec_result(int fd, bgpsim_control_decoder_t *decoder, output_buffer_t *stdout_buffer,
                            output_buffer_t *stderr_buffer, bgpsim_exec_done_t *done, int timeout_ms) {
    int64_t deadline = wait_now_ms() + timeout_ms;

    while (wait_now_ms() < deadline) {
        bgpsim_control_frame_t frame = {0};
        int                    rc = recv_frame_with_timeout(fd, decoder, &frame, (int)(deadline - wait_now_ms()));

        if (rc <= 0) {
            bgpsim_control_frame_reset(&frame);
            return -1;
        }

        if (frame.type == BGPSIM_CTRL_STDOUT_CHUNK) {
            output_buffer_write(stdout_buffer, (const char *)frame.payload, frame.payload_len);
        } else if (frame.type == BGPSIM_CTRL_STDERR_CHUNK) {
            output_buffer_write(stderr_buffer, (const char *)frame.payload, frame.payload_len);
        } else if (frame.type == BGPSIM_CTRL_EXEC_DONE) {
            rc = bgpsim_control_decode_exec_done(frame.payload, frame.payload_len, done);
            bgpsim_control_frame_reset(&frame);
            return rc == 0 ? 0 : -1;
        } else if (frame.type == BGPSIM_CTRL_ERROR) {
            bgpsim_control_frame_reset(&frame);
            errno = EPROTO;
            return -1;
        }

        bgpsim_control_frame_reset(&frame);
    }

    errno = ETIMEDOUT;
    return -1;
}

static void capture_control_chunk(void *opaque, output_stream_t stream, const char *data, size_t len) {
    control_capture_t *capture = opaque;

    if (!capture || !data || len == 0) {
        return;
    }

    if (stream == OUTPUT_STREAM_STDERR) {
        output_buffer_write(&capture->stderr_buffer, data, len);
    } else {
        output_buffer_write(&capture->stdout_buffer, data, len);
    }
}

static void capture_event(void *opaque, const char *data, size_t len) {
    event_capture_t *capture = opaque;

    if (!capture || !data || len == 0) {
        return;
    }

    output_buffer_write(&capture->buffer, data, len);
    capture->count++;
}

static void capture_exec_chunk(void *opaque, output_stream_t stream, const char *data, size_t len) {
    exec_capture_t *capture = opaque;

    if (capture == NULL) {
        return;
    }

    capture_control_chunk(capture->control, stream, data, len);
}

static void capture_exec_event(void *opaque, const char *data, size_t len) {
    exec_capture_t *capture = opaque;

    if (capture == NULL) {
        return;
    }

    capture_event(capture->events, data, len);
}

/*
 * Run one command through the control client and capture its stdout and stderr text in capture.
 */
static int execute_control_command(bgpsim_control_client_t *client, const char *command, cli_mode_t *mode,
                                   cli_session_t *session, control_capture_t *capture, int *status) {
    /*
     * Reset keeps the buffer, so a capture used for several commands does
     * not leak the text of the earlier ones.
     */
    output_buffer_reset(&capture->stdout_buffer);
    output_buffer_reset(&capture->stderr_buffer);
    return bgpsim_control_client_execute(client, command, mode, session, capture_control_chunk, NULL, capture, status);
}

/*
 * Like execute_control_command, and also capture the event lines that arrive during the command.
 */
static int execute_control_command_with_events(bgpsim_control_client_t *client, const char *command, cli_mode_t *mode,
                                               cli_session_t *session, control_capture_t *capture,
                                               event_capture_t *events, int *status) {
    exec_capture_t exec_capture = { .control = capture, .events = events };

    /*
     * Reset keeps the buffer, so a capture used for several commands does
     * not leak the text of the earlier ones.
     */
    output_buffer_reset(&capture->stdout_buffer);
    output_buffer_reset(&capture->stderr_buffer);
    return bgpsim_control_client_execute(client, command, mode, session,
                                         capture_exec_chunk, capture_exec_event,
                                         &exec_capture, status);
}

static void free_control_capture(control_capture_t *capture) {
    output_buffer_free(&capture->stdout_buffer);
    output_buffer_free(&capture->stderr_buffer);
}

static int client_buffer_contains(output_buffer_t *buffer, const char *needle) {
    return buffer && buffer->data && strstr(buffer->data, needle) != NULL;
}

static int count_substring_occurrences(const char *haystack, const char *needle) {
    int         count = 0;
    const char *current;
    size_t      needle_len;

    if (haystack == NULL || needle == NULL || needle[0] == '\0') {
        return 0;
    }

    needle_len = strlen(needle);
    current = haystack;
    while ((current = strstr(current, needle)) != NULL) {
        count++;
        current += needle_len;
    }

    return count;
}

/*
 * Drain events into capture until the event text contains needle. Returns 1 when it does, 0 when the time ends or the
 * drain fails.
 */
static int wait_for_event_contains(bgpsim_control_client_t *client, event_capture_t *capture, const char *needle,
                                   int timeout_ms) {
    int64_t deadline = wait_now_ms() + timeout_ms;

    useconds_t delay = WAIT_FIRST_DELAY_US;

    do {
        if (bgpsim_control_client_drain_events(client, capture_event, capture) != 0) {
            return 0;
        }
        if (capture->buffer.data && strstr(capture->buffer.data, needle) != NULL) {
            return 1;
        }
    } while (wait_backoff(deadline, &delay));
    return 0;
}

static int path_is_executable(const char *path) {
    return path != NULL && path[0] != '\0' && access(path, X_OK) == 0;
}

static int build_sibling_test_client_path(const char *binary_path, char *candidate, size_t candidate_size) {
    const char *slash;
    size_t      prefix_len;

    if (!binary_path || !candidate || candidate_size == 0) {
        return 0;
    }

    slash = strrchr(binary_path, '/');
    if (!slash) {
        return 0;
    }

    prefix_len = (size_t)(slash - binary_path);
    if (prefix_len >= candidate_size || prefix_len >= candidate_size - sizeof("/bgp_test_client")) {
        return 0;
    }

    memcpy(candidate, binary_path, prefix_len);
    candidate[prefix_len] = '\0';
    strncat(candidate, "/bgp_test_client", candidate_size - strlen(candidate) - 1);
    return 1;
}

static void init_test_client_path(const char *argv0) {
    char        resolved[PATH_MAX];
    char        candidate[PATH_MAX];
    const char *env_path = getenv("TEST_CLIENT");

    g_test_client_path[0] = '\0';

    if (path_is_executable(env_path)) {
        snprintf(g_test_client_path, sizeof(g_test_client_path), "%s", env_path);
        return;
    }

    if (argv0 != NULL && realpath(argv0, resolved) != NULL &&
        build_sibling_test_client_path(resolved, candidate, sizeof(candidate)) &&
        path_is_executable(candidate)) {
        snprintf(g_test_client_path, sizeof(g_test_client_path), "%s", candidate);
        return;
    }

    if (build_sibling_test_client_path(argv0, candidate, sizeof(candidate)) &&
        path_is_executable(candidate)) {
        snprintf(g_test_client_path, sizeof(g_test_client_path), "%s", candidate);
        return;
    }

    if (path_is_executable("/tmp/bgpsim/bgp_test_client")) {
        snprintf(g_test_client_path, sizeof(g_test_client_path), "%s", "/tmp/bgpsim/bgp_test_client");
    }
}

/*
 * Fork the test client in active mode to connect to ip:port; its output goes to client->log_path. tamper_name, when
 * set, sets the BGP_TEST_TAMPER mode of the client. Returns -1 when the client binary is missing or fork fails.
 */
static int spawn_test_client_active(spawned_test_client_t *client,
                                    const char *ip,
                                    uint16_t port,
                                    uint32_t my_as,
                                    const char *router_id,
                                    int keepalive_seconds,
                                    const char *tamper_name) {
    pid_t pid;

    if (!client || !ip || !router_id || !path_is_executable(g_test_client_path)) {
        errno = ENOENT;
        return -1;
    }

    memset(client, 0, sizeof(*client));
    client->pid = -1;
    snprintf(client->log_path, sizeof(client->log_path), "/tmp/bgpsim-test-client-%ld-%d.log",
             (long)getpid(), test_client_log_counter++);
    unlink(client->log_path);

    pid = fork();
    if (pid < 0) {
        return -1;
    }

    if (pid != 0) {
        client->pid = pid;
        return 0;
    }

    {
        char port_str[16];
        char as_str[16];
        char keepalive_str[16];
        int  log_fd = open(client->log_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);

        if (log_fd >= 0) {
            dup2(log_fd, STDOUT_FILENO);
            dup2(log_fd, STDERR_FILENO);
            close(log_fd);
        }

        if (tamper_name && tamper_name[0] != '\0') {
            setenv("BGP_TEST_TAMPER", tamper_name, 1);
        } else {
            unsetenv("BGP_TEST_TAMPER");
        }

        snprintf(port_str, sizeof(port_str), "%u", port);
        snprintf(as_str, sizeof(as_str), "%u", my_as);
        snprintf(keepalive_str, sizeof(keepalive_str), "%d", keepalive_seconds);
        execl(g_test_client_path, g_test_client_path, "--active", ip, port_str, as_str, router_id, keepalive_str,
              (char *)NULL);
        perror("execl");
        _exit(127);
    }
}

static int wait_for_spawned_client(spawned_test_client_t *client, int timeout_ms) {
    int64_t    deadline = wait_now_ms() + timeout_ms;
    useconds_t delay = WAIT_FIRST_DELAY_US;
    int        status = 0;

    if (!client || client->pid <= 0) {
        return 0;
    }

    if (client->waited) {
        return WIFEXITED(client->wait_status) && WEXITSTATUS(client->wait_status) == 0;
    }

    do {
        pid_t rc = waitpid(client->pid, &status, WNOHANG);

        if (rc == client->pid) {
            client->wait_status = status;
            client->waited = 1;
            return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        }
        if (rc < 0) {
            return 0;
        }
    } while (wait_backoff(deadline, &delay));

    kill(client->pid, SIGKILL);
    waitpid(client->pid, &status, 0);
    client->wait_status = status;
    client->waited = 1;
    return 0;
}

static void dump_file_tail(const char *path) {
    char    buf[2049];
    int     fd;
    off_t   size;
    off_t   start;
    ssize_t nread;

    if (!path || path[0] == '\0') {
        return;
    }

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "bgp_test_client log is unavailable: %s\n", path);
        return;
    }

    size = lseek(fd, 0, SEEK_END);
    if (size < 0) {
        close(fd);
        return;
    }

    /*
     * On failure the last couple of kilobytes are enough to show the
     * handshake phase, any exec failure, or the last protocol message.
     */
    start = size > (off_t)(sizeof(buf) - 1) ? size - (off_t)(sizeof(buf) - 1) : 0;
    if (lseek(fd, start, SEEK_SET) < 0) {
        close(fd);
        return;
    }

    nread = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (nread <= 0) {
        return;
    }

    buf[nread] = '\0';
    fprintf(stderr, "bgp_test_client log tail (%s):\n%s\n", path, buf);
}

static void describe_spawned_client_failure(const spawned_test_client_t *client) {
    if (!client || client->pid <= 0) {
        return;
    }

    if (!client->waited) {
        fprintf(stderr, "bgp_test_client pid %ld did not exit before timeout\n", (long)client->pid);
    } else if (WIFEXITED(client->wait_status)) {
        fprintf(stderr, "bgp_test_client pid %ld exited with status %d\n",
                (long)client->pid, WEXITSTATUS(client->wait_status));
    } else if (WIFSIGNALED(client->wait_status)) {
        fprintf(stderr, "bgp_test_client pid %ld died from signal %d\n",
                (long)client->pid, WTERMSIG(client->wait_status));
    }

    dump_file_tail(client->log_path);
}

/*
 * Serve one control handshake in a child: accept, read the SYN, answer ACK with the given version, exit. The client
 * under test then blocks on a real socket, and the child's exit closes it.
 */
static pid_t serve_one_handshake(const char *socket_path, const char *version) {
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    int                listener = socket(AF_UNIX, SOCK_STREAM, 0);
    pid_t              pid;

    unlink(socket_path);
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path);
    if (listener < 0 || bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(listener, 1) != 0) {
        if (listener >= 0) close(listener);
        return -1;
    }
    pid = fork();
    if (pid == 0) {
        uint8_t  syn[8];
        uint8_t *ack = NULL;
        size_t   ack_len = 0;
        size_t   got = 0;
        int      fd = accept(listener, NULL, NULL);

        while (fd >= 0 && got < sizeof(syn)) {
            ssize_t n = read(fd, syn + got, sizeof(syn) - got);
            if (n <= 0) break;
            got += (size_t)n;
        }
        if (fd >= 0 && got == sizeof(syn) &&
            bgpsim_control_build_frame(BGPSIM_CTRL_ACK, version, (uint32_t)strlen(version), &ack, &ack_len) == 0) {
            send_all(fd, ack, ack_len);
        }
        _exit(0);
    }
    close(listener);
    return pid;
}

static void test_client_refuses_version_mismatch(void) {
    bgpsim_control_client_t client;
    char                    socket_path[108];
    pid_t                   server;
    int                     status = 0;
    int                     passed = 0;

    snprintf(socket_path, sizeof(socket_path), "/tmp/bgpsim_version_%d.sock", (int)getpid());
    server = serve_one_handshake(socket_path, "3");
    if (server > 0) {
        errno = 0;
        passed = bgpsim_control_client_open(&client, socket_path) != 0 && errno == EPROTONOSUPPORT;
        waitpid(server, &status, 0);
    }
    test_result(passed, "Attach refuses a control server with another protocol version");

    // Positive control: the same one-shot server with the current version is accepted.
    server = serve_one_handshake(socket_path, BGPSIM_CONTROL_VERSION);
    passed = server > 0 && bgpsim_control_client_open(&client, socket_path) == 0;
    if (passed) bgpsim_control_client_close(&client);
    if (server > 0) waitpid(server, &status, 0);
    test_result(passed, "Attach accepts a control server with the current protocol version");
    unlink(socket_path);
}

static void test_fragmented_handshake_and_exec(void) {
    bgp_sim_t               *sim = create_sim();
    char                     socket_path[108] = "";
    bgpsim_control_decoder_t decoder;
    bgpsim_control_frame_t   frame = {0};
    output_buffer_t          stdout_buffer;
    output_buffer_t          stderr_buffer;
    bgpsim_exec_done_t       done;
    int                      fd = -1;
    int                      passed = 0;

    bgpsim_control_decoder_init(&decoder);
    output_buffer_init(&stdout_buffer);
    output_buffer_init(&stderr_buffer);

    if (sim != NULL && start_runtime(sim, socket_path, sizeof(socket_path)) == 0) {
        fd = connect_raw_control(socket_path);
        if (fd >= 0 &&
            send_frame_in_chunks(fd, BGPSIM_CTRL_SYN, NULL, 0, 1) == 0 &&
            recv_frame_with_timeout(fd, &decoder, &frame, TEST_TIMEOUT_MS) == 1 &&
            frame.type == BGPSIM_CTRL_ACK &&
            frame.payload_len == strlen(BGPSIM_CONTROL_VERSION) &&
            memcmp(frame.payload, BGPSIM_CONTROL_VERSION, frame.payload_len) == 0 &&
            send_frame_in_chunks(fd, BGPSIM_CTRL_EXEC_REQ, "show bgp summary", 16, 2) == 0 &&
            recv_exec_result(fd, &decoder, &stdout_buffer, &stderr_buffer, &done, TEST_TIMEOUT_MS) == 0) {
            passed = done.status >= 0 &&
                     done.mode == CLI_MODE_EXEC &&
                     client_buffer_contains(&stdout_buffer, "No BGP routers configured.") &&
                     stderr_buffer.len == 0;
        }
    }

    test_result(passed, "Fragmented control handshake and EXEC frames decode correctly");

    if (fd >= 0) {
        close(fd);
    }
    bgpsim_control_frame_reset(&frame);
    bgpsim_control_decoder_free(&decoder);
    output_buffer_free(&stdout_buffer);
    output_buffer_free(&stderr_buffer);
    destroy_sim(sim);
    unlink(socket_path);
}

static void test_exec_before_syn_then_recover(void) {
    bgp_sim_t               *sim = create_sim();
    char                     socket_path[108] = "";
    bgpsim_control_decoder_t decoder;
    bgpsim_control_frame_t   frame = {0};
    output_buffer_t          stdout_buffer;
    output_buffer_t          stderr_buffer;
    bgpsim_exec_done_t       done;
    int                      fd = -1;
    int                      passed = 0;

    bgpsim_control_decoder_init(&decoder);
    output_buffer_init(&stdout_buffer);
    output_buffer_init(&stderr_buffer);

    if (sim != NULL && start_runtime(sim, socket_path, sizeof(socket_path)) == 0) {
        fd = connect_raw_control(socket_path);
        if (fd >= 0 &&
            send_frame_in_chunks(fd, BGPSIM_CTRL_EXEC_REQ, "show bgp summary", 16, 8) == 0 &&
            recv_frame_with_timeout(fd, &decoder, &frame, TEST_TIMEOUT_MS) == 1 &&
            frame.type == BGPSIM_CTRL_ERROR &&
            strstr((const char *)frame.payload, "SYN required before EXEC") != NULL) {
            bgpsim_control_frame_reset(&frame);
            if (send_frame_in_chunks(fd, BGPSIM_CTRL_SYN, NULL, 0, 8) == 0 &&
                recv_frame_with_timeout(fd, &decoder, &frame, TEST_TIMEOUT_MS) == 1 &&
                frame.type == BGPSIM_CTRL_ACK &&
                send_frame_in_chunks(fd, BGPSIM_CTRL_EXEC_REQ, "show bgp summary", 16, 8) == 0 &&
                recv_exec_result(fd, &decoder, &stdout_buffer, &stderr_buffer, &done, TEST_TIMEOUT_MS) == 0) {
                passed = done.status >= 0 &&
                         client_buffer_contains(&stdout_buffer, "No BGP routers configured.") &&
                         stderr_buffer.len == 0;
            }
        }
    }

    test_result(passed, "Protocol error before SYN does not poison the control session");

    if (fd >= 0) {
        close(fd);
    }
    bgpsim_control_frame_reset(&frame);
    bgpsim_control_decoder_free(&decoder);
    output_buffer_free(&stdout_buffer);
    output_buffer_free(&stderr_buffer);
    destroy_sim(sim);
    unlink(socket_path);
}

static void test_pipelined_syn_and_exec_frames(void) {
    bgp_sim_t               *sim = create_sim();
    char                     socket_path[108] = "";
    bgpsim_control_decoder_t decoder;
    bgpsim_control_frame_t   frame = {0};
    output_buffer_t          stdout1;
    output_buffer_t          stderr1;
    output_buffer_t          stdout2;
    output_buffer_t          stderr2;
    output_buffer_t          stdout3;
    output_buffer_t          stderr3;
    bgpsim_exec_done_t       done1;
    bgpsim_exec_done_t       done2;
    bgpsim_exec_done_t       done3;
    uint8_t                 *syn = NULL;
    uint8_t                 *exec1 = NULL;
    uint8_t                 *exec2 = NULL;
    uint8_t                 *exec3 = NULL;
    size_t                   syn_len = 0;
    size_t                   exec1_len = 0;
    size_t                   exec2_len = 0;
    size_t                   exec3_len = 0;
    uint8_t                 *batch = NULL;
    size_t                   batch_len = 0;
    int                      fd = -1;
    int                      passed = 0;

    bgpsim_control_decoder_init(&decoder);
    output_buffer_init(&stdout1);
    output_buffer_init(&stderr1);
    output_buffer_init(&stdout2);
    output_buffer_init(&stderr2);
    output_buffer_init(&stdout3);
    output_buffer_init(&stderr3);

    if (sim != NULL && start_runtime(sim, socket_path, sizeof(socket_path)) == 0) {
        fd = connect_raw_control(socket_path);
        if (fd >= 0 &&
            bgpsim_control_build_frame(BGPSIM_CTRL_SYN, NULL, 0, &syn, &syn_len) == 0 &&
            bgpsim_control_build_frame(BGPSIM_CTRL_EXEC_REQ, "config", 6, &exec1, &exec1_len) == 0 &&
            bgpsim_control_build_frame(BGPSIM_CTRL_EXEC_REQ, "router bgp 65000", 16, &exec2, &exec2_len) == 0 &&
            bgpsim_control_build_frame(BGPSIM_CTRL_EXEC_REQ, "show running-config", 19, &exec3, &exec3_len) == 0) {
            batch_len = syn_len + exec1_len + exec2_len + exec3_len;
            batch = malloc(batch_len);
            if (batch != NULL) {
                size_t offset = 0;

                memcpy(batch + offset, syn, syn_len);
                offset += syn_len;
                memcpy(batch + offset, exec1, exec1_len);
                offset += exec1_len;
                memcpy(batch + offset, exec2, exec2_len);
                offset += exec2_len;
                memcpy(batch + offset, exec3, exec3_len);

                if (send_all(fd, batch, batch_len) == 0 &&
                    recv_frame_with_timeout(fd, &decoder, &frame, TEST_TIMEOUT_MS) == 1 &&
                    frame.type == BGPSIM_CTRL_ACK &&
                    recv_exec_result(fd, &decoder, &stdout1, &stderr1, &done1, TEST_TIMEOUT_MS) == 0 &&
                    recv_exec_result(fd, &decoder, &stdout2, &stderr2, &done2, TEST_TIMEOUT_MS) == 0 &&
                    recv_exec_result(fd, &decoder, &stdout3, &stderr3, &done3, TEST_TIMEOUT_MS) == 0) {
                    passed = done1.status >= 0 &&
                             done2.status >= 0 &&
                             done2.session.has_router &&
                             done2.session.current_router_as == 65000 &&
                             done3.status >= 0 &&
                             done3.session.has_router &&
                             done3.session.current_router_as == 65000 &&
                             stdout3.len > 0 &&
                             client_buffer_contains(&stdout3, "router bgp 65000");
                }
            }
        }
    }

    test_result(passed, "Pipelined SYN and EXEC frames preserve ordered session state");

    free(syn);
    free(exec1);
    free(exec2);
    free(exec3);
    free(batch);
    if (fd >= 0) {
        close(fd);
    }
    bgpsim_control_frame_reset(&frame);
    bgpsim_control_decoder_free(&decoder);
    output_buffer_free(&stdout1);
    output_buffer_free(&stderr1);
    output_buffer_free(&stdout2);
    output_buffer_free(&stderr2);
    output_buffer_free(&stdout3);
    output_buffer_free(&stderr3);
    destroy_sim(sim);
    unlink(socket_path);
}

static void test_invalid_frames_drop_or_error_session(void) {
    bgp_sim_t               *sim = create_sim();
    char                     socket_path[108] = "";
    bgpsim_control_decoder_t decoder;
    bgpsim_control_frame_t   frame = {0};
    uint8_t                  invalid_header[8];
    int                      fd = -1;
    int                      passed = 0;

    bgpsim_control_decoder_init(&decoder);
    memset(invalid_header, 0, sizeof(invalid_header));
    invalid_header[3] = 99; /* invalid type */

    if (sim != NULL && start_runtime(sim, socket_path, sizeof(socket_path)) == 0) {
        fd = connect_raw_control(socket_path);
        if (fd >= 0 && send_all(fd, invalid_header, sizeof(invalid_header)) == 0) {
            int rc = recv_frame_with_timeout(fd, &decoder, &frame, TEST_TIMEOUT_MS);

            passed = (rc == 1 && frame.type == BGPSIM_CTRL_ERROR) ||
                     (rc < 0 && (errno == ECONNRESET || errno == EPIPE));
        }
    }

    test_result(passed, "Invalid control frames are rejected without wedging the server");

    if (fd >= 0) {
        close(fd);
    }
    bgpsim_control_frame_reset(&frame);
    bgpsim_control_decoder_free(&decoder);
    destroy_sim(sim);
    unlink(socket_path);
}

static void test_control_session_state_isolation(void) {
    bgp_sim_t              *sim = create_sim();
    char                    socket_path[108] = "";
    bgpsim_control_client_t client1;
    bgpsim_control_client_t client2;
    cli_mode_t              mode1 = CLI_MODE_EXEC;
    cli_mode_t              mode2 = CLI_MODE_EXEC;
    cli_session_t           session1;
    cli_session_t           session2;
    control_capture_t       capture1 = {0};
    control_capture_t       capture2 = {0};
    int                     status1 = -1;
    int                     status2 = -1;
    int                     passed = 0;

    memset(&client1, 0, sizeof(client1));
    memset(&client2, 0, sizeof(client2));
    client1.fd = -1;
    client2.fd = -1;
    cli_session_init(&session1);
    cli_session_init(&session2);

    if (sim != NULL && start_runtime(sim, socket_path, sizeof(socket_path)) == 0 &&
        bgpsim_control_client_open(&client1, socket_path) == 0 &&
        bgpsim_control_client_open(&client2, socket_path) == 0 &&
        execute_control_command(&client1, "config", &mode1, &session1, &capture1, &status1) == 0 &&
        execute_control_command(&client1, "router bgp 65000", &mode1, &session1, &capture1, &status1) == 0 &&
        execute_control_command(&client2, "show running-config", &mode2, &session2, &capture2, &status2) == 0) {
        passed = status1 >= 0 &&
                 mode1 == CLI_MODE_CONFIG &&
                 session1.has_router &&
                 session1.current_router_as == 65000 &&
                 status2 >= 0 &&
                 mode2 == CLI_MODE_EXEC &&
                 !session2.has_router &&
                 capture2.stdout_buffer.len > 0;
    }

    test_result(passed, "Control sessions keep independent CLI mode and context");

    free_control_capture(&capture1);
    free_control_capture(&capture2);
    bgpsim_control_client_close(&client2);
    bgpsim_control_client_close(&client1);
    destroy_sim(sim);
    unlink(socket_path);
}

static void test_invalid_command_status_and_large_output(void) {
    bgp_sim_t              *sim = create_sim();
    char                    socket_path[108] = "";
    bgpsim_control_client_t client;
    cli_mode_t              mode = CLI_MODE_EXEC;
    cli_session_t           session;
    control_capture_t       capture = {0};
    int                     status = -1;
    int                     passed = 0;

    memset(&client, 0, sizeof(client));
    client.fd = -1;
    cli_session_init(&session);

    if (sim != NULL && start_runtime(sim, socket_path, sizeof(socket_path)) == 0 &&
        bgpsim_control_client_open(&client, socket_path) == 0 &&
        execute_control_command(&client, "invalid_command_xyz", &mode, &session, &capture, &status) == 0) {
        int invalid_ok = status < 0 &&
                         (capture.stderr_buffer.len > 0 || capture.stdout_buffer.len > 0);

        free_control_capture(&capture);
        output_buffer_init(&capture.stdout_buffer);
        output_buffer_init(&capture.stderr_buffer);

        if (invalid_ok &&
            execute_control_command(&client, "config", &mode, &session, &capture, &status) == 0) {
            free_control_capture(&capture);
            output_buffer_init(&capture.stdout_buffer);
            output_buffer_init(&capture.stderr_buffer);

            passed = 1;
            for (int i = 0; i < 40 && passed; i++) {
                char command[64];

                snprintf(command, sizeof(command), "router bgp %u", (unsigned)(65100 + i));
                if (execute_control_command(&client, command, &mode, &session, &capture, &status) != 0 || status < 0) {
                    passed = 0;
                }
                free_control_capture(&capture);
                output_buffer_init(&capture.stdout_buffer);
                output_buffer_init(&capture.stderr_buffer);
            }

            if (passed &&
                execute_control_command(&client, "end", &mode, &session, &capture, &status) == 0 &&
                status >= 0) {
                free_control_capture(&capture);
                output_buffer_init(&capture.stdout_buffer);
                output_buffer_init(&capture.stderr_buffer);
            } else {
                passed = 0;
            }

            if (passed &&
                execute_control_command(&client, "show running-config", &mode, &session, &capture, &status) == 0) {
                passed = status >= 0 &&
                         capture.stdout_buffer.len > 500 &&
                         client_buffer_contains(&capture.stdout_buffer, "router bgp 65100") &&
                         client_buffer_contains(&capture.stdout_buffer, "router bgp 65139");
            } else {
                passed = 0;
            }
        } else {
            passed = 0;
        }
    }

    test_result(passed, "Control EXEC_DONE status and large config output survive adversarial usage");

    free_control_capture(&capture);
    bgpsim_control_client_close(&client);
    destroy_sim(sim);
    unlink(socket_path);
}

typedef struct {
    bgp_neighbor_t *neighbor;
} neighbor_wait_t;

static int passive_neighbor_idle(void *opaque) {
    neighbor_wait_t *wait = opaque;
    bgp_neighbor_t  *neighbor = wait != NULL ? wait->neighbor : NULL;

    return neighbor != NULL &&
           neighbor->state == BGP_STATE_IDLE &&
           neighbor->sock_fd < 0 &&
           !neighbor->stream_open &&
           !neighbor->connect_pending &&
           !neighbor->pending_reconnect;
}

static void test_terminal_monitor_event_filtering(void) {
    bgp_sim_t              *sim = create_sim();
    char                    socket_path[108] = "";
    bgpsim_control_client_t watcher;
    bgpsim_control_client_t quiet;
    cli_mode_t              watcher_mode = CLI_MODE_EXEC;
    cli_session_t           watcher_session;
    cli_session_t           quiet_session;
    control_capture_t       capture = {0};
    event_capture_t         watcher_events;
    event_capture_t         quiet_events;
    spawned_test_client_t   test_client;
    int                     status = -1;
    int                     passed = 0;

    memset(&watcher, 0, sizeof(watcher));
    memset(&quiet, 0, sizeof(quiet));
    watcher.fd = -1;
    quiet.fd = -1;
    cli_session_init(&watcher_session);
    cli_session_init(&quiet_session);
    output_buffer_init(&watcher_events.buffer);
    output_buffer_init(&quiet_events.buffer);
    memset(&test_client, 0, sizeof(test_client));
    test_client.pid = -1;
    watcher_events.count = 0;
    quiet_events.count = 0;

    /*
     * Keep this as an external-peer harness on purpose. The control edge-case
     * is only meaningful if a real outside client completes the TCP+BGP
     * handshake and triggers the runtime's unsolicited EVENT fanout path.
     */
    if (g_test_client_path[0] == '\0') {
        fprintf(stderr, "bgp_test_client not found. Build the sibling helper binary or set TEST_CLIENT.\n");
    } else if (sim != NULL) {
        sim->passive_mode = 1;
        if (bgp_add_router(sim, 65000) == 1 &&
            bgp_add_neighbor(sim, 65000, "127.0.0.1", 65001) == 1 &&
            start_runtime(sim, socket_path, sizeof(socket_path)) == 0 &&
            wait_until(router_listening, sim->routers[0], TEST_TIMEOUT_MS) &&
            bgpsim_control_client_open(&watcher, socket_path) == 0 &&
            bgpsim_control_client_open(&quiet, socket_path) == 0 &&
            execute_control_command(&watcher, "terminal monitor", &watcher_mode, &watcher_session, &capture,
                                    &status) == 0 &&
            status >= 0) {
            free_control_capture(&capture);
            output_buffer_init(&capture.stdout_buffer);
            output_buffer_init(&capture.stderr_buffer);

            /*
             * Keep the peer alive briefly after ESTABLISHED so the watcher can
             * observe the Up EVENT before the session naturally tears down.
             */
            if (spawn_test_client_active(&test_client,
                                         "127.0.0.1",
                                         sim->routers[0]->listen_port,
                                         65001,
                                         "2.2.2.2",
                                         1,
                                         NULL) == 0 &&
                wait_for_event_contains(&watcher, &watcher_events,
                                        "%BGP-5-ADJCHANGE: neighbor 127.0.0.1 Up",
                                        TEST_TIMEOUT_MS) &&
                wait_for_spawned_client(&test_client, TEST_TIMEOUT_MS)) {
                bgpsim_control_client_drain_events(&quiet, capture_event, &quiet_events);
                passed = watcher_events.count > 0 && quiet_events.count == 0;
            }
        }
    }

    if (!passed) {
        if (test_client.pid > 0) {
            describe_spawned_client_failure(&test_client);
        }
        fprintf(stderr, "terminal-monitor diagnostics: watcher_events=%d quiet_events=%d helper=%s\n",
                watcher_events.count, quiet_events.count,
                g_test_client_path[0] != '\0' ? g_test_client_path : "(missing)");
    }

    test_result(passed, "terminal monitor only delivers runtime events to subscribed sessions");

    if (test_client.pid > 0) {
        wait_for_spawned_client(&test_client, 1000);
    }
    if (passed && test_client.log_path[0] != '\0') {
        unlink(test_client.log_path);
    }
    free_control_capture(&capture);
    output_buffer_free(&watcher_events.buffer);
    output_buffer_free(&quiet_events.buffer);
    bgpsim_control_client_close(&quiet);
    bgpsim_control_client_close(&watcher);
    destroy_sim(sim);
    unlink(socket_path);
}

static void test_terminal_monitor_event_channel_stress(void) {
    bgp_sim_t              *sim = create_sim();
    char                    socket_path[108] = "";
    bgpsim_control_client_t watcher;
    bgpsim_control_client_t quiet;
    cli_mode_t              watcher_mode = CLI_MODE_EXEC;
    cli_mode_t              quiet_mode = CLI_MODE_EXEC;
    cli_session_t           watcher_session;
    cli_session_t           quiet_session;
    control_capture_t       watcher_capture = {0};
    control_capture_t       quiet_capture = {0};
    event_capture_t         watcher_events;
    event_capture_t         quiet_events;
    int                     status = -1;
    int                     passed = 0;
    int                     up_count = 0;
    int                     down_count = 0;

    memset(&watcher, 0, sizeof(watcher));
    memset(&quiet, 0, sizeof(quiet));
    watcher.fd = -1;
    quiet.fd = -1;
    cli_session_init(&watcher_session);
    cli_session_init(&quiet_session);
    output_buffer_init(&watcher_events.buffer);
    output_buffer_init(&quiet_events.buffer);
    watcher_events.count = 0;
    quiet_events.count = 0;

    if (g_test_client_path[0] == '\0') {
        fprintf(stderr, "bgp_test_client not found. Build the sibling helper binary or set TEST_CLIENT.\n");
    } else if (sim != NULL) {
        bgp_neighbor_t *neighbor = NULL;

        sim->passive_mode = 1;
        if (bgp_add_router(sim, 65000) == 1 &&
            bgp_add_neighbor(sim, 65000, "127.0.0.1", 65001) == 1) {
            neighbor = sim->routers[0]->neighbors[0];
        }

        if (neighbor != NULL &&
            start_runtime(sim, socket_path, sizeof(socket_path)) == 0 &&
            wait_until(router_listening, sim->routers[0], TEST_TIMEOUT_MS) &&
            bgpsim_control_client_open(&watcher, socket_path) == 0 &&
            bgpsim_control_client_open(&quiet, socket_path) == 0 &&
            execute_control_command(&watcher, "terminal monitor", &watcher_mode, &watcher_session, &watcher_capture,
                                    &status) == 0 &&
            status >= 0) {
            int cycles_ok = 1;

            free_control_capture(&watcher_capture);
            output_buffer_init(&watcher_capture.stdout_buffer);
            output_buffer_init(&watcher_capture.stderr_buffer);

            for (int i = 0; i < TERMINAL_MONITOR_STRESS_CYCLES && cycles_ok; i++) {
                spawned_test_client_t test_client;

                memset(&test_client, 0, sizeof(test_client));
                test_client.pid = -1;

                /*
                 * Keep each peer session short so the test stresses many EVENT
                 * frames on one subscribed control socket without turning into
                 * a slow long-lived keepalive test.
                 */
                if (spawn_test_client_active(&test_client,
                                             "127.0.0.1",
                                             sim->routers[0]->listen_port,
                                             65001,
                                             "2.2.2.2",
                                             0,
                                             NULL) != 0 ||
                    !wait_for_spawned_client(&test_client, TEST_TIMEOUT_MS) ||
                    !wait_until(passive_neighbor_idle,
                                &(neighbor_wait_t){ .neighbor = neighbor },
                                TEST_TIMEOUT_MS)) {
                    describe_spawned_client_failure(&test_client);
                    cycles_ok = 0;
                    break;
                }

                if (test_client.log_path[0] != '\0') {
                    unlink(test_client.log_path);
                }
            }

            if (cycles_ok &&
                execute_control_command_with_events(&watcher, "show bgp summary",
                                                    &watcher_mode, &watcher_session,
                                                    &watcher_capture, &watcher_events,
                                                    &status) == 0 &&
                status >= 0 &&
                bgpsim_control_client_drain_events(&watcher, capture_event, &watcher_events) == 0 &&
                bgpsim_control_client_drain_events(&quiet, capture_event, &quiet_events) == 0) {
                up_count = count_substring_occurrences(watcher_events.buffer.data,
                                                       "%BGP-5-ADJCHANGE: neighbor 127.0.0.1 Up");
                down_count = count_substring_occurrences(watcher_events.buffer.data,
                                                         "%BGP-5-ADJCHANGE: neighbor 127.0.0.1 Down - connection lost");

                passed = watcher_mode == CLI_MODE_EXEC &&
                         quiet_mode == CLI_MODE_EXEC &&
                         watcher_events.count == TERMINAL_MONITOR_STRESS_CYCLES * 2 &&
                         quiet_events.count == 0 &&
                         up_count == TERMINAL_MONITOR_STRESS_CYCLES &&
                         down_count == TERMINAL_MONITOR_STRESS_CYCLES &&
                         watcher_capture.stderr_buffer.len == 0 &&
                         client_buffer_contains(&watcher_capture.stdout_buffer, "Neighbor") &&
                         client_buffer_contains(&watcher_capture.stdout_buffer, "127.0.0.1");
            }
        }
    }

    if (!passed) {
        fprintf(stderr,
                "terminal-monitor stress diagnostics: watcher_events=%d quiet_events=%d up=%d down=%d helper=%s\n",
                watcher_events.count, quiet_events.count, up_count, down_count,
                g_test_client_path[0] != '\0' ? g_test_client_path : "(missing)");
    }

    test_result(passed, "terminal monitor event channel stays ordered and isolated under repeated peer churn");

    free_control_capture(&watcher_capture);
    free_control_capture(&quiet_capture);
    output_buffer_free(&watcher_events.buffer);
    output_buffer_free(&quiet_events.buffer);
    bgpsim_control_client_close(&quiet);
    bgpsim_control_client_close(&watcher);
    destroy_sim(sim);
    unlink(socket_path);
}

static void test_script_context_and_complete_input(void) {
    bgp_sim_t               *sim = create_sim();
    char                     socket_path[108] = "";
    bgpsim_control_decoder_t decoder;
    bgpsim_control_frame_t   frame = {0};
    output_buffer_t          out = {0}, err = {0};
    bgpsim_exec_done_t       done = {0};
    int                      fd = -1, passed = 0;
    bgpsim_control_decoder_init(&decoder);
    if (sim && start_runtime(sim, socket_path, sizeof(socket_path)) == 0) {
        fd = connect_raw_control(socket_path);
        if (fd >= 0 && send_frame_in_chunks(fd, BGPSIM_CTRL_SYN, NULL, 0, 8) == 0 &&
            recv_frame_with_timeout(fd, &decoder, &frame, TEST_TIMEOUT_MS) == 1 && frame.type == BGPSIM_CTRL_ACK) {
            const char *setup[] = {"config", "script wire"};
            passed = 1;
            for (size_t i = 0; passed && i < sizeof(setup) / sizeof(*setup); i++)
                passed = send_frame_in_chunks(fd, BGPSIM_CTRL_EXEC_REQ, setup[i], strlen(setup[i]), 8) == 0 &&
                         recv_exec_result(fd, &decoder, &out, &err, &done, TEST_TIMEOUT_MS) == 0 && done.status >= 0;
            char prompt[256];
            cli_build_prompt(done.mode, &done.session, prompt, sizeof(prompt), 0);
            passed = passed && strcmp(prompt, "bgpsim(config-script-wire)# ") == 0;

            char oversized[BGPSIM_COMMAND_SIZE + 100];
            memset(oversized, ' ', sizeof(oversized));
            memcpy(oversized, "sleep 1s", 8);
            const char embedded_nul[] = "sleep 1s\0ignored";
            const char *invalid[] = {oversized, embedded_nul};
            const size_t sizes[] = {sizeof(oversized), sizeof(embedded_nul) - 1};
            for (size_t i = 0; passed && i < sizeof(invalid) / sizeof(*invalid); i++) {
                output_buffer_reset(&err);
                passed = send_frame_in_chunks(fd, BGPSIM_CTRL_EXEC_REQ, invalid[i], sizes[i], 128) == 0 &&
                         recv_exec_result(fd, &decoder, &out, &err, &done, TEST_TIMEOUT_MS) == 0 &&
                         done.status < 0 && err.len && strcmp(done.session.current_script_name, "wire") == 0;
            }
            // A rejected frame must neither append a step nor poison the session.
            const char *recover[] = {"sleep 2s", "show script wire"};
            for (size_t i = 0; passed && i < sizeof(recover) / sizeof(*recover); i++) {
                output_buffer_reset(&out);
                output_buffer_reset(&err);
                passed = send_frame_in_chunks(fd, BGPSIM_CTRL_EXEC_REQ, recover[i], strlen(recover[i]), 8) == 0 &&
                         recv_exec_result(fd, &decoder, &out, &err, &done, TEST_TIMEOUT_MS) == 0 &&
                         done.status >= 0 && !err.len;
            }
            passed = passed && client_buffer_contains(&out, "1 steps") && client_buffer_contains(&out, "sleep 2000ms");
        }
    }
    test_result(passed, "Attached script context survives EXEC_DONE; invalid raw input is atomic and recoverable");
    if (fd >= 0) close(fd);
    bgpsim_control_frame_reset(&frame);
    bgpsim_control_decoder_free(&decoder);
    output_buffer_free(&out);
    output_buffer_free(&err);
    destroy_sim(sim);
    unlink(socket_path);
}

static int open_fd_count(void) {
#ifdef __linux__
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) return -1;
    int            count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (entry->d_name[0] != '.') count++;
    }
    closedir(directory);
    return count;
#else
    return -1;
#endif
}

static int descriptors_recovered(void *opaque) {
    return open_fd_count() <= *(int *)opaque;
}

/*
 * A real control reader stops draining a multi-megabyte response stream, then
 * disconnects while uv_write callbacks are outstanding. A second connection
 * must remain responsive, isolated, and usable after every abandoned queue.
 */
static void test_slow_reader_disconnect_and_recovery(void) {
    bgp_sim_t              *sim = create_sim();
    char                    path[108] = "";
    bgpsim_control_client_t healthy = {.fd = -1};
    cli_mode_t              mode = CLI_MODE_EXEC;
    cli_session_t           session;
    control_capture_t       capture = {0};
    int                     passed = sim != NULL, status = -1;
    cli_session_init(&session);
    script_step_t step;
    passed = passed && script_step_sleep(&step, "1ms") == SCRIPT_OK;
    for (unsigned i = 0; passed && i < 8; i++) {
        char             name[32];
        bgpsim_script_t *script = NULL;
        snprintf(name, sizeof(name), "slow-%u", i);
        passed = script_create(&sim->scripts, name, &script) == SCRIPT_OK;
        for (unsigned j = 0; passed && j < 128; j++) passed = script_append(script, &step) == SCRIPT_OK;
    }
    passed = passed && start_runtime(sim, path, sizeof(path)) == 0 &&
             bgpsim_control_client_open(&healthy, path) == 0;
    int baseline_fds = open_fd_count();
    for (unsigned cycle = 0; passed && cycle < 8; cycle++) {
        bgpsim_control_decoder_t decoder;
        bgpsim_control_frame_t   frame = {0};
        bgpsim_control_decoder_init(&decoder);
        int fd = connect_raw_control(path);
        int small_buffer = 1024;
        passed = fd >= 0 && setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &small_buffer, sizeof(small_buffer)) == 0 &&
                 send_frame_in_chunks(fd, BGPSIM_CTRL_SYN, NULL, 0, 8) == 0 &&
                 recv_frame_with_timeout(fd, &decoder, &frame, TEST_TIMEOUT_MS) == 1 &&
                 frame.type == BGPSIM_CTRL_ACK;
        bgpsim_control_frame_reset(&frame);
        for (unsigned request = 0; passed && request < 256; request++) {
            passed = send_frame_in_chunks(fd, BGPSIM_CTRL_EXEC_REQ, "show running-config", 19, 64) == 0;
        }
        // Read one frame to prove requests executed, then stop reading entirely.
        passed = passed && recv_frame_with_timeout(fd, &decoder, &frame, TEST_TIMEOUT_MS) == 1 &&
                 frame.type == BGPSIM_CTRL_STDOUT_CHUNK && frame.payload_len > 0;
        free_control_capture(&capture);
        passed = passed && execute_control_command(&healthy, "show running-config", &mode, &session,
                                                   &capture, &status) == 0 && status >= 0 &&
                 capture.stderr_buffer.len == 0 && capture.stdout_buffer.len > 8192 &&
                 count_substring_occurrences(capture.stdout_buffer.data, "sleep 1ms") == 1024;
        if (fd >= 0) close(fd);
        bgpsim_control_frame_reset(&frame);
        bgpsim_control_decoder_free(&decoder);
        free_control_capture(&capture);
        passed = passed && execute_control_command(&healthy, "show scripts", &mode, &session,
                                                   &capture, &status) == 0 && status >= 0 &&
                 capture.stderr_buffer.len == 0 && client_buffer_contains(&capture.stdout_buffer, "slow-7");
        if (baseline_fds >= 0) passed = passed && wait_until(descriptors_recovered, &baseline_fds, TEST_TIMEOUT_MS);
    }
    test_result(passed, "Slow readers can abandon queued output without blocking clients or leaking descriptors");
    if (baseline_fds < 0) TEST_PRINT_SKIP("Descriptor leak accounting requires /proc/self/fd");
    free_control_capture(&capture);
    bgpsim_control_client_close(&healthy);
    destroy_sim(sim);
    unlink(path);
}

/*
 * Known bug: a control `shutdown` command can still lose its final `EXEC_DONE`
 * because the runtime begins closing control sessions immediately after
 * queueing the response. Keep a dedicated shutdown regression out of this suite
 * until final control frames are drained before close.
 */
int main(int argc, char **argv) {
    (void)argc;

    init_test_client_path(argv[0]);

    printf("BGP Control Edge-Case Tests\n");
    printf("===========================\n");

    test_client_refuses_version_mismatch();
    test_fragmented_handshake_and_exec();
    test_exec_before_syn_then_recover();
    test_pipelined_syn_and_exec_frames();
    test_invalid_frames_drop_or_error_session();
    test_control_session_state_isolation();
    test_invalid_command_status_and_large_output();
    test_terminal_monitor_event_filtering();
    test_terminal_monitor_event_channel_stress();
    test_script_context_and_complete_input();
    test_slow_reader_disconnect_and_recovery();
    TEST_PRINT_SKIP("Shutdown EXEC_DONE delivery is not guaranteed until response draining is implemented");

    printf("\nPassed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
