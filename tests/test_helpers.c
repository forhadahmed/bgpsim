// Test Helper Functions Implementation

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "parser.h"
#include "test_helpers.h"
#include "bgp_ribout_config.h"

void test_env_guard_capture(test_env_guard_t *guard, const char *name) {
    const char *value;

    if (!guard || !name) {
        return;
    }

    memset(guard, 0, sizeof(*guard));
    value = getenv(name);
    if (!value) {
        return;
    }

    guard->was_set = 1;
    strncpy(guard->value, value, sizeof(guard->value) - 1);
}

void test_env_guard_restore(const test_env_guard_t *guard, const char *name) {
    if (!guard || !name) {
        return;
    }

    if (guard->was_set) {
        setenv(name, guard->value, 1);
    } else {
        unsetenv(name);
    }
}

int test_exec_config(bgp_sim_t *sim, const char *command) {
    test_cli_session_t cli = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;
    return test_exec_config_session(sim, command, &cli, &router, &neighbor);
}

/*
 * Execute a configuration command with explicit mode and context tracking
 */
int test_exec_config_session(bgp_sim_t *sim, const char *command,
                                test_cli_session_t *cli,
                                bgp_router_t **current_router,
                                bgp_neighbor_t **current_neighbor) {
    int result = cli_process_command_with_output(&cli->session, sim, &cli->mode, command, NULL);
    *current_router = cli->session.has_router ? bgp_find_router(sim, cli->session.current_router_as) : NULL;
    *current_neighbor = cli->session.has_neighbor ?
                        bgp_find_neighbor(*current_router, cli->session.current_neighbor_ip) : NULL;
    return result;
}

/*
 * Convert binary prefix to string for testing
 */
void test_path_prefix_to_string(bgp_gen_path_t *path, char *buf, size_t buflen) {
    char addr_str[INET6_ADDRSTRLEN];
    if (path->prefix_af == AF_INET) {
        inet_ntop(AF_INET, &path->prefix_addr.ipv4, addr_str, sizeof(addr_str));
    } else {
        inet_ntop(AF_INET6, &path->prefix_addr.ipv6, addr_str, sizeof(addr_str));
    }
    snprintf(buf, buflen, "%s/%u", addr_str, path->prefix_len);
}

/*
 * Convert binary next_hop to string for testing
 */
void test_path_next_hop_to_string(bgp_gen_path_t *path, char *buf, size_t buflen) {
    if (path->next_hop_af == AF_INET) {
        inet_ntop(AF_INET, &path->next_hop_addr.ipv4, buf, buflen);
    } else {
        inet_ntop(AF_INET6, &path->next_hop_addr.ipv6, buf, buflen);
    }
}

/*
 * Copy the start of file into buf as a string, cut to fit; no change when buf is NULL.
 */
static void test_capture_read(FILE *file, char *buf, size_t buflen) {
    size_t used;

    if (!buf || buflen == 0) {
        return;
    }
    rewind(file);
    used = fread(buf, 1, buflen - 1, file);
    buf[used] = '\0';
}

int test_capture_output(void (*fn)(void *arg), void *arg,
                        char *stdout_buf, size_t stdout_buflen,
                        char *stderr_buf, size_t stderr_buflen) {
    FILE *out = tmpfile();
    FILE *err = stderr_buf ? tmpfile() : NULL;
    int   saved_out;
    int   saved_err = -1;

    if (!out || (stderr_buf && !err)) {
        if (out) {
            fclose(out);
        }
        if (err) {
            fclose(err);
        }
        return -1;
    }

    fflush(stdout);
    fflush(stderr);
    saved_out = dup(STDOUT_FILENO);
    dup2(fileno(out), STDOUT_FILENO);
    if (err) {
        saved_err = dup(STDERR_FILENO);
        dup2(fileno(err), STDERR_FILENO);
    }

    fn(arg);

    fflush(stdout);
    fflush(stderr);
    dup2(saved_out, STDOUT_FILENO);
    close(saved_out);
    if (err) {
        dup2(saved_err, STDERR_FILENO);
        close(saved_err);
    }

    test_capture_read(out, stdout_buf, stdout_buflen);
    fclose(out);
    if (err) {
        test_capture_read(err, stderr_buf, stderr_buflen);
        fclose(err);
    }
    return 0;
}
