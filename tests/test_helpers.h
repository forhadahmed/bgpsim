/*
 * Test Helper Functions
 * Shared utilities for BGP simulator tests
 */

#ifndef TEST_HELPERS_H
#define TEST_HELPERS_H

#include <string.h>
#include <arpa/inet.h>
#include "bgpsim.h"
#include "output.h"
#include "commands.h"
#include "bgp_update.h"

typedef struct {
    int  was_set;
    char value[128];
} test_env_guard_t;

typedef struct {
    cli_mode_t    mode;
    cli_session_t session;
} test_cli_session_t;

/*
 * Output of a command per stream: test_output_capture_write is the callback of an output_t or a control client.
 */
typedef struct {
    output_buffer_t stdout_buffer;
    output_buffer_t stderr_buffer;
} test_output_capture_t;

static inline void test_output_capture_init(test_output_capture_t *capture) {
    output_buffer_init(&capture->stdout_buffer);
    output_buffer_init(&capture->stderr_buffer);
}

static inline void test_output_capture_free(test_output_capture_t *capture) {
    output_buffer_free(&capture->stdout_buffer);
    output_buffer_free(&capture->stderr_buffer);
}

static inline void test_output_capture_write(void *opaque, output_stream_t stream, const char *data, size_t len) {
    test_output_capture_t *capture = opaque;

    if (!capture || !data || len == 0) {
        return;
    }
    output_buffer_write(stream == OUTPUT_STREAM_STDERR ? &capture->stderr_buffer : &capture->stdout_buffer, data, len);
}

/*
 * One command in a fresh config session, through the production CLI.
 */
int test_exec_config(bgp_sim_t *sim, const char *command);

/*
 * Persistent production session; object outputs are for assertions only.
 */
int test_exec_config_session(bgp_sim_t *sim, const char *command,
                                test_cli_session_t *cli,
                                bgp_router_t **current_router,
                                bgp_neighbor_t **current_neighbor);

/*
 * Convert binary prefix in bgp_gen_path_t to string format
 * Example: converts binary 10.0.0.0/24 to string "10.0.0.0/24"
 */
void test_path_prefix_to_string(bgp_gen_path_t *path, char *buf, size_t buflen);

/*
 * Convert binary next_hop in bgp_gen_path_t to string format
 * Example: converts binary 192.168.1.1 to string "192.168.1.1"
 */
void test_path_next_hop_to_string(bgp_gen_path_t *path, char *buf, size_t buflen);

/*
 * Save and restore a small environment variable value around a test. This is
 * primarily used for RANDSEED so tests can perturb deterministic ribout
 * randomness without leaking environment state into later cases.
 */
void test_env_guard_capture(test_env_guard_t *guard, const char *name);
void test_env_guard_restore(const test_env_guard_t *guard, const char *name);

/*
 * Run fn(arg) with stdout, and stderr when stderr_buf is not NULL, sent to
 * temporary files, then copy the text into the buffers (cut to their size).
 * Temporary files have no pipe-size limit, so large output cannot block.
 * Returns -1 when a temporary file cannot be made (fn does not run).
 */
int test_capture_output(void (*fn)(void *arg), void *arg,
                        char *stdout_buf, size_t stdout_buflen,
                        char *stderr_buf, size_t stderr_buflen);

/*
 * Run one CLI command with its stdout, and stderr when stderr_buf is not NULL, copied to the buffers. Returns the
 * command status.
 */
int test_capture_command(bgp_sim_t *sim, cli_session_t *session, cli_mode_t *mode, const char *command,
                         char *stdout_buf, size_t stdout_buflen, char *stderr_buf, size_t stderr_buflen);

/*
 * Load configuration text through a temporary file, as parse_config_file_with_output() reads it.
 */
int test_load_config(bgp_sim_t *sim, const char *text, const output_t *output);

static inline size_t test_count_messages(const bgp_msg_t *messages) {
    size_t count = 0;

    for (; messages; messages = messages->next) {
        count++;
    }
    return count;
}

static inline evpn_esi_t make_esi(uint8_t type, uint8_t fill) {
    evpn_esi_t esi;

    esi.type = type;
    memset(esi.value, fill, sizeof(esi.value));
    return esi;
}

/*
 * Next hops for the encoder tests, from address text. The link-local form carries the second IPv6 address of
 * RFC 2545 as well.
 */
static inline bgp_next_hop_t make_ipv4_next_hop(const char *addr) {
    bgp_next_hop_t next_hop;

    memset(&next_hop, 0, sizeof(next_hop));
    next_hop.af = AF_INET;
    inet_pton(AF_INET, addr, &next_hop.address.ipv4);
    return next_hop;
}

static inline bgp_next_hop_t make_ipv6_next_hop(const char *addr) {
    bgp_next_hop_t next_hop;

    memset(&next_hop, 0, sizeof(next_hop));
    next_hop.af = AF_INET6;
    inet_pton(AF_INET6, addr, &next_hop.address.ipv6);
    return next_hop;
}

static inline bgp_next_hop_t make_ipv6_next_hop_with_link_local(const char *global, const char *link_local) {
    bgp_next_hop_t next_hop = make_ipv6_next_hop(global);

    next_hop.has_link_local = 1;
    inet_pton(AF_INET6, link_local, &next_hop.link_local);
    return next_hop;
}

/*
 * Build a minimal attribute chain (ORIGIN + AS_PATH) for test generators.
 */
static inline bgp_path_attr_t* make_test_attrs(void) {
    bgp_path_attr_t  *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t          asns[] = {65001};
    as_path_segment_t segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t  *as_path = bgp_attr_create_as_path(&segment, 1);

    origin->next = as_path;
    return origin;
}

#endif /* TEST_HELPERS_H */
