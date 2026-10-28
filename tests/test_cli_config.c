/*
 * BGP CLI Configuration Tests
 * Covers config parsing, capability configuration, and running-config
 * round-trip behavior in one place.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "bgpsim.h"
#include "output.h"
#include "bgp_ribout.h"
#include "bgp_router.h"
#include "test_result.h"
#include "bgp_neighbor.h"
#include "test_helpers.h"
#include "bgp_ribout_config.h"
#include "test_nlri_templates.h"
#define TEST_CONFIG_FILE    "/tmp/bgpsim_test_config.txt"
#define CONFIG_CAPTURE_SIZE 65536

extern void cli_show_config(bgp_sim_t *sim);

typedef struct {
    output_buffer_t stdout_buffer;
    output_buffer_t stderr_buffer;
} config_capture_t;

static void capture_config_output(void *opaque, output_stream_t stream, const char *data, size_t len) {
    config_capture_t *capture = opaque;

    if (!capture || !data || len == 0) {
        return;
    }

    if (stream == OUTPUT_STREAM_STDERR) {
        output_buffer_write(&capture->stderr_buffer, data, len);
    } else {
        output_buffer_write(&capture->stdout_buffer, data, len);
    }
}

/*
 * Helper to create temporary config file
 */
void create_temp_config(const char *filename, const char *content) {
    FILE *f = fopen(filename, "w");
    if (f) {
        fprintf(f, "%s", content);
        fclose(f);
    }
}

/*
 * Capture the actual running-config serializer output for round-trip tests.
 */
static void show_config_call(void *arg) {
    cli_show_config((bgp_sim_t *)arg);
}

/*
 * Capture the running-config text in buffer; -1 when the capture fails.
 */
static int capture_running_config(bgp_sim_t *sim, char *buffer, size_t buffer_size) {
    if (buffer_size == 0) {
        return -1;
    }
    return test_capture_output(show_config_call, sim, buffer, buffer_size, NULL, 0);
}

static void write_running_config_to_file(bgp_sim_t *sim, const char *filename) {
    char  config_output[CONFIG_CAPTURE_SIZE];
    FILE *file;

    if (capture_running_config(sim, config_output, sizeof(config_output)) < 0) {
        fprintf(stderr, "Failed to capture running-config output\n");
        return;
    }

    file = fopen(filename, "w");
    if (!file) {
        fprintf(stderr, "Failed to open file for writing\n");
        return;
    }

    fputs(config_output, file);
    fclose(file);
}

/*
 * Test 1: Empty configuration file
 */
void test_empty_config() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);

    create_temp_config("/tmp/test_empty.conf", "");

    int result = parse_config_file("/tmp/test_empty.conf", &sim);
    unlink("/tmp/test_empty.conf");

    // Empty config should succeed
    test_result(result == 0, "Empty configuration file");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 2: Config file not found
 */
void test_config_not_found() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);

    int result = parse_config_file("/tmp/nonexistent_config_file_xyz.conf", &sim);

    // Should fail gracefully
    test_result(result != 0, "Configuration file not found");
    bgp_shutdown_sim(&sim);
}

void test_parse_config_file_inherits_routed_output() {
    bgp_sim_t        sim = {0};
    config_capture_t capture;
    output_t output = {
        .write = capture_config_output,
        .opaque = &capture
    };
    const output_t *previous_output;
    int             result;
    int             passed;

    bgp_init_simulator(&sim);
    output_buffer_init(&capture.stdout_buffer);
    output_buffer_init(&capture.stderr_buffer);
    create_temp_config("/tmp/test_nested_output.conf", "router bgp\n");

    previous_output = output_push(&output);
    result = parse_config_file("/tmp/test_nested_output.conf", &sim);
    output_pop(previous_output);

    unlink("/tmp/test_nested_output.conf");

    passed = result == 0 &&
             capture.stdout_buffer.len == 0 &&
             capture.stderr_buffer.data != NULL &&
             strstr(capture.stderr_buffer.data, "Incomplete Command on line 1") != NULL;

    output_buffer_free(&capture.stdout_buffer);
    output_buffer_free(&capture.stderr_buffer);
    test_result(passed, "Config parse inherits routed output");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 3: Valid router configuration
 */
void test_valid_router_config() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);

    const char *config = "router bgp 65000\n";
    create_temp_config("/tmp/test_router.conf", config);

    int result = parse_config_file("/tmp/test_router.conf", &sim);
    unlink("/tmp/test_router.conf");

    int passed = (result == 0) && (sim.router_count > 0);
    test_result(passed, "Valid router configuration");
    bgp_shutdown_sim(&sim);
}

/*
 * File loading intentionally continues after a rejected line. Verify both the
 * rejection and the next valid command, rather than treating return 0 as proof.
 */
static void test_rejected_config_lines(void) {
    const struct { const char *line; int router_context; const char *name; } cases[] = {
        {"router bgp", 0, "Missing AS number"},
        {"router bgp abc123", 0, "Invalid AS number format"},
        {"neighbor remote-as 65001", 1, "Missing neighbor IP"},
        {"neighbor 10.0.0.1 65001", 1, "Missing remote-as keyword"},
        {"invalid-command xyz", 1, "Unknown command"},
        {"neighbor 10.0.0.1 remote-as 65001", 0, "Missing router context"},
        {"ROUTER BGP 65000", 0, "Case-sensitive config keywords"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); i++) {
        bgp_sim_t        sim = {0};
        config_capture_t capture;
        output_t         output = {.write = capture_config_output, .opaque = &capture};
        char path[] = "/tmp/bgpsim-rejected-config-XXXXXX";
        int   fd = mkstemp(path);
        FILE *file = fd >= 0 ? fdopen(fd, "w") : NULL;
        if (!file) {
            if (fd >= 0) close(fd);
            test_result(0, cases[i].name);
            continue;
        }
        fprintf(file, "%s%s\n!\nrouter bgp 65002\n neighbor 192.0.2.2 remote-as 65003\n",
                cases[i].router_context ? "router bgp 65000\n" : "", cases[i].line);
        fclose(file);
        bgp_init_simulator(&sim);
        output_buffer_init(&capture.stdout_buffer);
        output_buffer_init(&capture.stderr_buffer);
        int rc = parse_config_file_with_output(path, &sim, &output);
        unlink(path);
        bgp_router_t *original = bgp_find_router(&sim, 65000);
        bgp_router_t *recovered = bgp_find_router(&sim, 65002);
        int passed = rc == 0 && capture.stderr_buffer.data &&
                     strstr(capture.stderr_buffer.data, "on line ") &&
                     strstr(capture.stderr_buffer.data, cases[i].line) &&
                     sim.router_count == cases[i].router_context + 1 &&
                     (cases[i].router_context ? original && original->neighbor_count == 0 : !original) &&
                     recovered && recovered->neighbor_count == 1 &&
                     bgp_find_neighbor(recovered, "192.0.2.2") != NULL;
        test_result(passed, cases[i].name);
        output_buffer_free(&capture.stdout_buffer);
        output_buffer_free(&capture.stderr_buffer);
        bgp_shutdown_sim(&sim);
    }
}

/*
 * Test 6: Valid neighbor configuration
 */
void test_valid_neighbor_config() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);

    const char *config =
        "router bgp 65000\n"
        " neighbor 10.0.0.1 remote-as 65001\n";
    create_temp_config("/tmp/test_neighbor.conf", config);

    int result = parse_config_file("/tmp/test_neighbor.conf", &sim);
    unlink("/tmp/test_neighbor.conf");

    bgp_router_t *router = bgp_find_router(&sim, 65000);
    int           passed = (result == 0) && (router != NULL) && (router->neighbor_count > 0);
    test_result(passed, "Valid neighbor configuration");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 6b: IPv6 neighbors from config file
 */
void test_ipv6_neighbor_config() {
    bgp_sim_t     sim = {0};
    bgp_router_t *router;
    const char *config =
        "router bgp 100\n"
        " neighbor 2001:db8::1 remote-as 200\n"
        " neighbor fe80::1 remote-as 300\n";

    bgp_init_simulator(&sim);
    create_temp_config("/tmp/test_neighbor_ipv6.conf", config);
    parse_config_file("/tmp/test_neighbor_ipv6.conf", &sim);
    unlink("/tmp/test_neighbor_ipv6.conf");

    router = bgp_find_router(&sim, 100);
    test_result(router != NULL && router->neighbor_count == 2 && router->neighbors[0]->af == AF_INET6 &&
                    router->neighbors[1]->af == AF_INET6 &&
                    strcmp(router->neighbors[0]->ip, "2001:db8::1") == 0 &&
                    strcmp(router->neighbors[1]->ip, "fe80::1") == 0,
                "IPv6 neighbors from config file");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 10: Update-source configuration
 */
void test_update_source_config() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);

    const char *config =
        "router bgp 65000\n"
        " update-source 192.168.1.1\n"
        " neighbor 10.0.0.1 remote-as 65001\n"
        " update-source 10.0.0.254\n";
    create_temp_config("/tmp/test_update_src.conf", config);

    int result = parse_config_file("/tmp/test_update_src.conf", &sim);
    unlink("/tmp/test_update_src.conf");

    bgp_router_t *router = bgp_find_router(&sim, 65000);
    int passed = (result == 0) && (router != NULL) &&
                 (strcmp(router->source_ip, "192.168.1.1") == 0) &&
                 (router->neighbor_count == 1) &&
                 (strcmp(router->neighbors[0]->source_ip, "10.0.0.254") == 0);
    test_result(passed, "Router and neighbor update-source configuration");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 11: Comment lines
 */
void test_comment_lines() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);

    const char *config =
        "# This is a comment\n"
        "router bgp 65000\n"
        " # Another comment\n"
        " neighbor 10.0.0.1 remote-as 65001\n"
        "! Router-style comment\n";
    create_temp_config("/tmp/test_comments.conf", config);

    int result = parse_config_file("/tmp/test_comments.conf", &sim);
    unlink("/tmp/test_comments.conf");

    int passed = (result == 0) && (sim.router_count > 0);
    test_result(passed, "Comment lines handling");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 12: Whitespace and blank lines
 */
void test_whitespace_handling() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);

    const char *config =
        "\n"
        "  \n"
        "router bgp 65000\n"
        "   \n"
        " neighbor 10.0.0.1 remote-as 65001\n"
        "\n";
    create_temp_config("/tmp/test_whitespace.conf", config);

    int result = parse_config_file("/tmp/test_whitespace.conf", &sim);
    unlink("/tmp/test_whitespace.conf");

    int passed = (result == 0) && (sim.router_count > 0);
    test_result(passed, "Whitespace and blank lines");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 13: Very long configuration line
 */
void test_long_config_line() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);

    char long_line[BGPSIM_COMMAND_SIZE + 32];
    memset(long_line, 'A', sizeof(long_line) - 1);
    long_line[sizeof(long_line) - 1] = '\0';

    char config[sizeof(long_line) + 128];
    snprintf(config, sizeof(config), "router bgp 65000\n%s\nneighbor 192.0.2.2 remote-as 65001\n", long_line);
    create_temp_config("/tmp/test_long_line.conf", config);

    config_capture_t capture;
    output_buffer_init(&capture.stdout_buffer);
    output_buffer_init(&capture.stderr_buffer);
    output_t output = {.write = capture_config_output, .opaque = &capture};
    int      rc = parse_config_file_with_output("/tmp/test_long_line.conf", &sim, &output);
    unlink("/tmp/test_long_line.conf");

    bgp_router_t *router = bgp_find_router(&sim, 65000);
    test_result(rc == 0 && sim.router_count == 1 && router && router->neighbor_count == 1 &&
                capture.stderr_buffer.data &&
                strstr(capture.stderr_buffer.data, "Invalid command input on line 2"),
                "Oversized config line is rejected whole and following line executes");
    output_buffer_free(&capture.stdout_buffer);
    output_buffer_free(&capture.stderr_buffer);
    bgp_shutdown_sim(&sim);
}

/*
 * Test 14: Multiple routers
 */
void test_multiple_routers() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);

    const char *config =
        "router bgp 65000\n"
        " neighbor 10.0.0.1 remote-as 65001\n"
        "router bgp 65001\n"
        " neighbor 10.0.0.2 remote-as 65000\n";
    create_temp_config("/tmp/test_multi_router.conf", config);

    int result = parse_config_file("/tmp/test_multi_router.conf", &sim);
    unlink("/tmp/test_multi_router.conf");

    int passed = (result == 0) && (sim.router_count == 2);
    test_result(passed, "Multiple routers configuration");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 18: Duplicate router definition
 */
void test_duplicate_router() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);

    const char *config =
        "router bgp 65000\n"
        "router bgp 65000\n";
    create_temp_config("/tmp/test_dup_router.conf", config);

    int rc = parse_config_file("/tmp/test_dup_router.conf", &sim);
    unlink("/tmp/test_dup_router.conf");

    test_result(rc == 0 && sim.router_count == 1 && bgp_find_router(&sim, 65000),
                "Duplicate router command selects existing router without allocating another");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 20: Exit command
 */
void test_exit_command() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);

    const char *config =
        "router bgp 65000\n"
        " neighbor 10.0.0.1 remote-as 65001\n"
        " exit\n"
        "router bgp 65001\n";
    create_temp_config("/tmp/test_exit.conf", config);

    int rc = parse_config_file("/tmp/test_exit.conf", &sim);
    unlink("/tmp/test_exit.conf");

    bgp_router_t *first = bgp_find_router(&sim, 65000);
    bgp_router_t *second = bgp_find_router(&sim, 65001);
    test_result(rc == 0 && sim.router_count == 2 && first && first->neighbor_count == 1 &&
                second && second->neighbor_count == 0, "Exit leaves neighbor context and permits another router");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 21: Router ID configuration
 */
void test_router_id_command() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);

    const char *config =
        "router bgp 65000\n"
        " router-id 1.2.3.4\n";
    create_temp_config("/tmp/test_router_id_cmd.conf", config);

    int result = parse_config_file("/tmp/test_router_id_cmd.conf", &sim);
    unlink("/tmp/test_router_id_cmd.conf");

    bgp_router_t *router = bgp_find_router(&sim, 65000);
    int passed = (result == 0) && (router != NULL) &&
                 (router->router_id_configured == 1) && router->router_id == ntohl(inet_addr("1.2.3.4"));
    test_result(passed, "Router ID configuration");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 22: Update source configuration
 */
void test_update_source_command() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);

    const char *config =
        "router bgp 65000\n"
        " update-source 192.168.1.1\n";
    create_temp_config("/tmp/test_update_src_cmd.conf", config);

    int result = parse_config_file("/tmp/test_update_src_cmd.conf", &sim);
    unlink("/tmp/test_update_src_cmd.conf");

    bgp_router_t *router = bgp_find_router(&sim, 65000);
    int passed = (result == 0) && (router != NULL) &&
                 (strcmp(router->source_ip, "192.168.1.1") == 0);
    test_result(passed, "Update source configuration");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 23: Neighbor update-source override should validate IPv6 literals
 */
void test_neighbor_ipv6_update_source_command() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 65000", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "update-source 2001:db8::100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 2001:db8::1 remote-as 65001", &mode, &router, &neighbor);
    int result = test_exec_config_session(&sim, "update-source 2001:db8::200", &mode, &router, &neighbor);

    int passed = (result == 1) &&
                 (router != NULL) &&
                 (neighbor != NULL) &&
                 (strcmp(router->source_ip, "2001:db8::100") == 0) &&
                 (strcmp(neighbor->source_ip, "2001:db8::200") == 0);
    test_result(passed, "Neighbor IPv6 update-source override");

    bgp_shutdown_sim(&sim);
}

/*
 * Test 23: Address family IPv4 configuration
 */
void test_address_family_ipv4() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);

    const char *config =
        "router bgp 65000\n"
        " neighbor 10.0.0.1 remote-as 65001\n"
        " address-family ipv4\n";
    create_temp_config("/tmp/test_af_ipv4.conf", config);

    int result = parse_config_file("/tmp/test_af_ipv4.conf", &sim);
    unlink("/tmp/test_af_ipv4.conf");

    bgp_router_t *router = bgp_find_router(&sim, 65000);
    int passed = (result == 0) && (router != NULL) &&
                 (router->neighbor_count > 0) &&
                 (router->neighbors[0]->capabilities.ipv4_unicast == 1);
    test_result(passed, "Address family IPv4 configuration");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 24: Address family IPv6 configuration
 */
void test_address_family_ipv6() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);

    const char *config =
        "router bgp 65000\n"
        " neighbor 10.0.0.1 remote-as 65001\n"
        " address-family ipv6\n";
    create_temp_config("/tmp/test_af_ipv6.conf", config);

    int result = parse_config_file("/tmp/test_af_ipv6.conf", &sim);
    unlink("/tmp/test_af_ipv6.conf");

    bgp_router_t *router = bgp_find_router(&sim, 65000);
    int passed = (result == 0) && (router != NULL) &&
                 (router->neighbor_count > 0) &&
                 (router->neighbors[0]->capabilities.ipv6_unicast == 1);
    test_result(passed, "Address family IPv6 configuration");
    bgp_shutdown_sim(&sim);
}

void test_address_family_ipv4_labels() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);

    const char *config =
        "router bgp 65000\n"
        " neighbor 10.0.0.1 remote-as 65001\n"
        " address-family ipv4 labels\n";
    create_temp_config("/tmp/test_af_ipv4_labels.conf", config);

    int result = parse_config_file("/tmp/test_af_ipv4_labels.conf", &sim);
    unlink("/tmp/test_af_ipv4_labels.conf");

    bgp_router_t *router = bgp_find_router(&sim, 65000);
    int passed = (result == 0) && (router != NULL) &&
                 (router->neighbor_count > 0) &&
                 (router->neighbors[0]->capabilities.ipv4_labeled_unicast == 1);
    test_result(passed, "Address family IPv4 labels configuration");
    bgp_shutdown_sim(&sim);
}

void test_capability_ext_nh_config() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);

    const char *config =
        "router bgp 65000\n"
        " neighbor 10.0.0.1 remote-as 65001\n"
        " capability ext-nh ipv4 labels\n";
    create_temp_config("/tmp/test_cap_ext_nh.conf", config);

    int result = parse_config_file("/tmp/test_cap_ext_nh.conf", &sim);
    unlink("/tmp/test_cap_ext_nh.conf");

    bgp_router_t *router = bgp_find_router(&sim, 65000);
    int passed = (result == 0) && (router != NULL) &&
                 (router->neighbor_count > 0) &&
                 (router->neighbors[0]->capabilities.ext_nh_ipv4_labeled_unicast_over_ipv6 == 1);
    test_result(passed, "Capability ext-nh configuration");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 25: Capability route-refresh configuration
 */
void test_capability_route_refresh() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);

    const char *config =
        "router bgp 65000\n"
        " neighbor 10.0.0.1 remote-as 65001\n"
        " capability route-refresh\n";
    create_temp_config("/tmp/test_cap_rr.conf", config);

    int result = parse_config_file("/tmp/test_cap_rr.conf", &sim);
    unlink("/tmp/test_cap_rr.conf");

    bgp_router_t *router = bgp_find_router(&sim, 65000);
    int passed = (result == 0) && (router != NULL) &&
                 (router->neighbor_count > 0) &&
                 (router->neighbors[0]->capabilities.route_refresh == 1);
    test_result(passed, "Capability route-refresh configuration");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 26: Capability graceful-restart configuration
 */
void test_capability_graceful_restart() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);

    const char *config =
        "router bgp 65000\n"
        " neighbor 10.0.0.1 remote-as 65001\n"
        " capability graceful-restart restart-time 180\n";
    create_temp_config("/tmp/test_cap_gr.conf", config);

    int result = parse_config_file("/tmp/test_cap_gr.conf", &sim);
    unlink("/tmp/test_cap_gr.conf");

    bgp_router_t *router = bgp_find_router(&sim, 65000);
    int passed = (result == 0) && (router != NULL) &&
                 (router->neighbor_count > 0) &&
                 (router->neighbors[0]->capabilities.graceful_restart == 1) &&
                 (router->neighbors[0]->capabilities.restart_time == 180);
    test_result(passed, "Capability graceful-restart configuration");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 27: RIB-OUT configuration
 */
void test_ribout_config() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);

    const char *config =
        "ribout test1\n"
        " prefix 10.0.0.0/24\n";
    create_temp_config("/tmp/test_ribout.conf", config);

    int result = parse_config_file("/tmp/test_ribout.conf", &sim);
    unlink("/tmp/test_ribout.conf");

    int passed = (result == 0) && (sim.ribout_count > 0);
    test_result(passed, "RIB-OUT configuration");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 28: RIB-OUT with multiple attributes
 */
void test_ribout_attributes() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);

    const char *config =
        "ribout test2\n"
        " prefix 192.168.0.0/16\n"
        " next-hop 10.1.1.1\n"
        " as-path 100 200 300\n";
    create_temp_config("/tmp/test_ribout_attr.conf", config);

    int result = parse_config_file("/tmp/test_ribout_attr.conf", &sim);
    unlink("/tmp/test_ribout_attr.conf");

    int passed = (result == 0) && (sim.ribout_count > 0);
    test_result(passed, "RIB-OUT with multiple attributes");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 29: "no" command parsing
 */
void test_no_neighbor() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);

    const char *config =
        "router bgp 65000\n"
        " neighbor 10.0.0.1 remote-as 65001\n"
        "router bgp 65001\n"
        "no router bgp 65000\n";
    create_temp_config("/tmp/test_no_cmd.conf", config);

    parse_config_file("/tmp/test_no_cmd.conf", &sim);
    unlink("/tmp/test_no_cmd.conf");

    // Test that "no" commands are handled without crash and router is removed
    int passed = (bgp_find_router(&sim, 65000) == NULL);
    test_result(passed, "No command parsing");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 30: VPNv4 address family configuration
 */
void test_address_family_vpnv4() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);

    const char *config =
        "router bgp 65000\n"
        " neighbor 10.0.0.1 remote-as 65001\n"
        " address-family vpnv4\n";
    create_temp_config("/tmp/test_af_vpnv4.conf", config);

    int result = parse_config_file("/tmp/test_af_vpnv4.conf", &sim);
    unlink("/tmp/test_af_vpnv4.conf");

    bgp_router_t *router = bgp_find_router(&sim, 65000);
    int passed = (result == 0) && (router != NULL) &&
                 (router->neighbor_count > 0) &&
                 (router->neighbors[0]->capabilities.vpnv4_unicast == 1);
    test_result(passed, "Address family VPNv4 configuration");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 31: Invalid nested line should not lose parser context
 */
void test_invalid_nested_line_recovery() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);

    const char *config =
        "router bgp 65000\n"
        " neighbor 10.0.0.1 remote-as 65001\n"
        " invalid-command xyz\n"
        " capability route-refresh\n"
        " exit\n"
        " update-source 192.168.1.1\n";
    create_temp_config("/tmp/test_invalid_nested.conf", config);

    int result = parse_config_file("/tmp/test_invalid_nested.conf", &sim);
    unlink("/tmp/test_invalid_nested.conf");

    bgp_router_t *router = bgp_find_router(&sim, 65000);
    int passed = (result == 0) && (router != NULL) &&
                 (router->neighbor_count == 1) &&
                 (router->neighbors[0]->capabilities.route_refresh == 1) &&
                 (strcmp(router->source_ip, "192.168.1.1") == 0);
    test_result(passed, "Invalid nested line preserves config context");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 32: Maximum 4-byte ASN values should parse cleanly
 */
void test_large_asn_boundary() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);

    const char *config =
        "router bgp 4294967295\n"
        " neighbor 192.0.2.1 remote-as 4294967294\n";
    create_temp_config("/tmp/test_large_asn.conf", config);

    int result = parse_config_file("/tmp/test_large_asn.conf", &sim);
    unlink("/tmp/test_large_asn.conf");

    bgp_router_t *router = bgp_find_router(&sim, 4294967295U);
    int passed = (result == 0) && (router != NULL) &&
                 (router->neighbor_count == 1) &&
                 (router->neighbors[0]->remote_as == 4294967294U);
    test_result(passed, "Maximum 4-byte ASN configuration");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 33: AS 0 should follow the parser's current uint32 semantics
 */
void test_as_zero_configuration() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);

    const char *config =
        "router bgp 0\n"
        " neighbor 192.0.2.2 remote-as 100\n";
    create_temp_config("/tmp/test_as_zero.conf", config);

    int result = parse_config_file("/tmp/test_as_zero.conf", &sim);
    unlink("/tmp/test_as_zero.conf");

    bgp_router_t *router = bgp_find_router(&sim, 0);
    int passed = (result == 0) && (router != NULL) &&
                 (router->neighbor_count == 1) &&
                 (strcmp(router->neighbors[0]->ip, "192.0.2.2") == 0) &&
                 (router->neighbors[0]->remote_as == 100);
    test_result(passed, "AS 0 configuration");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 34: The same neighbor IP can exist on different routers
 */
void test_same_neighbor_ip_different_routers() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);

    const char *config =
        "router bgp 65000\n"
        " neighbor 198.51.100.1 remote-as 65100\n"
        "router bgp 65001\n"
        " neighbor 198.51.100.1 remote-as 65101\n";
    create_temp_config("/tmp/test_same_neighbor_ip.conf", config);

    int result = parse_config_file("/tmp/test_same_neighbor_ip.conf", &sim);
    unlink("/tmp/test_same_neighbor_ip.conf");

    bgp_router_t *router1 = bgp_find_router(&sim, 65000);
    bgp_router_t *router2 = bgp_find_router(&sim, 65001);
    int passed = (result == 0) &&
                 (router1 != NULL) && (router2 != NULL) &&
                 (router1->neighbor_count == 1) &&
                 (router2->neighbor_count == 1) &&
                 (strcmp(router1->neighbors[0]->ip, "198.51.100.1") == 0) &&
                 (strcmp(router2->neighbors[0]->ip, "198.51.100.1") == 0) &&
                 (router1->neighbors[0]->remote_as == 65100) &&
                 (router2->neighbors[0]->remote_as == 65101);
    test_result(passed, "Same neighbor IP on different routers");
    bgp_shutdown_sim(&sim);
}

// Capability configuration tests

void test_enable_ipv4_unicast() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", &mode, &router, &neighbor);
    int result = test_exec_config_session(&sim, "address-family ipv4", &mode, &router, &neighbor);

    bgp_neighbor_t *nbr = sim.routers[0]->neighbors[0];
    test_result(result == 1 && nbr->capabilities.ipv4_unicast == 1, "Enable IPv4 unicast address family");

    bgp_shutdown_sim(&sim);
}

void test_enable_ipv6_unicast() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", &mode, &router, &neighbor);
    int result = test_exec_config_session(&sim, "address-family ipv6", &mode, &router, &neighbor);

    bgp_neighbor_t *nbr = sim.routers[0]->neighbors[0];
    test_result(result == 1 && nbr->capabilities.ipv6_unicast == 1, "Enable IPv6 unicast address family");

    bgp_shutdown_sim(&sim);
}

void test_enable_ipv4_labels() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", &mode, &router, &neighbor);
    int result = test_exec_config_session(&sim, "address-family ipv4 labels", &mode, &router, &neighbor);

    bgp_neighbor_t *nbr = sim.routers[0]->neighbors[0];
    test_result(result == 1 && nbr->capabilities.ipv4_labeled_unicast == 1, "Enable IPv4 labels address family");

    bgp_shutdown_sim(&sim);
}

void test_enable_ipv6_labels() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", &mode, &router, &neighbor);
    int result = test_exec_config_session(&sim, "address-family ipv6 labels", &mode, &router, &neighbor);

    bgp_neighbor_t *nbr = sim.routers[0]->neighbors[0];
    test_result(result == 1 && nbr->capabilities.ipv6_labeled_unicast == 1, "Enable IPv6 labels address family");

    bgp_shutdown_sim(&sim);
}

void test_enable_vpnv4() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", &mode, &router, &neighbor);
    int result = test_exec_config_session(&sim, "address-family vpnv4", &mode, &router, &neighbor);

    bgp_neighbor_t *nbr = sim.routers[0]->neighbors[0];
    test_result(result == 1 && nbr->capabilities.vpnv4_unicast == 1, "Enable VPNv4 address family");

    bgp_shutdown_sim(&sim);
}

void test_enable_vpnv6() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", &mode, &router, &neighbor);
    int result = test_exec_config_session(&sim, "address-family vpnv6", &mode, &router, &neighbor);

    bgp_neighbor_t *nbr = sim.routers[0]->neighbors[0];
    test_result(result == 1 && nbr->capabilities.vpnv6_unicast == 1, "Enable VPNv6 address family");

    bgp_shutdown_sim(&sim);
}

void test_enable_evpn() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", &mode, &router, &neighbor);
    int result = test_exec_config_session(&sim, "address-family l2vpn evpn", &mode, &router, &neighbor);

    bgp_neighbor_t *nbr = sim.routers[0]->neighbors[0];
    test_result(result == 1 && nbr->capabilities.evpn == 1, "Enable EVPN address family");

    bgp_shutdown_sim(&sim);
}

void test_enable_route_refresh() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", &mode, &router, &neighbor);
    int result = test_exec_config_session(&sim, "capability route-refresh", &mode, &router, &neighbor);

    bgp_neighbor_t *nbr = sim.routers[0]->neighbors[0];
    test_result(result == 1 && nbr->capabilities.route_refresh == 1, "Enable route refresh capability");

    bgp_shutdown_sim(&sim);
}

void test_default_four_byte_asn_capability() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", &mode, &router, &neighbor);

    test_result(neighbor != NULL && neighbor->capabilities.four_byte_asn == 1, "Four-byte ASN capability defaults on");

    bgp_shutdown_sim(&sim);
}

void test_disable_four_byte_asn() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", &mode, &router, &neighbor);
    int result = test_exec_config_session(&sim, "no capability four-byte-asn", &mode, &router, &neighbor);

    test_result(result == 1 && neighbor != NULL &&
                neighbor->capabilities.four_byte_asn == 0,
                "Disable four-byte ASN capability");

    bgp_shutdown_sim(&sim);
}

void test_disable_four_byte_asn_rejects_large_local_as() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 70000", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", &mode, &router, &neighbor);
    int result = test_exec_config_session(&sim, "no capability four-byte-asn", &mode, &router, &neighbor);

    test_result(result < 0 && neighbor != NULL &&
                neighbor->capabilities.four_byte_asn == 1,
                "Reject disabling four-byte ASN with large local AS");

    bgp_shutdown_sim(&sim);
}

void test_disable_four_byte_asn_rejects_large_remote_as() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 70000", &mode, &router, &neighbor);
    int result = test_exec_config_session(&sim, "no capability four-byte-asn", &mode, &router, &neighbor);

    test_result(result < 0 && neighbor != NULL &&
                neighbor->capabilities.four_byte_asn == 1,
                "Reject disabling four-byte ASN with large remote AS");

    bgp_shutdown_sim(&sim);
}

void test_running_config_four_byte_asn_default_and_override() {
    bgp_sim_t          sim = {0};
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;
    char               config_output[CONFIG_CAPTURE_SIZE];
    int                first_ok;
    int                second_ok;

    bgp_init_simulator(&sim);

    test_exec_config_session(&sim, "router bgp 100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", &mode, &router, &neighbor);

    first_ok = capture_running_config(&sim, config_output, sizeof(config_output)) == 0 &&
               strstr(config_output, "four-byte-asn") == NULL;

    test_exec_config_session(&sim, "no capability four-byte-asn", &mode, &router, &neighbor);

    second_ok = capture_running_config(&sim, config_output, sizeof(config_output)) == 0 &&
                strstr(config_output, "no capability four-byte-asn") != NULL;

    test_result(first_ok && second_ok, "Running-config omits default four-byte ASN and prints override");

    bgp_shutdown_sim(&sim);
}

void test_enable_graceful_restart() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", &mode, &router, &neighbor);
    int result = test_exec_config_session(&sim, "capability graceful-restart", &mode, &router, &neighbor);

    bgp_neighbor_t *nbr = sim.routers[0]->neighbors[0];
    test_result(result == 1 && nbr->capabilities.graceful_restart == 1 &&
                nbr->capabilities.restart_time == 120,
                "Enable graceful restart capability (default restart-time)");

    bgp_shutdown_sim(&sim);
}

void test_enable_graceful_restart_custom_time() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", &mode, &router, &neighbor);
    int result = test_exec_config_session(&sim, "capability graceful-restart restart-time 300", &mode, &router,
                                            &neighbor);

    bgp_neighbor_t *nbr = sim.routers[0]->neighbors[0];
    test_result(result == 1 && nbr->capabilities.graceful_restart == 1 &&
                nbr->capabilities.restart_time == 300,
                "Enable graceful restart with custom restart-time");

    bgp_shutdown_sim(&sim);
}

void test_enable_add_path() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", &mode, &router, &neighbor);
    int result = test_exec_config_session(&sim, "capability add-path", &mode, &router, &neighbor);

    bgp_neighbor_t *nbr = sim.routers[0]->neighbors[0];
    test_result(result == 1 &&
                nbr->capabilities.add_path_ipv4 == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                nbr->capabilities.add_path_ipv6 == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                nbr->capabilities.add_path_ipv4_labeled == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                nbr->capabilities.add_path_ipv6_labeled == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                nbr->capabilities.add_path_vpnv4 == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                nbr->capabilities.add_path_vpnv6 == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                nbr->capabilities.add_path_evpn == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                nbr->capabilities.add_path_ipv4_flowspec == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                nbr->capabilities.add_path_ipv6_flowspec == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                nbr->capabilities.add_path_ipv4_flowspec_vpn == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                nbr->capabilities.add_path_ipv6_flowspec_vpn == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                nbr->capabilities.add_path_ipv4_srpolicy == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                nbr->capabilities.add_path_ipv6_srpolicy == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                nbr->capabilities.add_path_bgp_ls == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                nbr->capabilities.add_path_ipv4_mvpn == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                nbr->capabilities.add_path_ipv6_mvpn == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                nbr->capabilities.add_path_ipv4_rtc == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                nbr->capabilities.add_path_vpls == (ADD_PATH_SEND | ADD_PATH_RECEIVE),
                "Enable ADD-PATH capability");

    bgp_shutdown_sim(&sim);
}

void test_enable_add_path_specific_af() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", &mode, &router, &neighbor);
    int result = test_exec_config_session(&sim, "capability add-path ipv4 labels", &mode, &router, &neighbor);

    bgp_neighbor_t *nbr = sim.routers[0]->neighbors[0];
    test_result(result == 1 &&
                nbr->capabilities.add_path_ipv4 == 0 &&
                nbr->capabilities.add_path_ipv4_labeled == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                nbr->capabilities.add_path_vpnv4 == 0,
                "Enable ADD-PATH for a specific address family");

    bgp_shutdown_sim(&sim);
}

void test_enable_ext_nh() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", &mode, &router, &neighbor);
    int result = test_exec_config_session(&sim, "capability ext-nh", &mode, &router, &neighbor);

    bgp_neighbor_t *nbr = sim.routers[0]->neighbors[0];
    test_result(result == 1 &&
                nbr->capabilities.ext_nh_ipv4_unicast_over_ipv6 == 1 &&
                nbr->capabilities.ext_nh_ipv4_labeled_unicast_over_ipv6 == 1 &&
                nbr->capabilities.ext_nh_vpnv4_unicast_over_ipv6 == 1,
                "Enable RFC 8950 extended next-hop");

    bgp_shutdown_sim(&sim);
}

void test_enable_ext_nh_specific_af() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", &mode, &router, &neighbor);
    int result = test_exec_config_session(&sim, "capability ext-nh vpnv4", &mode, &router, &neighbor);

    bgp_neighbor_t *nbr = sim.routers[0]->neighbors[0];
    test_result(result == 1 &&
                nbr->capabilities.ext_nh_ipv4_unicast_over_ipv6 == 0 &&
                nbr->capabilities.ext_nh_ipv4_labeled_unicast_over_ipv6 == 0 &&
                nbr->capabilities.ext_nh_vpnv4_unicast_over_ipv6 == 1,
                "Enable RFC 8950 extended next-hop for a specific address family");

    bgp_shutdown_sim(&sim);
}

void test_disable_ipv4_unicast() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "address-family ipv4", &mode, &router, &neighbor);
    int result = test_exec_config_session(&sim, "no address-family ipv4", &mode, &router, &neighbor);

    bgp_neighbor_t *nbr = sim.routers[0]->neighbors[0];
    test_result(result == 1 && nbr->capabilities.ipv4_unicast == 0, "Disable IPv4 unicast with 'no' command");

    bgp_shutdown_sim(&sim);
}

void test_disable_ipv6_unicast() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "address-family ipv6", &mode, &router, &neighbor);
    int result = test_exec_config_session(&sim, "no address-family ipv6", &mode, &router, &neighbor);

    bgp_neighbor_t *nbr = sim.routers[0]->neighbors[0];
    test_result(result == 1 && nbr->capabilities.ipv6_unicast == 0, "Disable IPv6 unicast with 'no' command");

    bgp_shutdown_sim(&sim);
}

void test_disable_ipv4_labels() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "address-family ipv4 labels", &mode, &router, &neighbor);
    int result = test_exec_config_session(&sim, "no address-family ipv4 labels", &mode, &router, &neighbor);

    bgp_neighbor_t *nbr = sim.routers[0]->neighbors[0];
    test_result(result == 1 && nbr->capabilities.ipv4_labeled_unicast == 0, "Disable IPv4 labels with 'no' command");

    bgp_shutdown_sim(&sim);
}

void test_disable_ipv6_labels() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "address-family ipv6 labels", &mode, &router, &neighbor);
    int result = test_exec_config_session(&sim, "no address-family ipv6 labels", &mode, &router, &neighbor);

    bgp_neighbor_t *nbr = sim.routers[0]->neighbors[0];
    test_result(result == 1 && nbr->capabilities.ipv6_labeled_unicast == 0, "Disable IPv6 labels with 'no' command");

    bgp_shutdown_sim(&sim);
}

void test_disable_vpnv4() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "address-family vpnv4", &mode, &router, &neighbor);
    int result = test_exec_config_session(&sim, "no address-family vpnv4", &mode, &router, &neighbor);

    bgp_neighbor_t *nbr = sim.routers[0]->neighbors[0];
    test_result(result == 1 && nbr->capabilities.vpnv4_unicast == 0, "Disable VPNv4 with 'no' command");

    bgp_shutdown_sim(&sim);
}

void test_disable_vpnv6() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "address-family vpnv6", &mode, &router, &neighbor);
    int result = test_exec_config_session(&sim, "no address-family vpnv6", &mode, &router, &neighbor);

    bgp_neighbor_t *nbr = sim.routers[0]->neighbors[0];
    test_result(result == 1 && nbr->capabilities.vpnv6_unicast == 0, "Disable VPNv6 with 'no' command");

    bgp_shutdown_sim(&sim);
}

void test_disable_evpn() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "address-family l2vpn evpn", &mode, &router, &neighbor);
    int result = test_exec_config_session(&sim, "no address-family l2vpn evpn", &mode, &router, &neighbor);

    bgp_neighbor_t *nbr = sim.routers[0]->neighbors[0];
    test_result(result == 1 && nbr->capabilities.evpn == 0, "Disable EVPN with 'no' command");

    bgp_shutdown_sim(&sim);
}

// New address family enable/disable tests

#define DEFINE_AF_ENABLE_TEST(name, af_cmd, field)                        \
void test_enable_##name() {                                               \
    bgp_sim_t sim = {0};                                                  \
    bgp_init_simulator(&sim);                                             \
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};                  \
    bgp_router_t      *router = NULL;                                     \
    bgp_neighbor_t    *neighbor = NULL;                                   \
    test_exec_config_session(&sim, "router bgp 100", &mode, &router,      \
                               &neighbor);                                \
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200",     \
                               &mode, &router, &neighbor);                \
    int result = test_exec_config_session(&sim, "address-family " af_cmd, \
                                            &mode, &router, &neighbor);   \
    bgp_neighbor_t *nbr = sim.routers[0]->neighbors[0];                   \
    test_result(result == 1 && nbr->capabilities.field == 1,              \
                "Enable " af_cmd " address family");                      \
    bgp_shutdown_sim(&sim);                                               \
}

#define DEFINE_AF_DISABLE_TEST(name, af_cmd, field)                   \
void test_disable_##name() {                                          \
    bgp_sim_t sim = {0};                                              \
    bgp_init_simulator(&sim);                                         \
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};              \
    bgp_router_t      *router = NULL;                                 \
    bgp_neighbor_t    *neighbor = NULL;                               \
    test_exec_config_session(&sim, "router bgp 100", &mode, &router,  \
                               &neighbor);                            \
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", \
                               &mode, &router, &neighbor);            \
    test_exec_config_session(&sim, "address-family " af_cmd,          \
                               &mode, &router, &neighbor);            \
    int result = test_exec_config_session(&sim,                       \
                               "no address-family " af_cmd,           \
                               &mode, &router, &neighbor);            \
    bgp_neighbor_t *nbr = sim.routers[0]->neighbors[0];               \
    test_result(result == 1 && nbr->capabilities.field == 0,          \
                "Disable " af_cmd " with 'no' command");              \
    bgp_shutdown_sim(&sim);                                           \
}

DEFINE_AF_ENABLE_TEST(ipv4_flowspec,  "ipv4 flowspec",  ipv4_flowspec)
DEFINE_AF_ENABLE_TEST(ipv6_flowspec,  "ipv6 flowspec",  ipv6_flowspec)
DEFINE_AF_ENABLE_TEST(ipv4_flowspec_vpn, "ipv4 flowspec-vpn", ipv4_flowspec_vpn)
DEFINE_AF_ENABLE_TEST(ipv6_flowspec_vpn, "ipv6 flowspec-vpn", ipv6_flowspec_vpn)
DEFINE_AF_ENABLE_TEST(ipv4_srpolicy,  "ipv4 srpolicy",  ipv4_srpolicy)
DEFINE_AF_ENABLE_TEST(ipv6_srpolicy,  "ipv6 srpolicy",  ipv6_srpolicy)
DEFINE_AF_ENABLE_TEST(bgp_ls,        "bgp-ls",         bgp_ls)
DEFINE_AF_ENABLE_TEST(ipv4_mvpn,     "ipv4 mvpn",      ipv4_mvpn)
DEFINE_AF_ENABLE_TEST(ipv6_mvpn,     "ipv6 mvpn",      ipv6_mvpn)
DEFINE_AF_ENABLE_TEST(ipv4_rtc,      "ipv4 rtc",       ipv4_rtc)
DEFINE_AF_ENABLE_TEST(vpls,          "l2vpn vpls",      vpls)

DEFINE_AF_DISABLE_TEST(ipv4_flowspec, "ipv4 flowspec",  ipv4_flowspec)
DEFINE_AF_DISABLE_TEST(ipv6_flowspec, "ipv6 flowspec",  ipv6_flowspec)
DEFINE_AF_DISABLE_TEST(ipv4_flowspec_vpn, "ipv4 flowspec-vpn", ipv4_flowspec_vpn)
DEFINE_AF_DISABLE_TEST(ipv6_flowspec_vpn, "ipv6 flowspec-vpn", ipv6_flowspec_vpn)
DEFINE_AF_DISABLE_TEST(ipv4_srpolicy, "ipv4 srpolicy",  ipv4_srpolicy)
DEFINE_AF_DISABLE_TEST(ipv6_srpolicy, "ipv6 srpolicy",  ipv6_srpolicy)
DEFINE_AF_DISABLE_TEST(bgp_ls,       "bgp-ls",         bgp_ls)
DEFINE_AF_DISABLE_TEST(ipv4_mvpn,    "ipv4 mvpn",      ipv4_mvpn)
DEFINE_AF_DISABLE_TEST(ipv6_mvpn,    "ipv6 mvpn",      ipv6_mvpn)
DEFINE_AF_DISABLE_TEST(ipv4_rtc,     "ipv4 rtc",       ipv4_rtc)
DEFINE_AF_DISABLE_TEST(vpls,         "l2vpn vpls",      vpls)

void test_disable_route_refresh() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "capability route-refresh", &mode, &router, &neighbor);
    int result = test_exec_config_session(&sim, "no capability route-refresh", &mode, &router, &neighbor);

    bgp_neighbor_t *nbr = sim.routers[0]->neighbors[0];
    test_result(result == 1 && nbr->capabilities.route_refresh == 0, "Disable route refresh with 'no' command");

    bgp_shutdown_sim(&sim);
}

void test_disable_graceful_restart() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "capability graceful-restart restart-time 300", &mode, &router, &neighbor);
    int result = test_exec_config_session(&sim, "no capability graceful-restart", &mode, &router, &neighbor);

    bgp_neighbor_t *nbr = sim.routers[0]->neighbors[0];
    test_result(result == 1 && nbr->capabilities.graceful_restart == 0 &&
                nbr->capabilities.restart_time == 0,
                "Disable graceful restart with 'no' command");

    bgp_shutdown_sim(&sim);
}

void test_disable_add_path() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "capability add-path", &mode, &router, &neighbor);
    int result = test_exec_config_session(&sim, "no capability add-path", &mode, &router, &neighbor);

    bgp_neighbor_t *nbr = sim.routers[0]->neighbors[0];
    test_result(result == 1 &&
                nbr->capabilities.add_path_ipv4 == 0 &&
                nbr->capabilities.add_path_ipv6 == 0 &&
                nbr->capabilities.add_path_ipv4_labeled == 0 &&
                nbr->capabilities.add_path_ipv6_labeled == 0 &&
                nbr->capabilities.add_path_vpnv4 == 0 &&
                nbr->capabilities.add_path_vpnv6 == 0 &&
                nbr->capabilities.add_path_evpn == 0 &&
                nbr->capabilities.add_path_ipv4_flowspec == 0 &&
                nbr->capabilities.add_path_ipv6_flowspec == 0 &&
                nbr->capabilities.add_path_ipv4_flowspec_vpn == 0 &&
                nbr->capabilities.add_path_ipv6_flowspec_vpn == 0 &&
                nbr->capabilities.add_path_ipv4_srpolicy == 0 &&
                nbr->capabilities.add_path_ipv6_srpolicy == 0 &&
                nbr->capabilities.add_path_bgp_ls == 0 &&
                nbr->capabilities.add_path_ipv4_mvpn == 0 &&
                nbr->capabilities.add_path_ipv6_mvpn == 0 &&
                nbr->capabilities.add_path_ipv4_rtc == 0 &&
                nbr->capabilities.add_path_vpls == 0,
                "Disable ADD-PATH with 'no' command");

    bgp_shutdown_sim(&sim);
}

void test_disable_ext_nh() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "capability ext-nh", &mode, &router, &neighbor);
    int result = test_exec_config_session(&sim, "no capability ext-nh", &mode, &router, &neighbor);

    bgp_neighbor_t *nbr = sim.routers[0]->neighbors[0];
    test_result(result == 1 &&
                nbr->capabilities.ext_nh_ipv4_unicast_over_ipv6 == 0 &&
                nbr->capabilities.ext_nh_ipv4_labeled_unicast_over_ipv6 == 0 &&
                nbr->capabilities.ext_nh_vpnv4_unicast_over_ipv6 == 0,
                "Disable RFC 8950 extended next-hop with 'no' command");

    bgp_shutdown_sim(&sim);
}

void test_multiple_capabilities() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t mode = {.mode = CLI_MODE_CONFIG};
    bgp_router_t      *router = NULL;
    bgp_neighbor_t    *neighbor = NULL;

    test_exec_config_session(&sim, "router bgp 100", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "neighbor 10.0.0.1 remote-as 200", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "address-family ipv4", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "address-family ipv6", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "capability route-refresh", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "capability graceful-restart restart-time 180", &mode, &router, &neighbor);
    test_exec_config_session(&sim, "capability add-path", &mode, &router, &neighbor);

    bgp_neighbor_t *nbr = sim.routers[0]->neighbors[0];
    test_result(nbr->capabilities.ipv4_unicast == 1 &&
                nbr->capabilities.ipv6_unicast == 1 &&
                nbr->capabilities.route_refresh == 1 &&
                nbr->capabilities.graceful_restart == 1 &&
                nbr->capabilities.restart_time == 180 &&
                nbr->capabilities.add_path_ipv4 == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                nbr->capabilities.add_path_ipv6 == (ADD_PATH_SEND | ADD_PATH_RECEIVE),
                "Multiple capabilities enabled together");

    bgp_shutdown_sim(&sim);
}

// Running-config round-trip tests

void test_basic_roundtrip() {
    bgp_sim_t sim1, sim2;

    bgp_init_simulator(&sim1);
    bgp_add_router(&sim1, 100);
    bgp_add_neighbor(&sim1, 100, "192.168.1.1", 200);

    bgp_router_t   *router1 = sim1.routers[0];
    bgp_neighbor_t *neighbor1 = router1->neighbors[0];
    strncpy(router1->source_ip, "192.0.2.10", sizeof(router1->source_ip) - 1);
    router1->source_ip[sizeof(router1->source_ip) - 1] = '\0';
    strncpy(neighbor1->source_ip, "192.0.2.20", sizeof(neighbor1->source_ip) - 1);
    neighbor1->source_ip[sizeof(neighbor1->source_ip) - 1] = '\0';
    neighbor1->capabilities.ipv4_unicast = 1;
    neighbor1->capabilities.route_refresh = 1;

    write_running_config_to_file(&sim1, TEST_CONFIG_FILE);

    bgp_init_simulator(&sim2);
    int result = parse_config_file(TEST_CONFIG_FILE, &sim2);

    int passed = (result >= 0 &&
                  sim2.router_count == 1 &&
                  sim2.routers[0]->local_as == 100 &&
                  sim2.routers[0]->neighbor_count == 1 &&
                  strcmp(sim2.routers[0]->source_ip, "192.0.2.10") == 0 &&
                  strcmp(sim2.routers[0]->neighbors[0]->ip, "192.168.1.1") == 0 &&
                  strcmp(sim2.routers[0]->neighbors[0]->source_ip, "192.0.2.20") == 0 &&
                  sim2.routers[0]->neighbors[0]->remote_as == 200 &&
                  sim2.routers[0]->neighbors[0]->capabilities.ipv4_unicast == 1 &&
                  sim2.routers[0]->neighbors[0]->capabilities.route_refresh == 1);

    test_result(passed, "Basic configuration round-trip");

    bgp_shutdown_sim(&sim1);
    bgp_shutdown_sim(&sim2);
    remove(TEST_CONFIG_FILE);
}

void test_multiple_routers_roundtrip() {
    bgp_sim_t sim1, sim2;

    bgp_init_simulator(&sim1);
    bgp_add_router(&sim1, 100);
    bgp_add_neighbor(&sim1, 100, "192.168.1.1", 200);
    bgp_add_neighbor(&sim1, 100, "192.168.1.2", 200);

    bgp_add_router(&sim1, 200);
    bgp_add_neighbor(&sim1, 200, "10.0.0.1", 100);

    sim1.routers[0]->neighbors[0]->capabilities.ipv4_unicast = 1;
    sim1.routers[0]->neighbors[0]->capabilities.ipv6_unicast = 1;
    sim1.routers[0]->neighbors[1]->capabilities.route_refresh = 1;
    sim1.routers[1]->neighbors[0]->capabilities.ipv4_unicast = 1;

    write_running_config_to_file(&sim1, TEST_CONFIG_FILE);
    bgp_init_simulator(&sim2);
    int result = parse_config_file(TEST_CONFIG_FILE, &sim2);

    int passed = (result >= 0 &&
                  sim2.router_count == 2 &&
                  sim2.routers[0]->neighbor_count == 2 &&
                  sim2.routers[1]->neighbor_count == 1 &&
                  sim2.routers[0]->neighbors[0]->capabilities.ipv4_unicast == 1 &&
                  sim2.routers[0]->neighbors[0]->capabilities.ipv6_unicast == 1 &&
                  sim2.routers[0]->neighbors[1]->capabilities.route_refresh == 1 &&
                  sim2.routers[1]->neighbors[0]->capabilities.ipv4_unicast == 1);

    test_result(passed, "Multiple routers and neighbors round-trip");

    bgp_shutdown_sim(&sim1);
    bgp_shutdown_sim(&sim2);
    remove(TEST_CONFIG_FILE);
}

void test_all_capabilities_roundtrip() {
    bgp_sim_t sim1, sim2;

    bgp_init_simulator(&sim1);
    bgp_add_router(&sim1, 100);
    bgp_add_neighbor(&sim1, 100, "192.168.1.1", 200);

    bgp_neighbor_t *neighbor = sim1.routers[0]->neighbors[0];
    neighbor->capabilities.ipv4_unicast = 1;
    neighbor->capabilities.ipv6_unicast = 1;
    neighbor->capabilities.ipv4_labeled_unicast = 1;
    neighbor->capabilities.ipv6_labeled_unicast = 1;
    neighbor->capabilities.vpnv4_unicast = 1;
    neighbor->capabilities.vpnv6_unicast = 1;
    neighbor->capabilities.evpn = 1;
    neighbor->capabilities.ipv4_flowspec = 1;
    neighbor->capabilities.ipv6_flowspec = 1;
    neighbor->capabilities.ipv4_flowspec_vpn = 1;
    neighbor->capabilities.ipv6_flowspec_vpn = 1;
    neighbor->capabilities.ipv4_srpolicy = 1;
    neighbor->capabilities.ipv6_srpolicy = 1;
    neighbor->capabilities.bgp_ls = 1;
    neighbor->capabilities.ipv4_mvpn = 1;
    neighbor->capabilities.ipv6_mvpn = 1;
    neighbor->capabilities.ipv4_rtc = 1;
    neighbor->capabilities.vpls = 1;
    neighbor->capabilities.route_refresh = 1;
    neighbor->capabilities.graceful_restart = 1;
    neighbor->capabilities.restart_time = 120;
    neighbor->capabilities.add_path_ipv4 = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->capabilities.add_path_ipv6 = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->capabilities.add_path_ipv4_labeled = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->capabilities.add_path_ipv6_labeled = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->capabilities.add_path_vpnv4 = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->capabilities.add_path_vpnv6 = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->capabilities.add_path_evpn = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->capabilities.add_path_ipv4_flowspec = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->capabilities.add_path_ipv6_flowspec = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->capabilities.add_path_ipv4_flowspec_vpn = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->capabilities.add_path_ipv6_flowspec_vpn = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->capabilities.add_path_ipv4_srpolicy = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->capabilities.add_path_ipv6_srpolicy = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->capabilities.add_path_bgp_ls = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->capabilities.add_path_ipv4_mvpn = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->capabilities.add_path_ipv6_mvpn = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->capabilities.add_path_ipv4_rtc = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->capabilities.add_path_vpls = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->capabilities.ext_nh_ipv4_unicast_over_ipv6 = 1;
    neighbor->capabilities.ext_nh_ipv4_labeled_unicast_over_ipv6 = 1;
    neighbor->capabilities.ext_nh_vpnv4_unicast_over_ipv6 = 1;

    write_running_config_to_file(&sim1, TEST_CONFIG_FILE);
    bgp_init_simulator(&sim2);
    int result = parse_config_file(TEST_CONFIG_FILE, &sim2);

    bgp_neighbor_t *neighbor2 = sim2.routers[0]->neighbors[0];
    int passed = (result >= 0 &&
                  neighbor2->capabilities.ipv4_unicast == 1 &&
                  neighbor2->capabilities.ipv6_unicast == 1 &&
                  neighbor2->capabilities.ipv4_labeled_unicast == 1 &&
                  neighbor2->capabilities.ipv6_labeled_unicast == 1 &&
                  neighbor2->capabilities.vpnv4_unicast == 1 &&
                  neighbor2->capabilities.vpnv6_unicast == 1 &&
                  neighbor2->capabilities.evpn == 1 &&
                  neighbor2->capabilities.ipv4_flowspec == 1 &&
                  neighbor2->capabilities.ipv6_flowspec == 1 &&
                  neighbor2->capabilities.ipv4_flowspec_vpn == 1 &&
                  neighbor2->capabilities.ipv6_flowspec_vpn == 1 &&
                  neighbor2->capabilities.ipv4_srpolicy == 1 &&
                  neighbor2->capabilities.ipv6_srpolicy == 1 &&
                  neighbor2->capabilities.bgp_ls == 1 &&
                  neighbor2->capabilities.ipv4_mvpn == 1 &&
                  neighbor2->capabilities.ipv6_mvpn == 1 &&
                  neighbor2->capabilities.ipv4_rtc == 1 &&
                  neighbor2->capabilities.vpls == 1 &&
                  neighbor2->capabilities.route_refresh == 1 &&
                  neighbor2->capabilities.graceful_restart == 1 &&
                  neighbor2->capabilities.restart_time == 120 &&
                  neighbor2->capabilities.add_path_ipv4 == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                  neighbor2->capabilities.add_path_ipv6 == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                  neighbor2->capabilities.add_path_ipv4_labeled == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                  neighbor2->capabilities.add_path_ipv6_labeled == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                  neighbor2->capabilities.add_path_vpnv4 == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                  neighbor2->capabilities.add_path_vpnv6 == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                  neighbor2->capabilities.add_path_evpn == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                  neighbor2->capabilities.add_path_ipv4_flowspec == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                  neighbor2->capabilities.add_path_ipv6_flowspec == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                  neighbor2->capabilities.add_path_ipv4_flowspec_vpn == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                  neighbor2->capabilities.add_path_ipv6_flowspec_vpn == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                  neighbor2->capabilities.add_path_ipv4_srpolicy == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                  neighbor2->capabilities.add_path_ipv6_srpolicy == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                  neighbor2->capabilities.add_path_bgp_ls == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                  neighbor2->capabilities.add_path_ipv4_mvpn == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                  neighbor2->capabilities.add_path_ipv6_mvpn == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                  neighbor2->capabilities.add_path_ipv4_rtc == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                  neighbor2->capabilities.add_path_vpls == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                  neighbor2->capabilities.ext_nh_ipv4_unicast_over_ipv6 == 1 &&
                  neighbor2->capabilities.ext_nh_ipv4_labeled_unicast_over_ipv6 == 1 &&
                  neighbor2->capabilities.ext_nh_vpnv4_unicast_over_ipv6 == 1);

    test_result(passed, "All capabilities round-trip");

    bgp_shutdown_sim(&sim1);
    bgp_shutdown_sim(&sim2);
    remove(TEST_CONFIG_FILE);
}

void test_add_path_mixed_roundtrip() {
    bgp_sim_t sim1, sim2;

    bgp_init_simulator(&sim1);
    bgp_add_router(&sim1, 100);
    bgp_add_neighbor(&sim1, 100, "192.168.1.1", 200);

    bgp_neighbor_t *neighbor = sim1.routers[0]->neighbors[0];
    neighbor->capabilities.ipv4_unicast = 1;
    neighbor->capabilities.ipv6_unicast = 1;
    neighbor->capabilities.ipv4_labeled_unicast = 1;
    neighbor->capabilities.ipv6_labeled_unicast = 1;
    neighbor->capabilities.vpnv4_unicast = 1;
    neighbor->capabilities.vpnv6_unicast = 1;
    neighbor->capabilities.evpn = 1;
    neighbor->capabilities.ipv4_flowspec = 1;
    neighbor->capabilities.add_path_ipv4 = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->capabilities.add_path_ipv6 = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->capabilities.add_path_ipv4_labeled = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->capabilities.add_path_ipv6_labeled = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->capabilities.add_path_vpnv4 = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->capabilities.add_path_vpnv6 = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->capabilities.add_path_evpn = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->capabilities.add_path_ipv4_flowspec = ADD_PATH_SEND | ADD_PATH_RECEIVE;

    write_running_config_to_file(&sim1, TEST_CONFIG_FILE);
    bgp_init_simulator(&sim2);
    int result = parse_config_file(TEST_CONFIG_FILE, &sim2);

    bgp_neighbor_t *neighbor2 = sim2.routers[0]->neighbors[0];
    int passed = (result >= 0 &&
                  neighbor2->capabilities.add_path_ipv4 == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                  neighbor2->capabilities.add_path_ipv6 == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                  neighbor2->capabilities.add_path_ipv4_labeled == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                  neighbor2->capabilities.add_path_ipv6_labeled == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                  neighbor2->capabilities.add_path_vpnv4 == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                  neighbor2->capabilities.add_path_vpnv6 == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                  neighbor2->capabilities.add_path_evpn == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                  neighbor2->capabilities.add_path_ipv4_flowspec == (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
                  neighbor2->capabilities.add_path_ipv6_flowspec == 0 &&
                  neighbor2->capabilities.add_path_ipv4_flowspec_vpn == 0 &&
                  neighbor2->capabilities.add_path_ipv6_flowspec_vpn == 0 &&
                  neighbor2->capabilities.add_path_ipv4_srpolicy == 0 &&
                  neighbor2->capabilities.add_path_ipv6_srpolicy == 0 &&
                  neighbor2->capabilities.add_path_bgp_ls == 0 &&
                  neighbor2->capabilities.add_path_ipv4_mvpn == 0 &&
                  neighbor2->capabilities.add_path_ipv6_mvpn == 0 &&
                  neighbor2->capabilities.add_path_ipv4_rtc == 0 &&
                  neighbor2->capabilities.add_path_vpls == 0);

    test_result(passed, "Mixed ADD-PATH capabilities round-trip");

    bgp_shutdown_sim(&sim1);
    bgp_shutdown_sim(&sim2);
    remove(TEST_CONFIG_FILE);
}

void test_ribout_roundtrip() {
    bgp_sim_t sim1, sim2;

    bgp_init_simulator(&sim1);

    bgp_ribout_config_t *block1 = bgp_sim_add_ribout(&sim1, "test-routes");

    bgp_ribout_parse_prefix(block1, "prefix 10.0.0.0/24 x 100");
    bgp_ribout_parse_path_ids(block1, "path-id 0 1 2 3");
    bgp_ribout_parse_label(block1, "label 16000 16001");
    bgp_ribout_parse_next_hop(block1, "next-hop 192.168.1.1");
    bgp_ribout_parse_aspath(block1, "as-path 100 200 300");
    bgp_ribout_parse_localpref(block1, "localpref range(150,152)");
    bgp_ribout_parse_origin(block1, "origin egp");

    bgp_ribout_config_t *block2 = bgp_sim_add_ribout(&sim1, "ecmp-routes");

    bgp_ribout_parse_prefix(block2, "prefix 172.16.0.0/16 x 50");
    bgp_ribout_parse_path_ids(block2, "path-id 0");
    bgp_ribout_parse_next_hop(block2, "next-hop 10.10.1.0 x 8");
    bgp_ribout_parse_aspath(block2, "as-path 100 { 200 300 } [rand(500) x 10]");
    bgp_ribout_parse_localpref(block2, "localpref randrange(200,300)");
    bgp_ribout_parse_med(block2, "med randrange(10,25)");
    bgp_ribout_parse_origin(block2, "origin incomplete");

    write_running_config_to_file(&sim1, TEST_CONFIG_FILE);
    bgp_init_simulator(&sim2);
    int result = parse_config_file(TEST_CONFIG_FILE, &sim2);

    int passed = (result >= 0 && sim2.ribout_count == 2);

    if (passed) {
        bgp_ribout_config_t *loaded1 = sim2.ribouts[0];
        passed = passed &&
                 (strcmp(loaded1->name, "test-routes") == 0) &&
                 (loaded1->prefix_spec.count == 100) &&
                 (loaded1->prefix_spec.prefix_len == 24) &&
                 (loaded1->path_id_count == 4) &&
                 (bgp_ribout_path_ids_at(loaded1, 0) == 0) &&
                 (bgp_ribout_path_ids_at(loaded1, 1) == 1) &&
                 (bgp_ribout_path_ids_at(loaded1, 2) == 2) &&
                 (bgp_ribout_path_ids_at(loaded1, 3) == 3) &&
                 (loaded1->label_count == 2) &&
                 (bgp_ribout_labels_at(loaded1, 0) == 16000) &&
                 (bgp_ribout_labels_at(loaded1, 1) == 16001) &&
                 (loaded1->next_hop_spec.count == 1) &&
                 (loaded1->aspath_segment_count == 1) &&
                 (loaded1->aspath_segments[0].type == ASPATH_SEQUENCE) &&
                 (loaded1->aspath_segments[0].value_count == 3) &&
                 (loaded1->aspath_segments[0].as_values[0] == 100) &&
                 (loaded1->aspath_segments[0].as_values[1] == 200) &&
                 (loaded1->aspath_segments[0].as_values[2] == 300) &&
                 (loaded1->localpref_spec.mode == BGP_U32_MODE_RANGE) &&
                 (loaded1->localpref_spec.range_start == 150) &&
                 (loaded1->localpref_spec.range_end == 152) &&
                 (loaded1->origin == ORIGIN_EGP);
    }

    if (passed) {
        bgp_ribout_config_t *loaded2 = sim2.ribouts[1];
        passed = passed &&
                 (strcmp(loaded2->name, "ecmp-routes") == 0) &&
                 (loaded2->prefix_spec.count == 50) &&
                 (loaded2->prefix_spec.prefix_len == 16) &&
                 (loaded2->path_id_count == 1) &&
                 (bgp_ribout_path_ids_at(loaded2, 0) == 0) &&
                 (loaded2->next_hop_spec.count == 8) &&
                 (loaded2->aspath_segment_count == 3) &&
                 (loaded2->aspath_segments[0].type == ASPATH_SEQUENCE) &&
                 (loaded2->aspath_segments[1].type == ASPATH_SET) &&
                 (loaded2->aspath_segments[2].type == ASPATH_RANDOM) &&
                 (loaded2->aspath_segments[2].rand_max == 500) &&
                 (loaded2->aspath_segments[2].rand_count == 10) &&
                 (loaded2->localpref_spec.mode == BGP_U32_MODE_RANDOM_RANGE) &&
                 (loaded2->localpref_spec.range_start == 200) &&
                 (loaded2->localpref_spec.range_end == 300) &&
                 (loaded2->med_spec.enabled == 1) &&
                 (loaded2->med_spec.mode == BGP_U32_MODE_RANDOM_RANGE) &&
                 (loaded2->med_spec.range_start == 10) &&
                 (loaded2->med_spec.range_end == 25) &&
                 (loaded2->origin == ORIGIN_INCOMPLETE);
    }

    test_result(passed, "RIB-OUT configuration round-trip");

    bgp_shutdown_sim(&sim1);
    bgp_shutdown_sim(&sim2);
    remove(TEST_CONFIG_FILE);
}

void test_ribout_vpn_roundtrip() {
    bgp_sim_t sim1, sim2;

    bgp_init_simulator(&sim1);

    bgp_ribout_config_t *vpn4 = bgp_sim_add_ribout(&sim1, "cust-a-vpn4");

    bgp_ribout_parse_prefix(vpn4, "prefix 10.10.0.0/24 x 4");
    bgp_ribout_parse_rd(vpn4, "rd 65000:100 65000:101");
    bgp_ribout_parse_label(vpn4, "label 16000 16001");
    bgp_ribout_parse_path_ids(vpn4, "path-id 1 2");
    bgp_ribout_parse_next_hop(vpn4, "next-hop 192.0.2.1");
    bgp_ribout_parse_rt(vpn4, "rt 65000:100");
    bgp_ribout_parse_rt(vpn4, "rt 65000:101");
    bgp_ribout_parse_soo(vpn4, "soo 65000:9");
    bgp_ribout_parse_med(vpn4, "med 50");
    bgp_ribout_parse_aspath(vpn4, "as-path 65100 65200");
    bgp_ribout_parse_localpref(vpn4, "localpref 200");
    bgp_ribout_parse_origin(vpn4, "origin igp");

    bgp_ribout_config_t *evpn5 = bgp_sim_add_ribout(&sim1, "tenant-a-evpn5");

    bgp_ribout_parse_prefix(evpn5, "prefix 192.168.0.0/24 x 2");
    bgp_ribout_parse_rd(evpn5, "rd 65000:300");
    bgp_ribout_parse_label(evpn5, "label 30000");
    bgp_ribout_parse_ethernet_tag(evpn5, "ethernet-tag 0 100");
    bgp_ribout_parse_gateway_ip(evpn5, "gateway-ip 10.255.0.1 x 2");
    bgp_ribout_parse_rt_set(evpn5, "rt-set [65000:300] [65000:301,65000:302]");
    bgp_ribout_parse_encap(evpn5, "encap vxlan");
    bgp_ribout_parse_router_mac(evpn5, "router-mac 02:aa:bb:cc:dd:ee");
    bgp_ribout_parse_med(evpn5, "med rand(25)");
    bgp_ribout_parse_next_hop(evpn5, "next-hop 192.0.2.10");
    bgp_ribout_parse_aspath(evpn5, "as-path 65500");
    bgp_ribout_parse_localpref(evpn5, "localpref 250");
    bgp_ribout_parse_origin(evpn5, "origin incomplete");

    write_running_config_to_file(&sim1, TEST_CONFIG_FILE);
    bgp_init_simulator(&sim2);
    int result = parse_config_file(TEST_CONFIG_FILE, &sim2);

    int passed = (result >= 0 && sim2.ribout_count == 2);

    if (passed) {
        bgp_ribout_config_t *loaded = sim2.ribouts[0];

        passed = passed &&
                 (strcmp(loaded->name, "cust-a-vpn4") == 0) &&
                 (loaded->rd_count == 2) &&
                 (loaded->label_count == 2) &&
                 (loaded->path_id_count == 2) &&
                 (loaded->rt_count == 2) &&
                 (loaded->soo_count == 1) &&
                 (loaded->med_spec.enabled == 1) &&
                 (loaded->med_spec.mode == BGP_U32_MODE_FIXED) &&
                 (loaded->med_spec.value == 50) &&
                 (bgp_ribout_resolve_family(loaded) == BGP_RIBOUT_FAMILY_VPNV4);
    }

    if (passed) {
        bgp_ribout_config_t *loaded = sim2.ribouts[1];

        passed = passed &&
                 (strcmp(loaded->name, "tenant-a-evpn5") == 0) &&
                 (loaded->rd_count == 1) &&
                 (loaded->label_count == 1) &&
                 (loaded->ethernet_tag_count == 2) &&
                 (loaded->gateway_ip_spec.count == 2) &&
                 (loaded->rt_set_count == 2) &&
                 (loaded->encap_count == 1) &&
                 (loaded->router_mac_count == 1) &&
                 (loaded->med_spec.enabled == 1) &&
                 (loaded->med_spec.mode == BGP_U32_MODE_RANDOM) &&
                 (loaded->med_spec.value == 25) &&
                 (bgp_ribout_resolve_family(loaded) == BGP_RIBOUT_FAMILY_EVPN_TYPE5_IPV4);
    }

    test_result(passed, "VPN and EVPN ribout configuration round-trip");

    bgp_shutdown_sim(&sim1);
    bgp_shutdown_sim(&sim2);
    remove(TEST_CONFIG_FILE);
}

/*
 * Color communities in unicast blocks survive running-config: per-value CO types and a sequence with one CO type
 */
void test_ribout_color_community_roundtrip() {
    bgp_sim_t sim1, sim2;

    bgp_init_simulator(&sim1);
    bgp_sim_add_ribout(&sim1, "colored-v4");
    bgp_ribout_parse_prefix(sim1.ribouts[0], "prefix 10.1.0.0/24 x 3");
    bgp_ribout_parse_next_hop(sim1.ribouts[0], "next-hop 10.255.0.201 x 3");
    bgp_ribout_parse_color(sim1.ribouts[0], "color 1 x 3 co 01");
    bgp_sim_add_ribout(&sim1, "colored-v6");
    bgp_ribout_parse_prefix(sim1.ribouts[1], "prefix 2001:db8:1::/64 x 2");
    bgp_ribout_parse_next_hop(sim1.ribouts[1], "next-hop 2001:db8:255::201");
    bgp_ribout_parse_color(sim1.ribouts[1], "color 4 co 10 7 9 co 11");
    bgp_ribout_config_t *set = bgp_sim_add_ribout(&sim1, "color-set");
    bgp_ribout_parse_prefix(set, "prefix 10.2.0.0/24");
    bgp_ribout_parse_color(set, "color set 100 co 01 300 co 10 200");
    bgp_ribout_config_t *sequence = bgp_sim_add_ribout(&sim1, "color-set-seq");
    bgp_ribout_parse_prefix(sequence, "prefix 10.3.0.0/24");
    bgp_ribout_parse_color(sequence, "color set 1 x 4 co 11");

    write_running_config_to_file(&sim1, TEST_CONFIG_FILE);
    bgp_init_simulator(&sim2);

    int                        loaded = parse_config_file(TEST_CONFIG_FILE, &sim2);
    const bgp_ribout_config_t *v4 = bgp_sim_find_ribout(&sim2, "colored-v4");
    const bgp_ribout_config_t *v6 = bgp_sim_find_ribout(&sim2, "colored-v6");
    set = bgp_sim_find_ribout(&sim2, "color-set");
    sequence = bgp_sim_find_ribout(&sim2, "color-set-seq");
    int passed = loaded >= 0 && sim2.ribout_count == 4 && v4 && v6 && set && sequence &&
                 !v4->color_set && !v6->color_set && set->color_set && sequence->color_set &&
                 set->color_count == 3 && bgp_ribout_colors_at(set, 1) == 300 &&
                 bgp_ribout_color_co_at(set, 0) == BGP_COLOR_CO_NULL &&
                 bgp_ribout_color_co_at(set, 1) == BGP_COLOR_CO_ANY &&
                 bgp_ribout_color_co_at(set, 2) == BGP_COLOR_CO_SPECIFIC &&
                 sequence->color_count == 4 && bgp_ribout_colors_at(sequence, 3) == 4 &&
                 bgp_ribout_color_co_at(sequence, 3) == BGP_COLOR_CO_RESERVED &&
                 v4->color_count == 3 && bgp_ribout_colors_at(v4, 0) == 1 && bgp_ribout_colors_at(v4, 2) == 3 &&
                 bgp_ribout_color_co_at(v4, 0) == BGP_COLOR_CO_NULL && bgp_ribout_color_co_at(v4, 2) == BGP_COLOR_CO_NULL &&
                 v6->color_count == 3 && bgp_ribout_colors_at(v6, 0) == 4 && bgp_ribout_color_co_at(v6, 0) == BGP_COLOR_CO_ANY &&
                 bgp_ribout_colors_at(v6, 1) == 7 && bgp_ribout_color_co_at(v6, 1) == BGP_COLOR_CO_SPECIFIC &&
                 bgp_ribout_colors_at(v6, 2) == 9 && bgp_ribout_color_co_at(v6, 2) == BGP_COLOR_CO_RESERVED &&
                 bgp_ribout_resolve_family(v4) == BGP_RIBOUT_FAMILY_IPV4_UNICAST &&
                 bgp_ribout_resolve_family(v6) == BGP_RIBOUT_FAMILY_IPV6_UNICAST;

    test_result(passed, "Color community round-trip (rotation, fixed sets, sequences and per-value CO)");
    remove(TEST_CONFIG_FILE);
    bgp_shutdown_sim(&sim1);
    bgp_shutdown_sim(&sim2);
}

void test_ribout_srpolicy_roundtrip() {
    bgp_sim_t sim1, sim2;
    test_env_guard_t randseed_guard;

    test_env_guard_capture(&randseed_guard, "RANDSEED");
    setenv("RANDSEED", "424242", 1);
    bgp_init_simulator(&sim1);

    bgp_ribout_config_t *sr4 = bgp_sim_add_ribout(&sim1, "srpol-v4");

    bgp_ribout_parse_distinguisher(sr4, "distinguisher 100 101");
    bgp_ribout_parse_color(sr4, "color 200 201");
    bgp_ribout_parse_endpoint(sr4, "endpoint 10.0.0.1 x 4");
    bgp_ribout_parse_path_ids(sr4, "path-id 7 8");
    bgp_ribout_parse_next_hop(sr4, "next-hop 2001:db8::1");
    bgp_ribout_parse_rt(sr4, "rt 192.0.2.10:100");
    bgp_ribout_parse_enlp(sr4, "enlp 3 4");
    bgp_ribout_parse_priority(sr4, "priority range(7,8)");
    bgp_ribout_parse_preference(sr4, "preference range(400,403)");
    bgp_ribout_parse_binding_sid(sr4, "binding-sid mpls randrange(16,1048575)");
    bgp_ribout_parse_segment_list(sr4, "segment-list 1 weight 10 mpls 16010 16011");
    bgp_ribout_parse_segment_list(sr4, "segment-list 2 weight 20 mpls 16020 16021");
    bgp_ribout_parse_localpref(sr4, "localpref 200");
    bgp_ribout_parse_origin(sr4, "origin egp");

    bgp_ribout_config_t *sr6 = bgp_sim_add_ribout(&sim1, "srpol-v6");

    bgp_ribout_parse_distinguisher(sr6, "distinguisher 500");
    bgp_ribout_parse_color(sr6, "color 600 601");
    bgp_ribout_parse_endpoint(sr6, "endpoint 2001:db8::1 x 2");
    bgp_ribout_parse_rt(sr6, "rt 192.0.2.20:200");
    bgp_ribout_parse_enlp(sr6, "enlp 2");
    bgp_ribout_parse_priority(sr6, "priority 9");
    bgp_ribout_parse_preference(sr6, "preference 700");
    bgp_ribout_parse_binding_sid(sr6, "binding-sid srv6 fc00:0:77::1 x 2");
    bgp_ribout_parse_segment_list(sr6, "segment-list 7 weight 70 srv6 2001:db8:7::1 behavior 4660 "
                                       "structure 48 16 16 48 2001:db8:7::2");
    bgp_ribout_parse_localpref(sr6, "localpref 225");
    bgp_ribout_parse_origin(sr6, "origin incomplete");

    write_running_config_to_file(&sim1, TEST_CONFIG_FILE);
    bgp_init_simulator(&sim2);
    int result = parse_config_file(TEST_CONFIG_FILE, &sim2);

    int passed = (result >= 0 && sim2.ribout_count == 2);

    if (passed) {
        bgp_ribout_config_t *loaded = sim2.ribouts[0];

        passed = passed &&
                 (strcmp(loaded->name, "srpol-v4") == 0) &&
                 (loaded->distinguisher_count == 2) &&
                 (loaded->color_count == 2) &&
                 (loaded->endpoint_spec.count == 4) &&
                 (loaded->path_id_count == 2) &&
                 (loaded->rt_count == 1) &&
                 (loaded->enlp_count == 2) &&
                 (loaded->priority_spec.enabled == 1) &&
                 (loaded->priority_spec.mode == BGP_U32_MODE_RANGE) &&
                 (loaded->priority_spec.range_start == 7) &&
                 (loaded->priority_spec.range_end == 8) &&
                 (loaded->preference_spec.enabled == 1) &&
                 (loaded->preference_spec.mode == BGP_U32_MODE_RANGE) &&
                 (loaded->preference_spec.range_start == 400) &&
                 (loaded->preference_spec.range_end == 403) &&
                 (loaded->binding_sid_spec.enabled == 1) &&
                 (loaded->binding_sid_spec.mode == BGP_U32_MODE_RANDOM_RANGE) &&
                 (loaded->binding_sid_spec.range_start == 16) &&
                 (loaded->binding_sid_spec.range_end == 1048575) &&
                 (loaded->segment_list_count == 2) &&
                 (loaded->next_hop_spec.af == AF_INET6) &&
                 (loaded->origin == ORIGIN_EGP) &&
                 (bgp_ribout_resolve_family(loaded) == BGP_RIBOUT_FAMILY_SR_POLICY_IPV4);
    }

    if (passed) {
        bgp_ribout_config_t *loaded = sim2.ribouts[1];

        passed = passed &&
                 (strcmp(loaded->name, "srpol-v6") == 0) &&
                 (loaded->distinguisher_count == 1) &&
                 (loaded->color_count == 2) &&
                 (loaded->endpoint_spec.count == 2) &&
                 (loaded->rt_count == 1) &&
                 (loaded->enlp_count == 1) &&
                 (bgp_ribout_priorities_at(loaded, 0) == 9) &&
                 (loaded->preference_count == 1) &&
                 (loaded->binding_sid_kind == BGP_RIBOUT_SR_BINDING_SID_SRV6) &&
                 (loaded->binding_sid_srv6_spec.count == 2) &&
                 (loaded->segment_list_count == 1) &&
                 (loaded->segment_lists[0].segments[0].has_srv6_behavior == 1) &&
                 (loaded->origin == ORIGIN_INCOMPLETE) &&
                 (bgp_ribout_resolve_family(loaded) == BGP_RIBOUT_FAMILY_SR_POLICY_IPV6);
    }

    test_result(passed, "SR Policy ribout configuration round-trip");

    bgp_shutdown_sim(&sim1);
    bgp_shutdown_sim(&sim2);
    test_env_guard_restore(&randseed_guard, "RANDSEED");
    remove(TEST_CONFIG_FILE);
}

/*
 * FlowSpec ribouts: the reloaded config prints the same text, and every match component (with each() and x count)
 * and action line (with rotating values) survives.
 */
void test_ribout_flowspec_roundtrip() {
    bgp_sim_t sim1, sim2;
    static char first[CONFIG_CAPTURE_SIZE];
    static char second[CONFIG_CAPTURE_SIZE];
    int passed = 1;

    bgp_init_simulator(&sim1);

    bgp_ribout_config_t *fs4 = bgp_sim_add_ribout(&sim1, "fs-v4");

    passed = passed &&
             bgp_ribout_parse_address_family(fs4, "address-family ipv4 flowspec") == 0 &&
             bgp_ribout_parse_aspath(fs4, "as-path 65001") == 0 &&
             bgp_ribout_parse_prefix(fs4, "prefix 10.1.0.0/24 x 3") == 0 &&
             bgp_ribout_flowspec_parse_component(fs4, "src-prefix", "192.0.2.0/24") == 0 &&
             bgp_ribout_flowspec_parse_component(fs4, "protocol", "each(6, 17)") == 0 &&
             bgp_ribout_flowspec_parse_component(fs4, "dst-port", ">=1024&<=2048 80") == 0 &&
             bgp_ribout_flowspec_parse_component(fs4, "src-port", "1000 x 4") == 0 &&
             bgp_ribout_flowspec_parse_component(fs4, "tcp-flags", "syn+ack !any(rst)") == 0 &&
             bgp_ribout_flowspec_parse_component(fs4, "packet-length", "<1500:2") == 0 &&
             bgp_ribout_flowspec_parse_component(fs4, "dscp", "46") == 0 &&
             bgp_ribout_flowspec_parse_component(fs4, "fragment", "any(isf)") == 0 &&
             bgp_ribout_flowspec_parse_component(fs4, "icmp-code", "true") == 0 &&
             bgp_ribout_flowspec_parse_action(fs4, "traffic-rate bytes 12500.5 as 65000") == 0 &&
             bgp_ribout_flowspec_parse_action(fs4, "redirect-ip 192.0.2.1 x 3 copy") == 0 &&
             bgp_ribout_parse_color(fs4, "color 100 co 01 200") == 0 &&
             bgp_ribout_flowspec_parse_action(fs4, "mark 10 46") == 0 &&
             bgp_ribout_flowspec_parse_action(fs4, "redirect-vrf 65000:100 192.0.2.9:7") == 0;

    bgp_ribout_config_t *fs6 = bgp_sim_add_ribout(&sim1, "fs-v6vpn");

    passed = passed &&
             bgp_ribout_parse_address_family(fs6, "address-family ipv6 flowspec-vpn") == 0 &&
             bgp_ribout_parse_rd(fs6, "rd 65000:1 x 2") == 0 &&
             bgp_ribout_parse_prefix(fs6, "prefix 2001:db8::/8-64 x 2") == 0 &&
             bgp_ribout_flowspec_parse_component(fs6, "protocol", "58") == 0 &&
             bgp_ribout_flowspec_parse_component(fs6, "flow-label", "12345:4") == 0 &&
             bgp_ribout_parse_next_hop(fs6, "next-hop 2001:db8::99") == 0 &&
             bgp_ribout_flowspec_parse_action(fs6, "traffic-action terminal sample") == 0 &&
             bgp_ribout_flowspec_parse_action(fs6, "redirect-vrf 2001:db8::1:300") == 0 &&
             bgp_ribout_flowspec_parse_action(fs6, "interface-set 65000:12 in out non-transitive") == 0 &&
             bgp_ribout_flowspec_parse_action(fs6, "redirect-next-hop") == 0 &&
             bgp_ribout_flowspec_parse_action(fs6, "redirect-ip 2001:db8::77 2001:db8::78") == 0;

    passed = passed && capture_running_config(&sim1, first, sizeof(first)) == 0;
    write_running_config_to_file(&sim1, TEST_CONFIG_FILE);
    bgp_init_simulator(&sim2);
    passed = passed && parse_config_file(TEST_CONFIG_FILE, &sim2) >= 0 && sim2.ribout_count == 2;
    passed = passed && capture_running_config(&sim2, second, sizeof(second)) == 0 &&
             strcmp(first, second) == 0;

    if (passed) {
        const bgp_ribout_config_t   *loaded = sim2.ribouts[0];
        const bgp_ribout_flowspec_t *fs = loaded->flowspec;

        passed = fs != NULL &&
                 loaded->prefix_spec.count == 3 &&
                 fs->src_prefix.count == 1 &&
                 fs->components[FLOWSPEC_IP_PROTOCOL].alternative_count == 2 &&
                 fs->components[FLOWSPEC_SRC_PORT].step_count == 4 &&
                 fs->components[FLOWSPEC_PORT].alternative_count == 0 &&
                 fs->components[FLOWSPEC_DEST_PORT].alternatives[0].num_values == 3 &&
                 (fs->components[FLOWSPEC_DEST_PORT].alternatives[0].values[1].op & FLOWSPEC_OP_AND) != 0 &&
                 (fs->components[FLOWSPEC_DEST_PORT].alternatives[0].values[2].op & FLOWSPEC_OP_END) != 0 &&
                 fs->components[FLOWSPEC_PACKET_LEN].alternatives[0].values[0].op ==
                     (FLOWSPEC_OP_END | FLOWSPEC_OP_LEN_2 | FLOWSPEC_OP_LT) &&
                 fs->actions.line_count == 4 &&
                 fs->actions.lines[1].value_count == 3 &&
                 fs->actions.lines[2].value_count == 2 &&
                 fs->actions.lines[3].value_count == 2 &&
                 loaded->color_count == 2 && bgp_ribout_color_co_at(loaded, 0) == BGP_COLOR_CO_NULL &&
                 bgp_ribout_total_paths(loaded) == 3 * 2 * 4 &&
                 bgp_ribout_resolve_family(loaded) == BGP_RIBOUT_FAMILY_FLOWSPEC_IPV4;
    }

    if (passed) {
        const bgp_ribout_config_t   *loaded = sim2.ribouts[1];
        const bgp_ribout_flowspec_t *fs = loaded->flowspec;

        passed = fs != NULL &&
                 loaded->prefix_offset == 8 &&
                 loaded->prefix_spec.prefix_len == 64 &&
                 fs->components[FLOWSPEC_FLOW_LABEL].alternatives[0].values[0].op ==
                     (FLOWSPEC_OP_END | FLOWSPEC_OP_LEN_4 | FLOWSPEC_OP_EQ) &&
                 fs->actions.line_count == 5 &&
                 fs->actions.lines[1].value_len == 20 &&
                 fs->actions.lines[3].redirect_next_hop == 1 &&
                 fs->actions.lines[4].value_count == 2 && fs->actions.lines[4].value_len == 20 &&
                 loaded->rd_count == 2 &&
                 bgp_ribout_resolve_family(loaded) == BGP_RIBOUT_FAMILY_FLOWSPEC_VPN_IPV6;
    }

    test_result(passed, "FlowSpec ribout configuration round-trip");

    bgp_shutdown_sim(&sim1);
    bgp_shutdown_sim(&sim2);
    remove(TEST_CONFIG_FILE);
}

void test_ribout_evpn_type2_roundtrip() {
    bgp_sim_t sim1, sim2;

    bgp_init_simulator(&sim1);

    bgp_ribout_config_t *evpn2 = bgp_sim_add_ribout(&sim1, "evpn2-hosts");

    bgp_ribout_parse_rd(evpn2, "rd 65000:320");
    bgp_ribout_parse_ethernet_tag(evpn2, "ethernet-tag 10 11");
    bgp_ribout_parse_mac(evpn2, "mac 1 x 8");
    bgp_ribout_parse_ip(evpn2, "ip 192.0.2.1 x 2");
    bgp_ribout_parse_label(evpn2, "label 30000 30001");
    bgp_ribout_parse_label2(evpn2, "label2 40000 40001");
    bgp_ribout_parse_esi(evpn2, "esi 00112233445566778899 x 2");
    bgp_ribout_parse_path_ids(evpn2, "path-id 7 8");
    bgp_ribout_parse_next_hop(evpn2, "next-hop 192.0.2.10 x 2");
    bgp_ribout_parse_rt_set(evpn2, "rt-set [65000:320] [65000:321,65000:322]");
    bgp_ribout_parse_encap(evpn2, "encap vxlan nvgre");
    bgp_ribout_parse_router_mac(evpn2, "router-mac 1 2");
    bgp_ribout_parse_localpref(evpn2, "localpref 220");
    bgp_ribout_parse_origin(evpn2, "origin egp");

    write_running_config_to_file(&sim1, TEST_CONFIG_FILE);
    bgp_init_simulator(&sim2);
    int result = parse_config_file(TEST_CONFIG_FILE, &sim2);

    int passed = (result >= 0 && sim2.ribout_count == 1);

    if (passed) {
        bgp_ribout_config_t *loaded = sim2.ribouts[0];

        passed = passed &&
                 (strcmp(loaded->name, "evpn2-hosts") == 0) &&
                 (loaded->rd_count == 1) &&
                 (loaded->ethernet_tag_count == 2) &&
                 (loaded->mac_spec.count == 8) &&
                 (loaded->ip_spec.count == 2) &&
                 (loaded->label_count == 2) &&
                 (loaded->label2_count == 2) &&
                 (loaded->esi_count == 2) &&
                 (loaded->path_id_count == 2) &&
                 (loaded->next_hop_spec.count == 2) &&
                 (loaded->rt_set_count == 2) &&
                 (loaded->encap_count == 2) &&
                 (loaded->router_mac_count == 2) &&
                 (memcmp(loaded->mac_spec.base_addr, (const uint8_t[]){0x00,0x00,0x00,0x00,0x00,0x01}, 6) == 0) &&
                 (loaded->esis[0].type == 0x00) &&
                 (memcmp(loaded->esis[0].value,
                         (const uint8_t[]){0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99},
                         9) == 0) &&
                 (memcmp(loaded->router_mac_values[0].bytes + 2,
                         (const uint8_t[]){0x00,0x00,0x00,0x00,0x00,0x01},
                         6) == 0) &&
                 (memcmp(loaded->router_mac_values[1].bytes + 2,
                         (const uint8_t[]){0x00,0x00,0x00,0x00,0x00,0x02},
                         6) == 0) &&
                 (loaded->localpref_spec.value == 220) &&
                 (loaded->origin == ORIGIN_EGP) &&
                 (bgp_ribout_resolve_family(loaded) == BGP_RIBOUT_FAMILY_EVPN_TYPE2);
    }

    test_result(passed, "EVPN Type 2 ribout configuration round-trip");

    bgp_shutdown_sim(&sim1);
    bgp_shutdown_sim(&sim2);
    remove(TEST_CONFIG_FILE);
}

/*
 * Add the single-RT sets [65551:first] .. [65551:last] with one rt-set line.
 */
static int add_rt_sets(bgp_ribout_config_t *block, int first, int last) {
    char line[1024];
    int  len = snprintf(line, sizeof(line), "rt-set");

    for (int i = first; i <= last; i++) {
        len += snprintf(line + len, sizeof(line) - (size_t)len, " [65551:%d]", i);
    }
    return bgp_ribout_parse_rt_set(block, line);
}

/*
 * Running-config may coalesce explicit sets into a sequence; compare generated values, not storage layouts.
 */
static int rt_sets_equal(const bgp_ribout_config_t *a, const bgp_ribout_config_t *b) {
    if (a->rt_set_count != b->rt_set_count) return 0;
    for (uint32_t i = 0; i < a->rt_set_count; i++) {
        bgp_rt_set_spec_t av = bgp_ribout_rt_set_at(a, i), bv = bgp_ribout_rt_set_at(b, i);
        if (av.count != bv.count || memcmp(av.values, bv.values, av.count * sizeof(*av.values))) return 0;
    }
    return 1;
}

/*
 * 100 rotating RT sets and rotating labels survive running-config. rt-set lines append, and running-config splits the
 * list so that every line stays within the 32 tokens of a command.
 */
void test_ribout_rt_sets_and_label_rotate_roundtrip() {
    bgp_sim_t  sim1, sim2;
    char config[CONFIG_CAPTURE_SIZE];
    int  lines_fit = 1;
    int  passed;

    bgp_init_simulator(&sim1);
    bgp_ribout_config_t *vpn = bgp_sim_add_ribout(&sim1, "vrfs");
    bgp_ribout_parse_prefix(vpn, "prefix 10.20.0.0/24 x 200");
    bgp_ribout_parse_rd(vpn, "rd 65551:1");
    bgp_ribout_parse_label(vpn, "label rotate 24001 x 100");
    bgp_ribout_parse_next_hop(vpn, "next-hop 192.0.2.1");
    passed = add_rt_sets(vpn, 1, 25) == 0 && add_rt_sets(vpn, 26, 50) == 0 && add_rt_sets(vpn, 51, 75) == 0 &&
             add_rt_sets(vpn, 76, 100) == 0 && vpn->rt_set_count == 100 && vpn->label_rotate == 1;

    passed = passed && capture_running_config(&sim1, config, sizeof(config)) >= 0 &&
             strstr(config, "  label rotate 24001 x 100\n") != NULL;
    for (char *line = strtok(config, "\n"); line; line = strtok(NULL, "\n")) {
        int tokens = 0;

        for (char *c = line; *c; c++) {
            tokens += (*c != ' ' && (c == line || c[-1] == ' '));
        }
        lines_fit = lines_fit && tokens <= 32 && strlen(line) < 1024;
    }

    write_running_config_to_file(&sim1, TEST_CONFIG_FILE);
    bgp_init_simulator(&sim2);
    passed = passed && lines_fit && parse_config_file(TEST_CONFIG_FILE, &sim2) >= 0 && sim2.ribout_count == 1;
    if (passed) {
        bgp_ribout_config_t *loaded = sim2.ribouts[0];

        passed = loaded->rt_set_count == 100 && loaded->label_rotate == 1 && loaded->label_count == 100 &&
                 bgp_ribout_labels_at(loaded, 0) == 24001 && bgp_ribout_labels_at(loaded, 99) == 24100 &&
                 rt_sets_equal(loaded, vpn);
    }
    test_result(passed, "100 RT sets and label rotate round-trip, every line within the command limits");

    bgp_shutdown_sim(&sim1);
    bgp_shutdown_sim(&sim2);
    remove(TEST_CONFIG_FILE);
}

static void test_compact_rt_sets_roundtrip(void) {
    bgp_sim_t sim1, sim2;
    char config[CONFIG_CAPTURE_SIZE];
    bgp_init_simulator(&sim1);
    bgp_init_simulator(&sim2);
    bgp_ribout_config_t *block = bgp_sim_add_ribout(&sim1, "compact-rt");
    int passed = block && bgp_ribout_edit(block, "rt-set", "[65000:1] x 1000000 [65551:10] x 3", 0) == 0 &&
                 capture_running_config(&sim1, config, sizeof(config)) >= 0 &&
                 strstr(config, "[65000:1] x 1000000 [65551:10] x 3\n") != NULL;
    write_running_config_to_file(&sim1, TEST_CONFIG_FILE);
    passed = passed && parse_config_file(TEST_CONFIG_FILE, &sim2) >= 0 && sim2.ribout_count == 1;
    if (passed) {
        bgp_ribout_config_t *loaded = sim2.ribouts[0];
        passed = loaded->rt_set_group_count == 2 && loaded->rt_set_count == 1000003 &&
                 bgp_ribout_config_bytes(loaded) < 16384 && rt_sets_equal(loaded, block);
        // A rejected append must not change either the compact groups or their logical count.
        passed = passed && bgp_ribout_edit(loaded, "rt-set", "[65551:65535] x 2", 0) < 0 &&
                 loaded->rt_set_group_count == 2 && rt_sets_equal(loaded, block);
    }
    test_result(passed, "Mixed million-set RT sequences round-trip compactly; invalid append changes nothing");
    bgp_shutdown_sim(&sim1);
    bgp_shutdown_sim(&sim2);
    remove(TEST_CONFIG_FILE);
}

/*
 * Community and large-community sets survive running-config: 64 sets as written each (sequences, well-known names,
 * a 16-value set of ~180 characters and a 16-value large set of ~530 characters in one token), split over lines that
 * stay within the command limits. An rt-set of 16 four-octet-AS route targets, also one long token, loads back too.
 */
void test_ribout_community_sets_roundtrip() {
    bgp_sim_t  sim1, sim2;
    char config[CONFIG_CAPTURE_SIZE];
    char line[1024];
    int  lines_fit = 1, community_lines = 0, len;
    int  passed = 1;

    bgp_init_simulator(&sim1);
    bgp_ribout_config_t *block = bgp_sim_add_ribout(&sim1, "tagged");
    bgp_ribout_parse_prefix(block, "prefix 10.20.0.0/24 x 10");
    bgp_ribout_parse_next_hop(block, "next-hop 192.0.2.1");
    len = snprintf(line, sizeof(line), "community [no-export,blackhole,graceful-shutdown,65535:7");
    for (int i = 0; i < 12; i++) {
        len += snprintf(line + len, sizeof(line) - (size_t)len, ",65000:%d", 100 + i);
    }
    snprintf(line + len, sizeof(line) - (size_t)len, "] x 9");
    passed = passed && bgp_ribout_parse_community(block, line) == 0;
    for (int i = 0; i < 62; i++) {
        snprintf(line, sizeof(line), "community 65001:%d x %d", 10 * i, 1 + i % 3);
        passed = passed && bgp_ribout_parse_community(block, line) == 0;
    }
    passed = passed && bgp_ribout_parse_community(block, "community no-peer x 100000") == 0 &&
             block->community_group_count == 64;
    len = snprintf(line, sizeof(line), "large-community [");
    for (int i = 0; i < MAX_LARGE_COMMUNITIES_PER_SET; i++) {
        len += snprintf(line + len, sizeof(line) - (size_t)len, "%s4294967295:4294967295:%u", i ? "," : "",
                        4294967000u + (unsigned)i);
    }
    snprintf(line + len, sizeof(line) - (size_t)len, "]");
    passed = passed && bgp_ribout_parse_large_community(block, line) == 0;
    for (int i = 0; i < 63; i++) {
        snprintf(line, sizeof(line), "large-community [65551:%d:0,65551:%d:1000] x %d", i, i, 1 + i % 4);
        passed = passed && bgp_ribout_parse_large_community(block, line) == 0;
    }
    passed = passed && block->large_community_group_count == 64;
    len = snprintf(line, sizeof(line), "rt-set [");
    for (int i = 0; i < 16; i++) {
        len += snprintf(line + len, sizeof(line) - (size_t)len, "%s65551:%d", i ? "," : "", 1001 + i);
    }
    snprintf(line + len, sizeof(line) - (size_t)len, "] [65551:1]");
    passed = passed && bgp_ribout_parse_rt_set(block, line) == 0 && block->rt_set_count == 2;

    passed = passed && capture_running_config(&sim1, config, sizeof(config)) >= 0;
    for (char *text = strtok(config, "\n"); text; text = strtok(NULL, "\n")) {
        int tokens = 0;

        for (char *c = text; *c; c++) {
            tokens += (*c != ' ' && (c == text || c[-1] == ' '));
        }
        lines_fit = lines_fit && tokens <= 32 && strlen(text) < 1024;
        community_lines += strncmp(text, "  community ", 12) == 0 || strncmp(text, "  large-community ", 18) == 0;
    }

    write_running_config_to_file(&sim1, TEST_CONFIG_FILE);
    bgp_init_simulator(&sim2);
    passed = passed && lines_fit && community_lines > 2 && parse_config_file(TEST_CONFIG_FILE, &sim2) >= 0 &&
             sim2.ribout_count == 1;
    if (passed) {
        bgp_ribout_config_t *loaded = sim2.ribouts[0];

        passed = loaded->community_group_count == 64 &&
                 loaded->large_community_group_count == 64 &&
                 memcmp(loaded->community_groups, block->community_groups,
                        block->community_group_count * sizeof(*block->community_groups)) == 0 &&
                 memcmp(loaded->large_community_groups, block->large_community_groups,
                        block->large_community_group_count * sizeof(*block->large_community_groups)) == 0 &&
                 loaded->rt_set_count == 2 &&
                 rt_sets_equal(loaded, block);
    }
    test_result(passed,
                "64 community and 64 large-community sets and a 16-RT set round-trip within the command limits");

    bgp_shutdown_sim(&sim1);
    bgp_shutdown_sim(&sim2);
    remove(TEST_CONFIG_FILE);
}

/*
 * Apply "keyword value" lines to a block with bgp_ribout_edit(), as the CLI does.
 */
static int edit_block(bgp_ribout_config_t *block, const char *const *lines) {
    for (; *lines; lines++) {
        char        keyword[32];
        const char *value = strchr(*lines, ' ');

        snprintf(keyword, sizeof(keyword), "%.*s", (int)(value - *lines), *lines);
        if (bgp_ribout_edit(block, keyword, value + 1, 0) != 0) {
            return -1;
        }
    }
    return 0;
}

/*
 * Two UPDATE lists hold the same messages, byte for byte, in the same order.
 */
static int same_updates(const bgp_msg_t *a, const bgp_msg_t *b) {
    for (; a && b; a = a->next, b = b->next) {
        if (a->length != b->length || memcmp(a->data, b->data, a->length) != 0) {
            return 0;
        }
    }
    return !a && !b;
}

/*
 * Every rotate form of a key list survives running-config, sequential lists as "<base> x <count>" and others value
 * by value: the reloaded ribouts generate the same UPDATEs byte for byte.
 */
void test_ribout_key_rotation_roundtrip() {
    static const char *const k_blocks[][12] = {
        {
            "distinguisher rotate 5 x 4",
            "color rotate 100 103 107 111",
            "endpoint rotate 10.0.0.1 x 4",
            "path-id rotate 7 9",
            "segment-list 1 weight 10 mpls 16001",
            "rt 192.0.2.1:100",
            NULL,
        },
        {
            "distinguisher 1 x 3",
            "color rotate 100 x 4",
            "endpoint 10.1.0.1 x 20",
            "segment-list 1 weight 10 mpls 16001",
            "rt 192.0.2.1:100",
            NULL,
        },
        {
            "prefix 172.16.0.0/24 x 12",
            "rd rotate 65551:5 x 3",
            "ethernet-tag rotate 0 x 3",
            "label 30000",
            "next-hop 192.0.2.10",
            NULL,
        },
        {
            "rd 65551:1",
            "mac 02:00:00:00:00:01 x 6",
            "ethernet-tag rotate 10 12",
            "ip rotate 10.1.0.1 x 6",
            "label 20",
            "next-hop 192.0.2.1",
            NULL,
        },
        {
            "prefix 100.64.0.0/24 x 9",
            "path-id rotate 1 5 9",
            "next-hop 192.0.2.2",
            NULL,
        },
        {
            "address-family ipv4 flowspec",
            "prefix 10.60.0.0/24 x 2",
            "protocol rotate each(6, 17)",
            "dst-port rotate 80 x 3",
            "src-port each(1, 2)",
            "dscp rotate 10",
            NULL,
        },
    };
    static const char *const k_printed[] = {
        "  distinguisher rotate 5 x 4\n",
        "  color rotate 100 103 107 111\n",
        "  endpoint rotate 10.0.0.1 x 4\n",
        "  path-id rotate 7 9\n",
        "  color rotate 100 x 4\n",
        "  ethernet-tag rotate 0 x 3\n",
        "  ethernet-tag rotate 10 12\n",
        "  path-id rotate 1 5 9\n",
        "  protocol rotate each(6, 17)\n",
        "  dst-port rotate 80 x 3\n",
        "  dscp rotate 10\n",
    };
    const int count = (int)(sizeof(k_blocks) / sizeof(k_blocks[0]));
    bgp_sim_t sim1, sim2;
    char config[CONFIG_CAPTURE_SIZE];
    int  passed = 1;

    bgp_init_simulator(&sim1);
    for (int i = 0; i < count; i++) {
        char name[16];

        snprintf(name, sizeof(name), "rot%d", i);
        bgp_sim_add_ribout(&sim1, name);
        passed = passed && edit_block(sim1.ribouts[i], k_blocks[i]) == 0 &&
                 bgp_ribout_generate(sim1.ribouts[i]) == BGP_RIBOUT_GENERATED;
    }
    test_result(passed, "Every rotate form configures and generates");

    passed = capture_running_config(&sim1, config, sizeof(config)) >= 0;
    for (size_t i = 0; passed && i < sizeof(k_printed) / sizeof(k_printed[0]); i++) {
        if (!strstr(config, k_printed[i])) {
            printf("  missing: %s", k_printed[i]);
            passed = 0;
        }
    }
    test_result(passed, "running-config prints each rotate form");

    write_running_config_to_file(&sim1, TEST_CONFIG_FILE);
    bgp_init_simulator(&sim2);
    passed = parse_config_file(TEST_CONFIG_FILE, &sim2) >= 0 && sim2.ribout_count == count;
    for (int i = 0; passed && i < count; i++) {
        const bgp_ribout_config_t *a = sim1.ribouts[i];
        bgp_ribout_config_t       *b = sim2.ribouts[i];

        passed = bgp_ribout_generate(b) == BGP_RIBOUT_GENERATED && same_updates(a->messages, b->messages) &&
                 a->distinguisher_rotate == b->distinguisher_rotate && a->color_rotate == b->color_rotate &&
                 a->endpoint_rotate == b->endpoint_rotate && a->path_id_rotate == b->path_id_rotate &&
                 a->ethernet_tag_rotate == b->ethernet_tag_rotate &&
                 (!a->flowspec || a->flowspec->rotating == b->flowspec->rotating);
        if (!passed) {
            printf("  ribout %s differs after reload\n", a->name);
        }
    }
    test_result(passed, "The reloaded ribouts generate the same UPDATEs byte for byte");

    bgp_shutdown_sim(&sim1);
    bgp_shutdown_sim(&sim2);
    remove(TEST_CONFIG_FILE);
}

/*
 * rt, soo and router-mac lines append, and their full lists (64, 32, 32 values) are longer than one command (32
 * tokens): running-config splits them over lines that load back to the same lists.
 */
void test_ribout_long_ext_comm_lists_roundtrip() {
    bgp_sim_t sim1, sim2;
    char config[CONFIG_CAPTURE_SIZE];
    char line[64];
    int  lines_fit = 1, passed = 1;

    bgp_init_simulator(&sim1);
    bgp_ribout_config_t *block = bgp_sim_add_ribout(&sim1, "long");
    bgp_ribout_parse_prefix(block, "prefix 172.16.0.0/24 x 4");
    bgp_ribout_parse_rd(block, "rd 65551:5");
    bgp_ribout_parse_label(block, "label 30000");
    bgp_ribout_parse_ethernet_tag(block, "ethernet-tag 0");
    bgp_ribout_parse_next_hop(block, "next-hop 192.0.2.10");
    for (int i = 0; i < 64; i++) {
        snprintf(line, sizeof(line), "rt 65551:%d", 1000 + i);
        passed = passed && bgp_ribout_parse_rt(block, line) == 0;
    }
    for (int i = 0; i < 32; i++) {
        snprintf(line, sizeof(line), "soo 192.0.2.%d:%d", i, 100 + i);
        passed = passed && bgp_ribout_parse_soo(block, line) == 0;
        snprintf(line, sizeof(line), "router-mac 02:aa:bb:cc:dd:%02x", i);
        passed = passed && bgp_ribout_parse_router_mac(block, line) == 0;
    }
    passed = passed && block->rt_count == 64 && block->soo_count == 32 && block->router_mac_count == 32;
    test_result(passed, "64 route targets, 32 SoO and 32 router MACs, one line each");

    passed = capture_running_config(&sim1, config, sizeof(config)) >= 0;
    for (char *text = strtok(config, "\n"); text; text = strtok(NULL, "\n")) {
        int tokens = 0;

        for (char *c = text; *c; c++) {
            tokens += (*c != ' ' && (c == text || c[-1] == ' '));
        }
        lines_fit = lines_fit && tokens <= 32 && strlen(text) < 1024;
    }
    write_running_config_to_file(&sim1, TEST_CONFIG_FILE);
    bgp_init_simulator(&sim2);
    passed = passed && lines_fit && parse_config_file(TEST_CONFIG_FILE, &sim2) >= 0 && sim2.ribout_count == 1;
    if (passed) {
        const bgp_ribout_config_t *loaded = sim2.ribouts[0];

        passed = loaded->rt_count == 64 && loaded->soo_count == 32 && loaded->router_mac_count == 32 &&
                 memcmp(loaded->rt_values, block->rt_values, sizeof(block->rt_values[0]) * 64) == 0 &&
                 memcmp(loaded->soo_values, block->soo_values, sizeof(block->soo_values[0]) * 32) == 0 &&
                 memcmp(loaded->router_mac_values, block->router_mac_values,
                        sizeof(block->router_mac_values[0]) * 32) == 0;
    }
    test_result(passed, "The lists split over lines within the command limits and load back whole, in order");

    bgp_shutdown_sim(&sim1);
    bgp_shutdown_sim(&sim2);
    remove(TEST_CONFIG_FILE);
}

/*
 * ip rotate survives running-config.
 */
void test_ribout_ip_rotate_roundtrip() {
    bgp_sim_t sim1, sim2;
    int       passed;

    bgp_init_simulator(&sim1);
    bgp_ribout_config_t *hosts = bgp_sim_add_ribout(&sim1, "hosts");
    bgp_ribout_parse_rd(hosts, "rd 65551:7");
    bgp_ribout_parse_mac(hosts, "mac 2 x 100");
    bgp_ribout_parse_ip(hosts, "ip rotate 10.1.0.1 x 100");
    bgp_ribout_parse_label(hosts, "label 20001 x 100");
    bgp_ribout_parse_next_hop(hosts, "next-hop 192.0.2.1");

    write_running_config_to_file(&sim1, TEST_CONFIG_FILE);
    bgp_init_simulator(&sim2);
    passed = parse_config_file(TEST_CONFIG_FILE, &sim2) >= 0 && sim2.ribout_count == 1 &&
             sim2.ribouts[0]->ip_rotate == 1 && sim2.ribouts[0]->ip_spec.count == 100 &&
             sim2.ribouts[0]->ip_spec.base_addr.ipv4.s_addr == hosts->ip_spec.base_addr.ipv4.s_addr;
    test_result(passed, "EVPN Type 2 ip rotate round-trip");

    bgp_shutdown_sim(&sim1);
    bgp_shutdown_sim(&sim2);
    remove(TEST_CONFIG_FILE);
}

/*
 * The rotation options survive running-config: rd rotate and rt-set sequences print as "<base> x <count>", rotate-every
 * and rotate-period as themselves, and a dual-stack Type 2 ribout as an ip line per family.
 */
void test_ribout_rotation_options_roundtrip() {
    bgp_sim_t sim1, sim2;
    char config[CONFIG_CAPTURE_SIZE];
    int  printed;
    int  passed;

    bgp_init_simulator(&sim1);
    bgp_ribout_config_t *vpn = bgp_sim_add_ribout(&sim1, "vrfs");
    bgp_ribout_config_t *hosts = bgp_sim_add_ribout(&sim1, "hosts");
    bgp_ribout_parse_prefix(vpn, "prefix 10.20.0.0/24 x 1000");
    bgp_ribout_parse_rd(vpn, "rd rotate 65551:1 x 100");
    bgp_ribout_parse_label(vpn, "label rotate 24001 x 100");
    bgp_ribout_parse_rt_set(vpn, "rt-set [65551:1,65551:1001] x 100");
    bgp_ribout_parse_rotate_every(vpn, "rotate-every 10");
    bgp_ribout_parse_rotate_period(vpn, "rotate-period 100");
    bgp_ribout_parse_next_hop(vpn, "next-hop 192.0.2.1");
    bgp_ribout_parse_rd(hosts, "rd 65551:6");
    bgp_ribout_parse_mac(hosts, "mac 2 x 100");
    bgp_ribout_parse_ip(hosts, "ip rotate 172.20.0.1 x 100");
    bgp_ribout_parse_ip(hosts, "ip 2001:db8:20::1 x 3");
    bgp_ribout_parse_label(hosts, "label 40001");
    bgp_ribout_parse_next_hop(hosts, "next-hop 192.0.2.20");

    printed = capture_running_config(&sim1, config, sizeof(config)) >= 0 &&
              strstr(config, "  rd rotate 65551:1 x 100\n") && strstr(config, "  rt-set [65551:1,65551:1001] x 100\n") &&
              strstr(config, "  rotate-every 10\n") && strstr(config, "  rotate-period 100\n") &&
              strstr(config, "  ip rotate 172.20.0.1 x 100\n") && strstr(config, "  ip 2001:db8:20::1 x 3\n");
    write_running_config_to_file(&sim1, TEST_CONFIG_FILE);
    bgp_init_simulator(&sim2);
    passed = printed && parse_config_file(TEST_CONFIG_FILE, &sim2) >= 0 && sim2.ribout_count == 2;
    if (passed) {
        const bgp_ribout_config_t *a = sim2.ribouts[0], *b = sim2.ribouts[1];

        int same_rds = a->rd_count == vpn->rd_count;
        for (uint32_t i = 0; same_rds && i < a->rd_count; i++) {
            route_distinguisher_t av = bgp_ribout_rds_at(a, i), bv = bgp_ribout_rds_at(vpn, i);
            same_rds = memcmp(&av, &bv, sizeof(av)) == 0;
        }
        passed = a->rd_rotate && a->rd_count == 100 && same_rds &&
                 a->rt_set_count == 100 && rt_sets_equal(a, vpn) &&
                 a->rotate_every == 10 && a->rotate_period == 100 && b->ip_rotate && !b->ip2_rotate &&
                 b->ip_spec.count == 100 && b->ip2_spec.count == 3 && b->ip2_spec.af == AF_INET6;
    }
    test_result(passed, "rd rotate, rt-set sequences, rotate-every/period and dual-stack ip round-trip");

    bgp_shutdown_sim(&sim1);
    bgp_shutdown_sim(&sim2);
    remove(TEST_CONFIG_FILE);
}

void test_ribout_link_local_next_hop_roundtrip() {
    bgp_sim_t sim1, sim2;
    struct in6_addr expected_link_local;

    bgp_init_simulator(&sim1);

    bgp_ribout_config_t *block = bgp_sim_add_ribout(&sim1, "ipv6-llnh");

    bgp_ribout_parse_prefix(block, "prefix 2001:db8::/64 x 2");
    bgp_ribout_parse_next_hop(block, "next-hop 2001:db8:ffff::1 x 4 link-local fe80::1");
    bgp_ribout_parse_aspath(block, "as-path 65001 65002");
    bgp_ribout_parse_localpref(block, "localpref 125");
    bgp_ribout_parse_origin(block, "origin igp");

    write_running_config_to_file(&sim1, TEST_CONFIG_FILE);
    bgp_init_simulator(&sim2);
    int result = parse_config_file(TEST_CONFIG_FILE, &sim2);

    inet_pton(AF_INET6, "fe80::1", &expected_link_local);

    int passed = (result >= 0 && sim2.ribout_count == 1);

    if (passed) {
        bgp_ribout_config_t *loaded = sim2.ribouts[0];

        passed = passed &&
                 (strcmp(loaded->name, "ipv6-llnh") == 0) &&
                 (loaded->prefix_spec.af == AF_INET6) &&
                 (loaded->next_hop_spec.af == AF_INET6) &&
                 (loaded->next_hop_spec.count == 4) &&
                 (loaded->next_hop_spec.has_link_local == 1) &&
                 (memcmp(&loaded->next_hop_spec.link_local, &expected_link_local, sizeof(expected_link_local)) == 0);
    }

    test_result(passed, "RIB-OUT IPv6 link-local next-hop round-trip");

    bgp_shutdown_sim(&sim1);
    bgp_shutdown_sim(&sim2);
    remove(TEST_CONFIG_FILE);
}

void test_combined_roundtrip() {
    bgp_sim_t sim1, sim2;

    bgp_init_simulator(&sim1);

    bgp_add_router(&sim1, 100);
    bgp_add_neighbor(&sim1, 100, "192.168.1.1", 200);
    sim1.routers[0]->neighbors[0]->capabilities.ipv4_unicast = 1;

    bgp_ribout_config_t *block = bgp_sim_add_ribout(&sim1, "combined-test");

    bgp_ribout_parse_prefix(block, "prefix 10.0.0.0/24 x 10");
    bgp_ribout_parse_path_ids(block, "path-id 0 1");
    bgp_ribout_parse_next_hop(block, "next-hop 192.168.1.1");
    bgp_ribout_parse_aspath(block, "as-path 100 200");
    bgp_ribout_parse_localpref(block, "localpref 100");
    bgp_ribout_parse_origin(block, "origin igp");

    write_running_config_to_file(&sim1, TEST_CONFIG_FILE);
    bgp_init_simulator(&sim2);
    int result = parse_config_file(TEST_CONFIG_FILE, &sim2);

    int passed = (result >= 0 &&
                  sim2.router_count == 1 &&
                  sim2.routers[0]->local_as == 100 &&
                  sim2.routers[0]->neighbor_count == 1 &&
                  sim2.ribouts[0]->prefix_spec.count == 10 &&
                  sim2.ribout_count == 1);

    test_result(passed, "Combined routers and ribouts round-trip");

    bgp_shutdown_sim(&sim1);
    bgp_shutdown_sim(&sim2);
    remove(TEST_CONFIG_FILE);
}

static void test_template_round_trip(void) {
    bgp_sim_t first = {0}, second = {0};
    bgp_init_simulator(&first);
    bgp_init_simulator(&second);
    cli_session_t session = {0};
    cli_mode_t    mode = CLI_MODE_CONFIG;
    int           ok = 1;
    for (size_t i = 0; i < sizeof(template_vectors) / sizeof(*template_vectors); i++) {
        char line[1200];
        snprintf(line, sizeof(line), "ribout typed-%zu", i);
        ok = cli_process_command(&session, &first, &mode, line) == 0 && ok;
        snprintf(line, sizeof(line), "%s x %u", template_vectors[i].command, template_vectors[i].count);
        ok = cli_process_command(&session, &first, &mode, line) == 0 &&
             cli_process_command(&session, &first, &mode, "path-id 7 9") == 0 &&
             cli_process_command(&session, &first, &mode, "next-hop 2001:db8::9") == 0 && ok;
        const char *attr = template_vectors[i].safi == 65 ? "l2-info encap 19 flags 0 mtu 1500" :
                           template_vectors[i].safi == 71 ? "ls-attribute type 1026 value 6e6f6465" :
                           template_vectors[i].safi == 5 ? "pmsi flags 0 type 6 label 1000 id c0000201" : NULL;
        if (attr) ok = cli_process_command(&session, &first, &mode, attr) == 0 && ok;
        ok = cli_process_command(&session, &first, &mode, "exit") == 0 && ok;
    }
    char original[CONFIG_CAPTURE_SIZE], loaded[CONFIG_CAPTURE_SIZE];
    ok = capture_running_config(&first, original, sizeof(original)) >= 0 && ok;
    write_running_config_to_file(&first, TEST_CONFIG_FILE);
    ok = parse_config_file(TEST_CONFIG_FILE, &second) >= 0 && first.ribout_count == second.ribout_count &&
         capture_running_config(&second, loaded, sizeof(loaded)) >= 0 && !strcmp(original, loaded) && ok;
    for (int i = 0; ok && i < first.ribout_count; i++) {
        bgp_ribout_config_t *a = first.ribouts[i], *b = second.ribouts[i];
        ok = bgp_ribout_generate(a) == BGP_RIBOUT_GENERATED && bgp_ribout_generate(b) == BGP_RIBOUT_GENERATED &&
             a->message_count == b->message_count && a->message_count > 0;
        bgp_msg_t *x = a->messages, *y = b->messages;
        while (ok && x && y) {
            ok = x->length == y->length && !memcmp(x->data, y->data, x->length);
            x = x->next;
            y = y->next;
        }
        ok = ok && !x && !y;
    }
    bgp_shutdown_sim(&first);
    bgp_shutdown_sim(&second);
    unlink(TEST_CONFIG_FILE);
    test_result(ok, "All typed NLRI templates and family attributes round-trip through CLI/config to identical UPDATEs");
}

int main() {
    test_template_round_trip();
    printf("BGP CLI Configuration Tests\n");
    printf("========================================\n\n");

    test_empty_config();
    test_config_not_found();
    test_parse_config_file_inherits_routed_output();
    test_valid_router_config();
    test_rejected_config_lines();
    test_valid_neighbor_config();
    test_ipv6_neighbor_config();
    test_update_source_config();
    test_comment_lines();
    test_whitespace_handling();
    test_long_config_line();
    test_multiple_routers();
    test_duplicate_router();
    test_exit_command();
    test_router_id_command();
    test_update_source_command();
    test_neighbor_ipv6_update_source_command();
    test_address_family_ipv4();
    test_address_family_ipv6();
    test_address_family_ipv4_labels();
    test_capability_ext_nh_config();
    test_capability_route_refresh();
    test_capability_graceful_restart();
    test_ribout_config();
    test_ribout_attributes();
    test_no_neighbor();
    test_address_family_vpnv4();
    test_invalid_nested_line_recovery();
    test_large_asn_boundary();
    test_as_zero_configuration();
    test_same_neighbor_ip_different_routers();

    test_enable_ipv4_unicast();
    test_enable_ipv6_unicast();
    test_enable_ipv4_labels();
    test_enable_ipv6_labels();
    test_enable_vpnv4();
    test_enable_vpnv6();
    test_enable_evpn();
    test_enable_ipv4_flowspec();
    test_enable_ipv6_flowspec();
    test_enable_ipv4_flowspec_vpn();
    test_enable_ipv6_flowspec_vpn();
    test_enable_ipv4_srpolicy();
    test_enable_ipv6_srpolicy();
    test_enable_bgp_ls();
    test_enable_ipv4_mvpn();
    test_enable_ipv6_mvpn();
    test_enable_ipv4_rtc();
    test_enable_vpls();
    test_enable_route_refresh();
    test_default_four_byte_asn_capability();
    test_disable_four_byte_asn();
    test_disable_four_byte_asn_rejects_large_local_as();
    test_disable_four_byte_asn_rejects_large_remote_as();
    test_running_config_four_byte_asn_default_and_override();
    test_enable_graceful_restart();
    test_enable_graceful_restart_custom_time();
    test_enable_add_path();
    test_enable_add_path_specific_af();
    test_enable_ext_nh();
    test_enable_ext_nh_specific_af();
    test_disable_ipv4_unicast();
    test_disable_ipv6_unicast();
    test_disable_ipv4_labels();
    test_disable_ipv6_labels();
    test_disable_vpnv4();
    test_disable_vpnv6();
    test_disable_evpn();
    test_disable_ipv4_flowspec();
    test_disable_ipv6_flowspec();
    test_disable_ipv4_flowspec_vpn();
    test_disable_ipv6_flowspec_vpn();
    test_disable_ipv4_srpolicy();
    test_disable_ipv6_srpolicy();
    test_disable_bgp_ls();
    test_disable_ipv4_mvpn();
    test_disable_ipv6_mvpn();
    test_disable_ipv4_rtc();
    test_disable_vpls();
    test_disable_route_refresh();
    test_disable_graceful_restart();
    test_disable_add_path();
    test_disable_ext_nh();
    test_multiple_capabilities();

    test_basic_roundtrip();
    test_multiple_routers_roundtrip();
    test_all_capabilities_roundtrip();
    test_add_path_mixed_roundtrip();
    test_ribout_roundtrip();
    test_ribout_link_local_next_hop_roundtrip();
    test_ribout_vpn_roundtrip();
    test_ribout_srpolicy_roundtrip();
    test_ribout_color_community_roundtrip();
    test_ribout_flowspec_roundtrip();
    test_ribout_evpn_type2_roundtrip();
    test_ribout_rt_sets_and_label_rotate_roundtrip();
    test_compact_rt_sets_roundtrip();
    test_ribout_community_sets_roundtrip();
    test_ribout_key_rotation_roundtrip();
    test_ribout_long_ext_comm_lists_roundtrip();
    test_ribout_ip_rotate_roundtrip();
    test_ribout_rotation_options_roundtrip();
    test_combined_roundtrip();

    printf("\n========================================\n");
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    printf("========================================\n");

    return (tests_failed == 0) ? 0 : 1;
}
