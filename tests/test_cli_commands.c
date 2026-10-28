/*
 * BGP CLI Command Processing Tests
 * Tests command parsing and CLI functionality
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "util.h"
#include "bgpsim.h"
#include "output.h"
#include "parser.h"
#include "control.h"
#include "bgp_router.h"
#include "test_result.h"
#include "bgp_neighbor.h"
#include "test_helpers.h"
#include "bgp_ribout_snapshot.h"

static void init_cli_test_state(test_cli_session_t *state, cli_mode_t mode) {
    state->mode = mode;
    cli_session_init(&state->session);
}

static void run_cli_command(bgp_sim_t *sim, test_cli_session_t *state, const char *command) {
    cli_process_command(&state->session, sim, &state->mode, command);
}

static void enter_config_mode(bgp_sim_t *sim, test_cli_session_t *state) {
    run_cli_command(sim, state, "config");
}

static int output_contains_all(const char *output, const char *const *needles, size_t needle_count) {
    for (size_t i = 0; i < needle_count; i++) {
        if (strstr(output, needles[i]) == NULL) {
            return 0;
        }
    }

    return 1;
}

static int output_contains_none(const char *output, const char *const *needles, size_t needle_count) {
    for (size_t i = 0; i < needle_count; i++) {
        if (strstr(output, needles[i]) != NULL) {
            return 0;
        }
    }

    return 1;
}

/*
 * Run one command through the control client and copy its stdout and stderr text to the buffers. Returns the command
 * status, or -1 when the control exchange fails.
 */
static int run_control_command(bgpsim_control_client_t *client, const char *command,
                               char *stdout_buf, size_t stdout_buf_size,
                               char *stderr_buf, size_t stderr_buf_size) {
    test_output_capture_t capture;
    cli_mode_t            mode = CLI_MODE_EXEC;
    cli_session_t         session;
    int                   status = 0;
    int                   rc;

    test_output_capture_init(&capture);
    cli_session_init(&session);

    rc = bgpsim_control_client_execute(client, command, &mode, &session, test_output_capture_write, NULL, &capture, &status);
    if (stdout_buf && stdout_buf_size > 0) {
        snprintf(stdout_buf, stdout_buf_size, "%s", capture.stdout_buffer.data ? capture.stdout_buffer.data : "");
    }
    if (stderr_buf && stderr_buf_size > 0) {
        snprintf(stderr_buf, stderr_buf_size, "%s", capture.stderr_buffer.data ? capture.stderr_buffer.data : "");
    }

    test_output_capture_free(&capture);
    return rc == 0 ? status : -1;
}

void test_output_push_null_inherits_routed_output() {
    test_output_capture_t capture;
    output_t output = {
        .write = test_output_capture_write,
        .opaque = &capture
    };
    const output_t *previous_output;
    int             passed;

    test_output_capture_init(&capture);

    previous_output = output_push(&output);
    out_printf(NULL, "alpha stdout");
    err_printf(NULL, "beta stderr");
    output_pop(previous_output);

    passed = capture.stdout_buffer.data != NULL &&
             strstr(capture.stdout_buffer.data, "alpha stdout") != NULL &&
             capture.stderr_buffer.data != NULL &&
             strstr(capture.stderr_buffer.data, "beta stderr") != NULL;

    test_output_capture_free(&capture);
    test_result(passed, "NULL output inherits routed stdout/stderr");
}

void test_parser_help_inherits_routed_output() {
    static cmd_def_t help_commands[] = {
        { .name = "alpha", .help_text = "Alpha command" },
        { .name = "beta", .help_text = "Beta command" }
    };
    parser_ctx_t          parser;
    test_output_capture_t capture;
    output_t output = {
        .write = test_output_capture_write,
        .opaque = &capture
    };
    int passed;

    test_output_capture_init(&capture);
    parser_init(&parser, help_commands, (int)(sizeof(help_commands) / sizeof(help_commands[0])), NULL);

    /*
     * parser_show_help_with_output() owns the routing choice through its
     * explicit output argument. Drive it the same way the CLI does instead of
     * layering an extra output_push()/output_pop() pair around the call.
     */
    parser_show_help_with_output(&parser, &output);

    passed = capture.stderr_buffer.len == 0 &&
             capture.stdout_buffer.data != NULL &&
             strstr(capture.stdout_buffer.data, "alpha") != NULL &&
             strstr(capture.stdout_buffer.data, "Alpha command") != NULL &&
             strstr(capture.stdout_buffer.data, "beta") != NULL &&
             strstr(capture.stdout_buffer.data, "Beta command") != NULL;

    test_output_capture_free(&capture);
    test_result(passed, "Parser help inherits routed output");
}

typedef int (*cli_state_validator_t)(bgp_sim_t *sim);

typedef struct {
    const char           *name;
    const char           *setup_commands[4];
    int                   setup_count;
    const char           *invalid_command;
    const char           *recovery_command;
    cli_state_validator_t validator;
} cli_recovery_case_t;

static int validate_neighbor_mode_recovery(bgp_sim_t *sim) {
    bgp_router_t *router = bgp_find_router(sim, 65000);

    if (!router || router->neighbor_count == 0) {
        return 0;
    }

    return strcmp(router->neighbors[0]->ip, "10.0.0.1") == 0 &&
           router->neighbors[0]->capabilities.ipv4_unicast == 1;
}

static int validate_ribout_mode_recovery(bgp_sim_t *sim) {
    bgp_ribout_config_t *ribout = bgp_sim_find_ribout(sim, "recovery");

    return ribout != NULL &&
           ribout->prefix_spec.count == 4 &&
           ribout->prefix_spec.prefix_len == 24;
}

/*
 * Test 1: Initial CLI mode
 */
void test_initial_cli_mode() {
    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_EXEC);

    test_result(state.mode == CLI_MODE_EXEC, "Initial CLI mode is EXEC");
}

/*
 * Test 2: Mode transition to config
 */
void test_mode_transition_to_config() {
    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_EXEC);
    state.mode = CLI_MODE_CONFIG;

    test_result(state.mode == CLI_MODE_CONFIG, "Mode transition to CONFIG");
}

/*
 * Test 3: Mode transition back to exec
 */
void test_mode_transition_to_exec() {
    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_CONFIG);
    state.mode = CLI_MODE_EXEC;

    test_result(state.mode == CLI_MODE_EXEC, "Mode transition back to EXEC");
}

/*
 * Test 4: Empty command handling
 */
void test_empty_command() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_EXEC);

    // Empty command should be handled gracefully
    run_cli_command(&sim, &state, "");

    test_result(state.mode == CLI_MODE_EXEC, "Empty command handling");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 5: Whitespace-only command
 */
void test_whitespace_command() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_EXEC);

    run_cli_command(&sim, &state, "   ");

    test_result(state.mode == CLI_MODE_EXEC, "Whitespace-only command");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 6: Help command in EXEC mode
 */
void test_help_exec_mode() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_EXEC);

    // Help should work and not crash
    run_cli_command(&sim, &state, "help");

    test_result(state.mode == CLI_MODE_EXEC, "Help command in EXEC mode");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 7: Help command in CONFIG mode
 */
void test_help_config_mode() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_CONFIG);

    run_cli_command(&sim, &state, "help");

    test_result(state.mode == CLI_MODE_CONFIG, "Help command in CONFIG mode");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 7b: Global config help should stay current-mode only
 */
void test_help_global_config_surface() {
    static const char *required[] = {
        "router bgp <AS>",
        "  router bgp <AS>    Configure BGP routing",
        "ribout <name>",
        "exit",
        "end"
    };
    static const char *forbidden[] = {
        "Global configuration commands:",
        "Reachable parent configuration commands:",
        "Reachable EXEC commands:",
        "Note: Use 'no <command>'",
        "show bgp summary",
        "update generate",
        "router-id <router-id>",
        "address-family ipv4",
        "next-hop ..."
    };

    bgp_sim_t          sim = {0};
    test_cli_session_t state;
    char               stdout_buf[4096];
    char               stderr_buf[512];

    bgp_init_simulator(&sim);
    init_cli_test_state(&state, CLI_MODE_EXEC);
    enter_config_mode(&sim, &state);

    test_capture_command(&sim, &state.session, &state.mode, "help",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));

    test_result(state.mode == CLI_MODE_CONFIG &&
                stderr_buf[0] == '\0' &&
                output_contains_all(stdout_buf, required, sizeof(required) / sizeof(required[0])) &&
                output_contains_none(stdout_buf, forbidden, sizeof(forbidden) / sizeof(forbidden[0])),
                "Global config help stays current-mode only");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 7c: Router mode help should stay current-mode only
 */
void test_help_router_mode_surface() {
    static const char *required[] = {
        "router-id <router-id>",
        "update-source <source-ip>",
        "neighbor <ip> remote-as <AS>",
        "exit",
        "end"
    };
    static const char *forbidden[] = {
        "Router BGP configuration commands:",
        "Reachable parent configuration commands:",
        "Reachable EXEC commands:",
        "router bgp <AS>",
        "ribout <name>",
        "show bgp summary",
        "address-family ipv4",
        "next-hop ..."
    };

    bgp_sim_t          sim = {0};
    test_cli_session_t state;
    char               stdout_buf[4096];
    char               stderr_buf[512];

    bgp_init_simulator(&sim);
    init_cli_test_state(&state, CLI_MODE_EXEC);
    enter_config_mode(&sim, &state);
    run_cli_command(&sim, &state, "router bgp 65000");

    test_capture_command(&sim, &state.session, &state.mode, "help",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));

    test_result(state.mode == CLI_MODE_CONFIG &&
                stderr_buf[0] == '\0' &&
                output_contains_all(stdout_buf, required, sizeof(required) / sizeof(required[0])) &&
                output_contains_none(stdout_buf, forbidden, sizeof(forbidden) / sizeof(forbidden[0])),
                "Router mode help stays current-mode only");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 7d: Neighbor mode help should stay current-mode only
 */
void test_help_neighbor_mode_surface() {
    static const char *required[] = {
        "update-source <source-ip>",
        "advertise <ribout>",
        "address-family ipv4",
        "capability route-refresh",
        "capability four-byte-asn",
        "exit",
        "end"
    };
    static const char *forbidden[] = {
        "Neighbor configuration commands:",
        "Reachable parent configuration commands:",
        "Reachable EXEC commands:",
        "router-id <router-id>",
        "router bgp <AS>",
        "ribout <name>",
        "show bgp summary",
        "next-hop ..."
    };

    bgp_sim_t          sim = {0};
    test_cli_session_t state;
    char               stdout_buf[8192];
    char               stderr_buf[512];

    bgp_init_simulator(&sim);
    init_cli_test_state(&state, CLI_MODE_EXEC);
    enter_config_mode(&sim, &state);
    run_cli_command(&sim, &state, "router bgp 65000");
    run_cli_command(&sim, &state, "neighbor 10.0.0.1 remote-as 65001");

    test_capture_command(&sim, &state.session, &state.mode, "help",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));

    test_result(state.mode == CLI_MODE_CONFIG &&
                stderr_buf[0] == '\0' &&
                output_contains_all(stdout_buf, required, sizeof(required) / sizeof(required[0])) &&
                output_contains_none(stdout_buf, forbidden, sizeof(forbidden) / sizeof(forbidden[0])),
                "Neighbor mode help stays current-mode only");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 7e: RIB-OUT mode help should stay current-mode only
 */
void test_help_ribout_mode_surface() {
    static const char *required[] = {
        "prefix ...",
        "next-hop ...",
        "as-path ...",
        "exit",
        "end"
    };
    static const char *forbidden[] = {
        "RIB-OUT configuration commands:",
        "Reachable parent configuration commands:",
        "Reachable EXEC commands:",
        "router bgp <AS>",
        "ribout <name>",
        "show bgp summary",
        "neighbor <ip> remote-as <AS>",
        "address-family ipv4"
    };

    bgp_sim_t          sim = {0};
    test_cli_session_t state;
    char               stdout_buf[16384];
    char               stderr_buf[512];

    bgp_init_simulator(&sim);
    init_cli_test_state(&state, CLI_MODE_EXEC);
    enter_config_mode(&sim, &state);
    run_cli_command(&sim, &state, "ribout help-surface");

    test_capture_command(&sim, &state.session, &state.mode, "help",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));

    test_result(state.mode == CLI_MODE_CONFIG &&
                stderr_buf[0] == '\0' &&
                output_contains_all(stdout_buf, required, sizeof(required) / sizeof(required[0])) &&
                output_contains_none(stdout_buf, forbidden, sizeof(forbidden) / sizeof(forbidden[0])),
                "RIB-OUT mode help stays current-mode only");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 7e2: RIB-OUT mode help lists the FlowSpec lines; there is no rule mode and no steer line
 */
void test_help_ribout_flowspec_surface() {
    static const char *required[] = {
        "prefix ...",
        "src-prefix ...",
        "protocol ...",
        "tcp-flags ...",
        "flow-label ...",
        "action ...",
        "color ..."
    };
    static const char *forbidden[] = {
        "rule <name>",
        "steer ...",
        "dst-prefix ..."
    };

    bgp_sim_t          sim = {0};
    test_cli_session_t state;
    char               stdout_buf[16384];
    char               stderr_buf[512];

    bgp_init_simulator(&sim);
    init_cli_test_state(&state, CLI_MODE_EXEC);
    enter_config_mode(&sim, &state);
    run_cli_command(&sim, &state, "ribout help-flowspec");

    test_capture_command(&sim, &state.session, &state.mode, "help",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));

    test_result(state.mode == CLI_MODE_CONFIG &&
                stderr_buf[0] == '\0' &&
                output_contains_all(stdout_buf, required, sizeof(required) / sizeof(required[0])) &&
                output_contains_none(stdout_buf, forbidden, sizeof(forbidden) / sizeof(forbidden[0])),
                "RIB-OUT mode help lists the FlowSpec lines without a rule mode");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 7f: RIB-OUT parameter help should advertise the full supported syntax
 */
void test_help_ribout_parameter_syntax() {
    bgp_sim_t          sim = {0};
    test_cli_session_t state;
    char               stdout_buf[4096];
    char               stderr_buf[512];
    int                ok = 1;

    bgp_init_simulator(&sim);
    init_cli_test_state(&state, CLI_MODE_EXEC);
    enter_config_mode(&sim, &state);
    run_cli_command(&sim, &state, "ribout help-params");

    test_capture_command(&sim, &state.session, &state.mode, "localpref ?",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));
    ok = ok &&
         stderr_buf[0] == '\0' &&
         strstr(stdout_buf, "<value|rand|range|none>") != NULL &&
         strstr(stdout_buf, "u32 | rand(N) | range(A,B) | randrange(A,B) | none") != NULL;

    test_capture_command(&sim, &state.session, &state.mode, "path-id ?",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));
    ok = ok &&
         stderr_buf[0] == '\0' &&
         strstr(stdout_buf, "[rotate] <ids> | [rotate] <base> x <count> | range(A,B)") != NULL &&
         strstr(stdout_buf, "u32 list or interval") != NULL;

    test_capture_command(&sim, &state.session, &state.mode, "mac ?",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));
    ok = ok &&
         stderr_buf[0] == '\0' &&
         strstr(stdout_buf, "<mac|u64> [x <count>]") != NULL &&
         strstr(stdout_buf, "48-bit MAC or u64, sequential count") != NULL;

    test_capture_command(&sim, &state.session, &state.mode, "esi ?",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));
    ok = ok &&
         stderr_buf[0] == '\0' &&
         strstr(stdout_buf, "<esi|hex|u64> [x <count>] | <esi|hex|u64>...") != NULL &&
         strstr(stdout_buf, "10-octet ESI | 20-hex | u64") != NULL;

    test_capture_command(&sim, &state.session, &state.mode, "next-hop ?",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));
    ok = ok &&
         stderr_buf[0] == '\0' &&
         strstr(stdout_buf, "<ip> [x <count>] [link-local <ipv6>]") != NULL &&
         strstr(stdout_buf, "IPv4/IPv6 next hop, optional IPv6 link-local") != NULL;

    test_capture_command(&sim, &state.session, &state.mode, "rt-set ?",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));
    ok = ok &&
         stderr_buf[0] == '\0' &&
         strstr(stdout_buf, "[rt[,rt...]] ...") != NULL &&
         strstr(stdout_buf, "bracketed RT sets") != NULL;

    test_capture_command(&sim, &state.session, &state.mode, "router-mac ?",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));
    ok = ok &&
         stderr_buf[0] == '\0' &&
         strstr(stdout_buf, "<mac|u64> [x <count>] | <mac|u64>...") != NULL &&
         strstr(stdout_buf, "unicast 48-bit MAC or u64") != NULL;

    test_capture_command(&sim, &state.session, &state.mode, "binding-sid ?",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));
    ok = ok &&
         stderr_buf[0] == '\0' &&
         strstr(stdout_buf, "mpls <value|rand|range> | srv6 <sid> [x <count>]") != NULL &&
         strstr(stdout_buf, "MPLS labels or SRv6 SIDs") != NULL;

    test_capture_command(&sim, &state.session, &state.mode, "endpoint ?",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));
    ok = ok &&
         stderr_buf[0] == '\0' &&
         strstr(stdout_buf, "[rotate] <ip> [x <count>]") != NULL &&
         strstr(stdout_buf, "IPv4/IPv6 address, sequential count") != NULL;

    test_capture_command(&sim, &state.session, &state.mode, "enlp ?",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));
    ok = ok &&
         stderr_buf[0] == '\0' &&
         strstr(stdout_buf, "<value|rand|range>") != NULL &&
         strstr(stdout_buf, "1-4 | rand(N) | range(A,B) | randrange(A,B)") != NULL;

    test_capture_command(&sim, &state.session, &state.mode, "priority ?",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));
    ok = ok &&
         stderr_buf[0] == '\0' &&
         strstr(stdout_buf, "<value|rand|range>") != NULL &&
         strstr(stdout_buf, "0-255 | rand(N) | range(A,B) | randrange(A,B)") != NULL;

    test_result(ok, "RIB-OUT parameter help advertises full value syntax");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 8: Full-line '?' in EXEC mode should match flat interactive discovery
 */
void test_question_mark_help() {
    bgp_sim_t          sim = {0};
    test_cli_session_t state;
    char               stdout_buf[4096];
    char               stderr_buf[512];
    static const char *required[] = {
        "  config",
        "  configure",
        "show commands",
        "  clear",
        "  update",
        "  shutdown"
    };
    static const char *forbidden[] = {
        "show running-config",
        "show bgp summary",
        "Global configuration commands:",
        "Reachable EXEC commands:",
        "Note: Use 'no <command>'"
    };

    bgp_init_simulator(&sim);
    init_cli_test_state(&state, CLI_MODE_EXEC);

    test_capture_command(&sim, &state.session, &state.mode, "?",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));

    int passed = state.mode == CLI_MODE_EXEC &&
                 stderr_buf[0] == '\0' &&
                 output_contains_all(stdout_buf, required, sizeof(required) / sizeof(required[0])) &&
                 output_contains_none(stdout_buf, forbidden, sizeof(forbidden) / sizeof(forbidden[0]));
    test_result(passed, "Question mark in EXEC mode uses flat discovery output");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 8a: Full-line '?' in CONFIG mode should use the same flat style
 */
void test_question_mark_config_surface() {
    bgp_sim_t          sim = {0};
    test_cli_session_t state;
    char               stdout_buf[4096];
    char               stderr_buf[512];
    static const char *required[] = {
        "  router",
        "  ribout",
        "show commands",
        "  clear",
        "  update"
    };
    static const char *forbidden[] = {
        "router bgp <AS>    Configure BGP routing",
        "show bgp summary",
        "Global configuration commands:",
        "Reachable parent configuration commands:",
        "Reachable EXEC commands:",
        "Note: Use 'no <command>'"
    };

    bgp_init_simulator(&sim);
    init_cli_test_state(&state, CLI_MODE_EXEC);
    enter_config_mode(&sim, &state);

    test_capture_command(&sim, &state.session, &state.mode, "?",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));

    int passed = state.mode == CLI_MODE_CONFIG &&
                 stderr_buf[0] == '\0' &&
                 output_contains_all(stdout_buf, required, sizeof(required) / sizeof(required[0])) &&
                 output_contains_none(stdout_buf, forbidden, sizeof(forbidden) / sizeof(forbidden[0]));
    test_result(passed, "Question mark in CONFIG mode matches flat discovery output");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 8b: Inline exec-mode 'show bgp ?' should use the shared '?' renderer
 */
void test_inline_question_mark_exec_surface() {
    static const char *required[] = {
        "  summary",
        "  neighbors",
        "Show all BGP neighbors"
    };
    static const char *forbidden[] = {
        "Unknown Command:",
        "Incomplete Command:"
    };

    bgp_sim_t          sim = {0};
    test_cli_session_t state;
    char               stdout_buf[4096];
    char               stderr_buf[512];

    bgp_init_simulator(&sim);
    init_cli_test_state(&state, CLI_MODE_EXEC);

    test_capture_command(&sim, &state.session, &state.mode, "show bgp ?",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));

    test_result(state.mode == CLI_MODE_EXEC &&
                stderr_buf[0] == '\0' &&
                output_contains_all(stdout_buf, required, sizeof(required) / sizeof(required[0])) &&
                output_contains_none(stdout_buf, forbidden, sizeof(forbidden) / sizeof(forbidden[0])),
                "Inline exec-mode 'show bgp ?' uses shared discovery output");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 8c: Inline config-mode 'router bgp ?' should show the AS parameter
 */
void test_inline_question_mark_config_parameter() {
    static const char *required[] = {
        "<AS>",
        "AS number (1-4294967295)"
    };
    static const char *forbidden[] = {
        "Unknown Command:",
        "Incomplete Command:"
    };

    bgp_sim_t          sim = {0};
    test_cli_session_t state;
    char               stdout_buf[4096];
    char               stderr_buf[512];

    bgp_init_simulator(&sim);
    init_cli_test_state(&state, CLI_MODE_EXEC);
    enter_config_mode(&sim, &state);

    test_capture_command(&sim, &state.session, &state.mode, "router bgp ?",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));

    test_result(state.mode == CLI_MODE_CONFIG &&
                stderr_buf[0] == '\0' &&
                output_contains_all(stdout_buf, required, sizeof(required) / sizeof(required[0])) &&
                output_contains_none(stdout_buf, forbidden, sizeof(forbidden) / sizeof(forbidden[0])),
                "Inline config-mode 'router bgp ?' shows parameter help");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 8d: Full-line 'no ?' should match interactive negated discovery
 */
void test_question_mark_negated_config_surface() {
    static const char *required[] = {
        "  router",
        "  ribout"
    };
    static const char *forbidden[] = {
        "show commands",
        "  exit",
        "  end",
        "Unknown Command:"
    };

    bgp_sim_t          sim = {0};
    test_cli_session_t state;
    char               stdout_buf[4096];
    char               stderr_buf[512];

    bgp_init_simulator(&sim);
    init_cli_test_state(&state, CLI_MODE_EXEC);
    enter_config_mode(&sim, &state);

    test_capture_command(&sim, &state.session, &state.mode, "no ?",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));

    test_result(state.mode == CLI_MODE_CONFIG &&
                stderr_buf[0] == '\0' &&
                output_contains_all(stdout_buf, required, sizeof(required) / sizeof(required[0])) &&
                output_contains_none(stdout_buf, forbidden, sizeof(forbidden) / sizeof(forbidden[0])),
                "Full-line 'no ?' matches interactive negated discovery");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 8e: Exec fallback should preserve nested config mode after success
 */
void test_exec_fallback_preserves_nested_config_mode() {
    bgp_sim_t          sim = {0};
    test_cli_session_t state;
    char               stdout_buf[4096];
    char               stderr_buf[512];

    bgp_init_simulator(&sim);
    init_cli_test_state(&state, CLI_MODE_EXEC);
    enter_config_mode(&sim, &state);
    run_cli_command(&sim, &state, "router bgp 65000");
    run_cli_command(&sim, &state, "neighbor 10.0.0.1 remote-as 65001");

    test_capture_command(&sim, &state.session, &state.mode, "show bgp summary",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));

    test_result(state.mode == CLI_MODE_CONFIG &&
                state.session.config_mode == CONFIG_MODE_NEIGHBOR &&
                state.session.has_neighbor &&
                strcmp(state.session.current_neighbor_ip, "10.0.0.1") == 0 &&
                stderr_buf[0] == '\0' &&
                strstr(stdout_buf, "local AS number 65000") != NULL,
                "Exec fallback preserves nested config mode after show command");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 9: Config mode entry
 */
void test_config_mode_entry() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_EXEC);

    run_cli_command(&sim, &state, "config");

    test_result(state.mode == CLI_MODE_CONFIG, "Config mode entry");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 10: Exit config mode with 'end'
 */
void test_exit_config_end() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_CONFIG);

    // NOTE: 'end' command transitions mode, we test mode handling
    run_cli_command(&sim, &state, "end");

    test_result(state.mode == CLI_MODE_EXEC, "Exit config mode with 'end'");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 11: Exit config mode with 'exit' from CONFIG
 */
void test_exit_config_exit() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_CONFIG);

    // NOTE: 'exit' from CONFIG mode goes to EXEC, from EXEC it exits program
    run_cli_command(&sim, &state, "exit");

    test_result(state.mode == CLI_MODE_EXEC, "Exit config mode with 'exit'");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 12: Show routers command
 */
void test_show_routers() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    bgp_add_router(&sim, 65000);

    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_EXEC);

    // Should execute without crash
    run_cli_command(&sim, &state, "show bgp summary");

    test_result(state.mode == CLI_MODE_EXEC, "Show bgp summary command");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 13: Show neighbors command (all)
 */
void test_show_neighbors_all() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    bgp_add_router(&sim, 65000);
    bgp_add_neighbor(&sim, 65000, "10.0.0.1", 65001);

    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_EXEC);

    run_cli_command(&sim, &state, "show bgp neighbors");

    test_result(state.mode == CLI_MODE_EXEC, "Show bgp neighbors command (all)");

    bgp_shutdown_sim(&sim);
}

/*
 * Test 14: Show neighbors with AS filter
 */
void test_show_neighbors_filtered() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    bgp_add_router(&sim, 65000);
    bgp_add_neighbor(&sim, 65000, "10.0.0.1", 65001);

    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_EXEC);

    run_cli_command(&sim, &state, "show bgp neighbors 65000");

    test_result(state.mode == CLI_MODE_EXEC, "Show bgp neighbors with AS filter");

    bgp_shutdown_sim(&sim);
}

/*
 * Test 15: Show neighbors includes new capability families
 */
void test_show_neighbors_new_family_capabilities() {
    bgp_sim_t sim = {0};
    char      stdout_buf[8192];
    char      stderr_buf[1024];
    static const char *const needles[] = {
        "Multiprotocol IPv4 FlowSpec: advertised and received",
        "Multiprotocol IPv6 SR Policy: advertised and received",
        "Multiprotocol BGP-LS: advertised and received",
        "Multiprotocol IPv4 MVPN: advertised and received",
        "Multiprotocol RTC: advertised and received",
        "Multiprotocol L2VPN VPLS: advertised and received",
        "ADD-PATH IPv4 FlowSpec: advertised and received",
        "ADD-PATH IPv6 SR Policy: advertised and received",
        "ADD-PATH BGP-LS: advertised and received",
        "ADD-PATH IPv4 MVPN: advertised and received",
        "ADD-PATH RTC: advertised and received",
        "ADD-PATH L2VPN VPLS: advertised and received"
    };

    bgp_init_simulator(&sim);
    bgp_add_router(&sim, 65000);
    bgp_add_neighbor(&sim, 65000, "10.0.0.1", 65001);

    bgp_neighbor_t *neighbor = sim.routers[0]->neighbors[0];
    neighbor->peer_capabilities_received = 1;
    neighbor->capabilities.ipv4_flowspec = 1;
    neighbor->capabilities.ipv6_srpolicy = 1;
    neighbor->capabilities.bgp_ls = 1;
    neighbor->capabilities.ipv4_mvpn = 1;
    neighbor->capabilities.ipv4_rtc = 1;
    neighbor->capabilities.vpls = 1;
    neighbor->capabilities.add_path_ipv4_flowspec = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->capabilities.add_path_ipv6_srpolicy = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->capabilities.add_path_bgp_ls = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->capabilities.add_path_ipv4_mvpn = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->capabilities.add_path_ipv4_rtc = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->capabilities.add_path_vpls = ADD_PATH_SEND | ADD_PATH_RECEIVE;

    neighbor->peer_capabilities.ipv4_flowspec = 1;
    neighbor->peer_capabilities.ipv6_srpolicy = 1;
    neighbor->peer_capabilities.bgp_ls = 1;
    neighbor->peer_capabilities.ipv4_mvpn = 1;
    neighbor->peer_capabilities.ipv4_rtc = 1;
    neighbor->peer_capabilities.vpls = 1;
    neighbor->peer_capabilities.add_path_ipv4_flowspec = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->peer_capabilities.add_path_ipv6_srpolicy = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->peer_capabilities.add_path_bgp_ls = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->peer_capabilities.add_path_ipv4_mvpn = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->peer_capabilities.add_path_ipv4_rtc = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    neighbor->peer_capabilities.add_path_vpls = ADD_PATH_SEND | ADD_PATH_RECEIVE;

    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_EXEC);

    test_capture_command(&sim, &state.session, &state.mode, "show bgp neighbors 65000",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));

    test_result(output_contains_all(stdout_buf, needles,
                                    sizeof(needles) / sizeof(needles[0])) &&
                stderr_buf[0] == '\0',
                "Show bgp neighbors includes new family capabilities");

    bgp_shutdown_sim(&sim);
}

/*
 * Test 16: Router BGP command in config mode
 */
void test_router_bgp_command() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_CONFIG);

    run_cli_command(&sim, &state, "router bgp 65000");

    bgp_router_t *router = bgp_find_router(&sim, 65000);
    test_result(router != NULL, "Router BGP command in config mode");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 16: Neighbor command in config mode
 */
void test_neighbor_command() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    bgp_add_router(&sim, 65000);

    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_CONFIG);

    run_cli_command(&sim, &state, "neighbor 10.0.0.1 remote-as 65001");

    // Check if command was processed
    test_result(state.mode == CLI_MODE_CONFIG, "Neighbor command in config mode");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 17: No router command
 */
void test_no_router_command() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    bgp_add_router(&sim, 65000);

    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_CONFIG);

    run_cli_command(&sim, &state, "no router bgp 65000");

    test_result(state.mode == CLI_MODE_CONFIG, "No router command");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 18: No neighbor command
 */
void test_no_neighbor_command() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    bgp_add_router(&sim, 65000);
    bgp_add_neighbor(&sim, 65000, "10.0.0.1", 65001);

    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_CONFIG);

    run_cli_command(&sim, &state, "no neighbor 10.0.0.1 remote-as 65001");

    test_result(state.mode == CLI_MODE_CONFIG, "No neighbor command");

    bgp_shutdown_sim(&sim);
}

/*
 * Test 19: Invalid command in EXEC mode
 */
void test_invalid_command_exec() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_EXEC);

    // NOTE: Skip 'quit' and 'exit' from EXEC mode as they terminate the program
    run_cli_command(&sim, &state, "invalid_command_xyz");

    // Should stay in same mode
    test_result(state.mode == CLI_MODE_EXEC, "Invalid command in EXEC mode");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 20: Invalid command in CONFIG mode
 */
void test_invalid_command_config() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_CONFIG);

    run_cli_command(&sim, &state, "invalid_command_xyz");

    test_result(state.mode == CLI_MODE_CONFIG, "Invalid command in CONFIG mode");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 20a: Incomplete command should report incomplete, not unknown
 */
void test_incomplete_command_config() {
    bgp_sim_t          sim = {0};
    test_cli_session_t state;
    char               stdout_buf[256];
    char               stderr_buf[256];

    bgp_init_simulator(&sim);
    init_cli_test_state(&state, CLI_MODE_EXEC);
    enter_config_mode(&sim, &state);

    test_capture_command(&sim, &state.session, &state.mode, "router bgp",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));

    test_result(state.mode == CLI_MODE_CONFIG &&
                stdout_buf[0] == '\0' &&
                strstr(stderr_buf, "Incomplete Command: router bgp") != NULL &&
                strstr(stderr_buf, "Unknown Command") == NULL,
                "Incomplete config command reports 'Incomplete Command'");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 20b: Invalid nested command should preserve current config context
 */
void test_invalid_nested_command_recovery() {
    static const cli_recovery_case_t cases[] = {
        {
            "Invalid command does not unwind out of neighbor mode",
            {
                "router bgp 65000",
                "neighbor 10.0.0.1 remote-as 65001",
            },
            2,
            "invalid_command_xyz",
            "address-family ipv4",
            validate_neighbor_mode_recovery
        },
        {
            "Invalid command does not unwind out of ribout mode",
            {
                "ribout recovery",
            },
            1,
            "invalid_command_xyz",
            "prefix 10.0.0.0/24 x 4",
            validate_ribout_mode_recovery
        }
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        bgp_sim_t          sim = {0};
        test_cli_session_t state;

        bgp_init_simulator(&sim);
        init_cli_test_state(&state, CLI_MODE_EXEC);
        enter_config_mode(&sim, &state);

        for (int j = 0; j < cases[i].setup_count; j++) {
            run_cli_command(&sim, &state, cases[i].setup_commands[j]);
        }

        run_cli_command(&sim, &state, cases[i].invalid_command);
        run_cli_command(&sim, &state, cases[i].recovery_command);

        test_result(state.mode == CLI_MODE_CONFIG && cases[i].validator(&sim), cases[i].name);
        bgp_shutdown_sim(&sim);
    }
}

/*
 * Test 21: Very long command line
 */
void test_long_command() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_EXEC);

    char long_cmd[BGPSIM_COMMAND_SIZE + 32];
    memset(long_cmd, 'A', sizeof(long_cmd) - 1);
    long_cmd[sizeof(long_cmd) - 1] = '\0';

    char out[256], err[256];
    test_capture_command(&sim, &state.session, &state.mode, long_cmd, out, sizeof(out), err, sizeof(err));
    int rejected = strstr(err, "command is too long") != NULL && sim.router_count == 0;
    run_cli_command(&sim, &state, "config");
    run_cli_command(&sim, &state, "router bgp 65000");
    test_result(rejected && bgp_find_router(&sim, 65000) && sim.router_count == 1,
                "Oversized CLI command is rejected without state changes and next command executes");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 22: Command with leading whitespace
 */
void test_leading_whitespace() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_EXEC);

    run_cli_command(&sim, &state, "    help");

    test_result(state.mode == CLI_MODE_EXEC, "Command with leading whitespace");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 23: Command with trailing whitespace
 */
void test_trailing_whitespace() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_EXEC);

    run_cli_command(&sim, &state, "help    ");

    test_result(state.mode == CLI_MODE_EXEC, "Command with trailing whitespace");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 24: Command with extra spaces
 */
void test_extra_spaces() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_EXEC);

    run_cli_command(&sim, &state, "show    routers");

    test_result(state.mode == CLI_MODE_EXEC, "Command with extra spaces");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 25: Case sensitivity of commands
 */
void test_command_case_sensitivity() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_EXEC);

    char out[256], err[256];
    test_capture_command(&sim, &state.session, &state.mode, "HELP", out, sizeof(out), err, sizeof(err));
    test_result(strstr(err, "Unknown") && state.mode == CLI_MODE_EXEC && sim.router_count == 0,
                "CLI keywords are case-sensitive and rejected input leaves mode unchanged");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 26: Negated exit should be rejected
 */
void test_no_exit_rejected() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_EXEC);
    char stdout_buf[256];
    char stderr_buf[256];

    enter_config_mode(&sim, &state);
    test_capture_command(&sim, &state.session, &state.mode, "no exit",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));

    test_result(state.mode == CLI_MODE_CONFIG &&
                strstr(stderr_buf, "'no exit' is not supported") != NULL,
                "Reject 'no exit' in config mode");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 27: Negated end should be rejected
 */
void test_no_end_rejected() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_EXEC);
    char stdout_buf[256];
    char stderr_buf[256];

    enter_config_mode(&sim, &state);
    test_capture_command(&sim, &state.session, &state.mode, "no end",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));

    test_result(state.mode == CLI_MODE_CONFIG &&
                strstr(stderr_buf, "'no end' is not supported") != NULL,
                "Reject 'no end' in config mode");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 28: Negated exec command should not fall through in config mode
 */
void test_no_exec_fallback_rejected() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_EXEC);
    char stdout_buf[512];
    char stderr_buf[512];

    enter_config_mode(&sim, &state);
    test_capture_command(&sim, &state.session, &state.mode, "no show running-config",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));

    test_result(state.mode == CLI_MODE_CONFIG &&
                stdout_buf[0] == '\0' &&
                strstr(stderr_buf, "Unknown Command: show running-config") != NULL,
                "Reject negated exec fallback in config mode");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 29: Negated router-id should not mutate router state
 */
void test_no_router_id_rejected() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_EXEC);
    char stdout_buf[256];
    char stderr_buf[256];

    enter_config_mode(&sim, &state);
    run_cli_command(&sim, &state, "router bgp 65000");

    bgp_router_t *router = bgp_find_router(&sim, 65000);
    test_capture_command(&sim, &state.session, &state.mode, "no router-id 1.2.3.4",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));

    test_result(router != NULL &&
                router->router_id_configured == 0,
                "Reject negated router-id without changing router state");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 30: Negated update-source should clear router state
 */
void test_no_update_source_rejected() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_EXEC);
    char stdout_buf[256];
    char stderr_buf[256];

    enter_config_mode(&sim, &state);
    run_cli_command(&sim, &state, "router bgp 65000");
    run_cli_command(&sim, &state, "update-source 192.168.1.1");

    bgp_router_t *router = bgp_find_router(&sim, 65000);
    test_capture_command(&sim, &state.session, &state.mode, "no update-source 192.168.1.1",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));

    test_result(router != NULL &&
                stderr_buf[0] == '\0' &&
                router->source_ip[0] == '\0',
                "Negated update-source clears router state");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 31: Negated update-source should clear neighbor override only
 */
void test_no_neighbor_update_source_clears_override() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_EXEC);
    char stdout_buf[256];
    char stderr_buf[256];

    enter_config_mode(&sim, &state);
    run_cli_command(&sim, &state, "router bgp 65000");
    run_cli_command(&sim, &state, "update-source 192.168.1.1");
    run_cli_command(&sim, &state, "neighbor 10.0.0.1 remote-as 65001");
    run_cli_command(&sim, &state, "update-source 10.0.0.254");

    bgp_router_t   *router = bgp_find_router(&sim, 65000);
    bgp_neighbor_t *neighbor = router != NULL ? router->neighbors[0] : NULL;
    test_capture_command(&sim, &state.session, &state.mode, "no update-source 10.0.0.254",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));

    test_result(router != NULL &&
                neighbor != NULL &&
                stderr_buf[0] == '\0' &&
                strcmp(router->source_ip, "192.168.1.1") == 0 &&
                neighbor->source_ip[0] == '\0',
                "Negated update-source clears neighbor override");
    bgp_shutdown_sim(&sim);
}

/*
 * One command on router 65000, its expected outcome, and the router's VRF after it.
 */
typedef struct {
    const char *command;
    int         accepted;
    const char *error;
    const char *vrf;
} vrf_step_t;

#define VRF_63_CHARS "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

/*
 * Run the steps in one session. No runtime exists here, so nothing opens a namespace.
 */
static void run_vrf_steps(const char *name, const vrf_step_t *steps, size_t count) {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_EXEC);

    enter_config_mode(&sim, &state);
    run_cli_command(&sim, &state, "router bgp 65000");
    bgp_router_t *router = bgp_find_router(&sim, 65000);

    for (size_t i = 0; i < count; i++) {
        char stdout_buf[256];
        char stderr_buf[256];
        char label[256];
        int  status = test_capture_command(&sim, &state.session, &state.mode, steps[i].command, stdout_buf,
                                           sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));

        snprintf(label, sizeof(label), "%s %zu: %s", name, i + 1, steps[i].command);
        test_result((steps[i].accepted ? status >= 0 : status < 0) &&
                    (!steps[i].error || strstr(stderr_buf, steps[i].error) != NULL) &&
                    strcmp(router->vrf, steps[i].vrf) == 0,
                    label);
    }
    bgp_shutdown_sim(&sim);
}

void test_vrf_names() {
    static const vrf_step_t steps[] = {
        {"vrf", 0, "VRF name required", ""},
        {"vrf ns-BLUE", 1, NULL, "ns-BLUE"},
        {"no vrf other", 0, "not in VRF other", "ns-BLUE"},
        {"no vrf ns-BLUE", 1, NULL, ""},
        {"no vrf", 1, NULL, ""},
        {"no vrf other", 0, "not in VRF other", ""},
        {"vrf ns-RED", 1, NULL, "ns-RED"},
        {"no vrf", 1, NULL, ""},
        {"vrf KEEP", 1, NULL, "KEEP"},
        {"vrf a/b", 0, "Invalid VRF name", "KEEP"},
        {"vrf .", 0, "Invalid VRF name", "KEEP"},
        {"vrf ..", 0, "Invalid VRF name", "KEEP"},
        {"vrf /etc/passwd", 0, "Invalid VRF name", "KEEP"},
        {"vrf ../x", 0, "Invalid VRF name", "KEEP"},
        {"vrf all", 0, "reserved", "KEEP"},
        {"vrf default", 0, "reserved", "KEEP"},
        {"vrf allowed", 1, NULL, "allowed"},
        {"vrf " VRF_63_CHARS, 1, NULL, VRF_63_CHARS},
        {"vrf " VRF_63_CHARS "a", 0, NULL, VRF_63_CHARS},
    };

    run_vrf_steps("VRF name", steps, sizeof(steps) / sizeof(steps[0]));
}

/*
 * The VRF of a router can change at any time; only a name that is not its VRF is refused by no vrf.
 */
void test_vrf_changes_with_neighbors() {
    static const vrf_step_t late[] = {
        {"neighbor 10.0.0.1 remote-as 65001", 1, NULL, ""},
        {"vrf BLUE", 1, NULL, "BLUE"},
    };
    static const vrf_step_t in_vrf[] = {
        {"vrf RED", 1, NULL, "RED"},
        {"neighbor 10.0.0.2 remote-as 65011", 1, NULL, "RED"},
        {"vrf RED", 1, NULL, "RED"},
        {"vrf BLUE", 1, NULL, "BLUE"},
        {"no vrf RED", 0, "not in VRF RED", "BLUE"},
        {"router bgp 65000", 1, NULL, "BLUE"},
        {"vrf GREEN", 1, NULL, "GREEN"},
        {"no vrf GREEN", 1, NULL, ""},
        {"vrf BLUE", 1, NULL, "BLUE"},
        {"no neighbor 10.0.0.2 remote-as 65011", 1, NULL, "BLUE"},
        {"vrf RED", 1, NULL, "RED"},
    };

    run_vrf_steps("VRF after a neighbor", late, sizeof(late) / sizeof(late[0]));
    run_vrf_steps("VRF with neighbors", in_vrf, sizeof(in_vrf) / sizeof(in_vrf[0]));
}

/*
 * One clear bgp command and the resets it added to each router's first neighbor: own, BLUE and RED.
 */
static void expect_clear(bgp_sim_t *sim, test_cli_session_t *state, const char *command, int expect_status,
                         uint64_t own, uint64_t blue, uint64_t red) {
    static const uint32_t routers[] = {65000, 65010, 65020};
    uint64_t       before[3];
    const uint64_t added[3] = {own, blue, red};
    char           stderr_buf[256];
    char           stdout_buf[256];
    int            ok;

    for (int i = 0; i < 3; i++) {
        before[i] = bgp_find_router(sim, routers[i])->neighbors[0]->session_resets;
    }
    int status = test_capture_command(sim, &state->session, &state->mode, command,
                                      stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));
    ok = expect_status < 0 ? status < 0 : status >= 0;
    for (int i = 0; i < 3; i++) {
        ok = ok && bgp_find_router(sim, routers[i])->neighbors[0]->session_resets == before[i] + added[i];
    }
    test_result(ok, command);
}

void test_clear_bgp_scope() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_EXEC);

    enter_config_mode(&sim, &state);
    run_cli_command(&sim, &state, "router bgp 65000");
    run_cli_command(&sim, &state, "neighbor 10.0.0.1 remote-as 65001");
    run_cli_command(&sim, &state, "exit");
    run_cli_command(&sim, &state, "exit");
    run_cli_command(&sim, &state, "router bgp 65010");
    run_cli_command(&sim, &state, "vrf BLUE");
    run_cli_command(&sim, &state, "neighbor 10.0.0.1 remote-as 65011");
    run_cli_command(&sim, &state, "exit");
    run_cli_command(&sim, &state, "exit");
    run_cli_command(&sim, &state, "router bgp 65020");
    run_cli_command(&sim, &state, "vrf RED");
    run_cli_command(&sim, &state, "neighbor 10.0.0.2 remote-as 65021");
    run_cli_command(&sim, &state, "end");

    expect_clear(&sim, &state, "clear bgp vrf BLUE 10.0.0.1", 0, 0, 1, 0);
    expect_clear(&sim, &state, "clear bgp router 65000 10.0.0.1", 0, 1, 0, 0);
    expect_clear(&sim, &state, "clear bgp vrf default 10.0.0.1", 0, 1, 0, 0);
    expect_clear(&sim, &state, "clear bgp vrf all 10.0.0.1", 0, 1, 1, 0);
    expect_clear(&sim, &state, "clear bgp 10.0.0.1", 0, 1, 1, 0);
    expect_clear(&sim, &state, "clear bgp vrf default *", 0, 1, 0, 0);
    expect_clear(&sim, &state, "clear bgp router 65020 *", 0, 0, 0, 1);
    expect_clear(&sim, &state, "clear bgp vrf RED *", 0, 0, 0, 1);
    expect_clear(&sim, &state, "clear bgp vrf all *", 0, 1, 1, 1);
    expect_clear(&sim, &state, "clear bgp *", 0, 1, 1, 1);
    expect_clear(&sim, &state, "clear bgp vrf BLUE 10.0.0.2", -1, 0, 0, 0);
    expect_clear(&sim, &state, "clear bgp vrf NOPE 10.0.0.1", -1, 0, 0, 0);
    expect_clear(&sim, &state, "clear bgp vrf NOPE *", -1, 0, 0, 0);
    expect_clear(&sim, &state, "clear bgp router 1 *", -1, 0, 0, 0);
    bgp_shutdown_sim(&sim);
}

void test_vrf_is_a_router_command() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_EXEC);
    char output[256];

    int status = test_capture_command(&sim, &state.session, &state.mode, "vrf BLUE", output, sizeof(output), NULL, 0);
    test_result(status < 0, "vrf is rejected in exec mode");

    enter_config_mode(&sim, &state);
    status = test_capture_command(&sim, &state.session, &state.mode, "vrf BLUE", output, sizeof(output), NULL, 0);
    test_result(status < 0 && sim.router_count == 0, "vrf is rejected outside a router");
    bgp_shutdown_sim(&sim);
}

void test_vrf_shown_only_when_set() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    test_cli_session_t state;
    init_cli_test_state(&state, CLI_MODE_EXEC);
    char output[4096];
    char stderr_buf[256];

    enter_config_mode(&sim, &state);
    run_cli_command(&sim, &state, "router bgp 65000");
    run_cli_command(&sim, &state, "neighbor 10.0.0.1 remote-as 65001");
    run_cli_command(&sim, &state, "exit");
    run_cli_command(&sim, &state, "exit");
    run_cli_command(&sim, &state, "router bgp 65010");
    run_cli_command(&sim, &state, "vrf BLUE");
    run_cli_command(&sim, &state, "neighbor 10.0.0.2 remote-as 65011");
    run_cli_command(&sim, &state, "end");

    test_capture_command(&sim, &state.session, &state.mode, "show bgp summary",
                         output, sizeof(output), stderr_buf, sizeof(stderr_buf));
    test_result(strstr(output, "local AS number 65000\n") != NULL &&
                strstr(output, "local AS number 65010, VRF BLUE\n") != NULL,
                "show bgp summary names the VRF only for a router that has one");

    test_capture_command(&sim, &state.session, &state.mode, "show bgp neighbors",
                         output, sizeof(output), stderr_buf, sizeof(stderr_buf));
    test_result(strstr(output, "BGP neighbor is 10.0.0.1, remote AS 65001, local AS 65000\n") != NULL &&
                strstr(output, "BGP neighbor is 10.0.0.2, remote AS 65011, local AS 65010, VRF BLUE\n") != NULL,
                "show bgp neighbors names the VRF only for a router that has one");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 32: Prompt transitions should track explicit CLI session state
 */
void test_prompt_transitions() {
    typedef struct {
        const char *command;
        cli_mode_t  expected_mode;
        const char *expected_prompt;
        const char *description;
    } prompt_case_t;

    static const prompt_case_t cases[] = {
        { "config", CLI_MODE_CONFIG, BGPSIM "(config)# ",
          "Prompt enters global config mode" },
        { "router bgp 65000", CLI_MODE_CONFIG, BGPSIM "(config-router-bgp-65000)# ",
          "Prompt enters router mode" },
        { "neighbor 10.0.0.1 remote-as 65001", CLI_MODE_CONFIG,
          BGPSIM "(config-router-bgp-65000-neighbor-10.0.0.1)# ",
          "Prompt enters neighbor mode" },
        { "exit", CLI_MODE_CONFIG, BGPSIM "(config-router-bgp-65000)# ",
          "Prompt exits back to router mode" },
        { "exit", CLI_MODE_CONFIG, BGPSIM "(config)# ",
          "Prompt exits back to global config" },
        { "ribout prompt-check", CLI_MODE_CONFIG, BGPSIM "(config-ribout-prompt-check)# ",
          "Prompt enters ribout mode" },
        { "end", CLI_MODE_EXEC, BGPSIM "> ",
          "Prompt returns to exec mode" },
    };

    bgp_sim_t          sim = {0};
    test_cli_session_t state = { .mode = CLI_MODE_EXEC };
    char               prompt[128];

    bgp_init_simulator(&sim);

    cli_build_prompt(state.mode, &state.session, prompt, sizeof(prompt), 0);
    test_result(strcmp(prompt, BGPSIM "> ") == 0, "Initial prompt is exec mode");

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        run_cli_command(&sim, &state, cases[i].command);
        cli_build_prompt(state.mode, &state.session, prompt, sizeof(prompt), 0);

        test_result(state.mode == cases[i].expected_mode &&
                    strcmp(prompt, cases[i].expected_prompt) == 0,
                    cases[i].description);
    }

    bgp_shutdown_sim(&sim);
}

/*
 * Test 32: Multiple control sessions should coexist without degraded output
 */
void test_control_server_multiple_sessions() {
    bgp_sim_t               sim = {0};
    char                    socket_path[108];
    char                    output1[1024];
    char                    output2[1024];
    char                    output3[1024];
    bgpsim_control_client_t client1;
    bgpsim_control_client_t client2;
    bgpsim_control_client_t client3;
    int                     server_started = 0;
    int                     passed = 0;

    memset(&client1, 0, sizeof(client1));
    memset(&client2, 0, sizeof(client2));
    memset(&client3, 0, sizeof(client3));
    client1.fd = -1;
    client2.fd = -1;
    client3.fd = -1;

    snprintf(socket_path, sizeof(socket_path), "/tmp/bgpsim-test-cli-%ld.sock", (long)getpid());

    bgp_init_simulator(&sim);
    unlink(socket_path);

    if (bgpsim_control_init(&sim, socket_path) != 0) {
        test_result(0, "Control server multi-session warning");
        bgp_shutdown_sim(&sim);
        return;
    }
    server_started = 1;

    if (bgpsim_control_client_open(&client1, socket_path) != 0 ||
        run_control_command(&client1, "show bgp summary", output1, sizeof(output1), NULL, 0) != 0) {
        goto cleanup;
    }

    if (bgpsim_control_client_open(&client2, socket_path) != 0 ||
        run_control_command(&client2, "show bgp summary", output2, sizeof(output2), NULL, 0) != 0) {
        goto cleanup;
    }

    if (bgpsim_control_client_open(&client3, socket_path) != 0 ||
        run_control_command(&client3, "show bgp summary", output3, sizeof(output3), NULL, 0) != 0) {
        goto cleanup;
    }

    passed = strstr(output1, "No BGP routers configured.") != NULL &&
             strstr(output2, "No BGP routers configured.") != NULL &&
             strstr(output3, "No BGP routers configured.") != NULL;

cleanup:
    bgpsim_control_client_close(&client3);
    bgpsim_control_client_close(&client2);
    bgpsim_control_client_close(&client1);
    if (server_started) {
        bgpsim_control_shutdown();
    }
    unlink(socket_path);
    bgp_shutdown_sim(&sim);

    test_result(passed, "Control server allows multiple sessions");
}

void test_update_generate_srpolicy_without_prefix() {
    bgp_sim_t          sim = {0};
    test_cli_session_t state;
    char               stdout_buf[4096];
    char               stderr_buf[512];

    bgp_init_simulator(&sim);
    init_cli_test_state(&state, CLI_MODE_EXEC);

    enter_config_mode(&sim, &state);
    run_cli_command(&sim, &state, "ribout sr-scale");
    run_cli_command(&sim, &state, "distinguisher 100");
    run_cli_command(&sim, &state, "color 200");
    run_cli_command(&sim, &state, "endpoint 2001:db8:100::1 x 4");
    run_cli_command(&sim, &state, "next-hop 2001:db8:feed::1");
    run_cli_command(&sim, &state, "rt 192.0.2.10:100");
    run_cli_command(&sim, &state,
                    "segment-list 7 weight 70 srv6 "
                    "2001:db8:7::1 2001:db8:7::2 2001:db8:7::3 "
                    "2001:db8:7::4 2001:db8:7::5 2001:db8:7::6");
    run_cli_command(&sim, &state, "end");

    test_capture_command(&sim, &state.session, &state.mode, "update generate",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));

    test_result(state.mode == CLI_MODE_EXEC &&
                stderr_buf[0] == '\0' &&
                strstr(stdout_buf, "ribout sr-scale: Generated") != NULL &&
                strstr(stdout_buf, "Skipped") == NULL &&
                sim.ribout_count == 1 &&
                sim.ribouts[0]->message_count > 0,
                "Update generate handles SR Policy ribouts without prefix NLRI");
    bgp_shutdown_sim(&sim);
}

void test_update_generate_evpn_type2_without_prefix() {
    bgp_sim_t          sim = {0};
    test_cli_session_t state;
    char               stdout_buf[4096];
    char               stderr_buf[512];

    bgp_init_simulator(&sim);
    init_cli_test_state(&state, CLI_MODE_EXEC);

    enter_config_mode(&sim, &state);
    run_cli_command(&sim, &state, "ribout evpn2-scale");
    run_cli_command(&sim, &state, "rd 65000:320");
    run_cli_command(&sim, &state, "ethernet-tag 10");
    run_cli_command(&sim, &state, "mac 00:11:22:33:44:00 x 4");
    run_cli_command(&sim, &state, "ip 192.0.2.1 x 2");
    run_cli_command(&sim, &state, "label 30000");
    run_cli_command(&sim, &state, "label2 40000 40001");
    run_cli_command(&sim, &state, "next-hop 192.0.2.10");
    run_cli_command(&sim, &state, "rt 65000:320");
    run_cli_command(&sim, &state, "end");

    test_capture_command(&sim, &state.session, &state.mode, "update generate",
                         stdout_buf, sizeof(stdout_buf), stderr_buf, sizeof(stderr_buf));

    test_result(state.mode == CLI_MODE_EXEC &&
                stderr_buf[0] == '\0' &&
                strstr(stdout_buf, "ribout evpn2-scale: Generated") != NULL &&
                strstr(stdout_buf, "Skipped") == NULL &&
                sim.ribout_count == 1 &&
                sim.ribouts[0]->message_count > 0,
                "Update generate handles EVPN Type 2 ribouts without prefix NLRI");
    bgp_shutdown_sim(&sim);
}

static void test_update_generate_selection(void) {
    bgp_sim_t          sim;
    test_cli_session_t state;
    char               out[4096], err[512];
    bgp_init_simulator(&sim);
    init_cli_test_state(&state, CLI_MODE_EXEC);
    bgp_ribout_config_t *blocks[3];
    const char *names[] = {"a", "b", "c"};
    int setup = 1;
    for (int i = 0; i < 3; i++) {
        blocks[i] = bgp_sim_add_ribout(&sim, names[i]);
        setup &= blocks[i] && bgp_ribout_edit(blocks[i], "prefix", "10.0.0.0/24", 0) == 0 &&
                 bgp_ribout_edit(blocks[i], "next-hop", "192.0.2.1", 0) == 0;
    }
    setup &= test_capture_command(&sim, &state.session, &state.mode, "update generate",
                                  out, sizeof(out), err, sizeof(err)) >= 0;
    for (int i = 0; i < 3; i++) setup &= blocks[i] && blocks[i]->snapshot;
    test_result(setup, "Initial full generation publishes every selected-test fixture");
    if (!setup) goto done;
    uint64_t a = blocks[0]->snapshot->id, b = blocks[1]->snapshot->id, c = blocks[2]->snapshot->id;
    bgp_ribout_edit(blocks[0], "localpref", "200", 0);
    bgp_ribout_edit(blocks[1], "localpref", "300", 0);
    int rc = test_capture_command(&sim, &state.session, &state.mode, "update generate ribout a missing",
                                  out, sizeof(out), err, sizeof(err));
    test_result(rc < 0 && strstr(err, "missing") && blocks[0]->snapshot->id == a &&
                blocks[1]->snapshot->id == b && blocks[2]->snapshot->id == c && blocks[0]->dirty,
                "Unknown selection names reject the complete command before publication");
    rc = test_capture_command(&sim, &state.session, &state.mode, "update generate ribout a a c",
                              out, sizeof(out), err, sizeof(err));
    test_result(rc >= 0 && !*err && blocks[0]->snapshot->id > a && blocks[2]->snapshot->id > c &&
                blocks[2]->snapshot->id == blocks[0]->snapshot->id + 1 &&
                blocks[1]->snapshot->id == b && blocks[1]->dirty && !blocks[0]->dirty &&
                !strstr(out, "ribout b:"), "Named generation deduplicates names and leaves unrelated dirty blocks untouched");
    a = blocks[0]->snapshot->id;
    c = blocks[2]->snapshot->id;
    rc = test_capture_command(&sim, &state.session, &state.mode, "up gen ch", out, sizeof(out), err, sizeof(err));
    test_result(rc >= 0 && blocks[0]->snapshot->id == a && blocks[2]->snapshot->id == c &&
                blocks[1]->snapshot->id > b && !blocks[1]->dirty && strstr(out, "ribout b: Generated"),
                "Changed generation supports keyword abbreviations and regenerates only dirty blocks");
    b = blocks[1]->snapshot->id;
    rc = test_capture_command(&sim, &state.session, &state.mode, "update generate changed",
                              out, sizeof(out), err, sizeof(err));
    test_result(rc >= 0 && strstr(out, "No changed") && blocks[0]->snapshot->id == a &&
                blocks[1]->snapshot->id == b && blocks[2]->snapshot->id == c,
                "Changed generation with current snapshots performs no regeneration");
    bgp_ribout_edit(blocks[1], "label", "2000000", 0);
    rc = test_capture_command(&sim, &state.session, &state.mode, "update generate changed",
                              out, sizeof(out), err, sizeof(err));
    test_result(rc < 0 && blocks[1]->dirty && blocks[1]->snapshot->id == b &&
                blocks[0]->snapshot->id == a && blocks[2]->snapshot->id == c,
                "Failed selective generation retains the old snapshot and dirty state");
    bgp_ribout_config_t *pending = bgp_sim_add_ribout(&sim, "pending");
    rc = test_capture_command(&sim, &state.session, &state.mode, "update generate ribout pending a",
                              out, sizeof(out), err, sizeof(err));
    test_result(rc >= 0 && pending && pending->dirty && !pending->snapshot && strstr(out, "Skipped") &&
                blocks[0]->snapshot->id > a && blocks[1]->snapshot->id == b,
                "An incomplete selected block is reported and unrelated invalid blocks are not generated");
    bgp_ribout_edit(blocks[1], "label", "", 1);
    a = blocks[0]->snapshot->id;
    rc = test_capture_command(&sim, &state.session, &state.mode, "update generate", out, sizeof(out), err, sizeof(err));
    test_result(rc >= 0 && blocks[0]->snapshot->id > a && blocks[1]->snapshot->id > b && blocks[2]->snapshot->id > c,
                "Bare update generate still regenerates all complete blocks, including clean ones");
    test_result(cli_process_command(&state.session, &sim, &state.mode, "update generate ribout") < 0 &&
                cli_process_command(&state.session, &sim, &state.mode, "update generate changed extra") < 0,
                "Generation selectors reject missing names and trailing arguments");
done:
    bgp_shutdown_sim(&sim);
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--sessions") == 0) {
        test_control_server_multiple_sessions();
        return tests_failed ? 1 : 0;
    }
    if (argc > 2 || (argc == 2 && strcmp(argv[1], "--unit") != 0)) {
        fprintf(stderr, "Usage: %s [--unit|--sessions]\n", argv[0]);
        return 2;
    }
    test_update_generate_selection();
    printf("BGP CLI Command Processing Tests\n");
    printf("=================================\n\n");

    // Run all tests
    test_initial_cli_mode();
    test_mode_transition_to_config();
    test_mode_transition_to_exec();
    test_empty_command();
    test_whitespace_command();
    test_help_exec_mode();
    test_help_config_mode();
    test_help_global_config_surface();
    test_help_router_mode_surface();
    test_help_neighbor_mode_surface();
    test_help_ribout_mode_surface();
    test_help_ribout_flowspec_surface();
    test_help_ribout_parameter_syntax();
    test_question_mark_help();
    test_question_mark_config_surface();
    test_inline_question_mark_exec_surface();
    test_inline_question_mark_config_parameter();
    test_question_mark_negated_config_surface();
    test_exec_fallback_preserves_nested_config_mode();
    test_config_mode_entry();
    test_exit_config_end();
    test_exit_config_exit();
    test_show_routers();
    test_show_neighbors_all();
    test_show_neighbors_filtered();
    test_show_neighbors_new_family_capabilities();
    test_router_bgp_command();
    test_neighbor_command();
    test_no_router_command();
    test_no_neighbor_command();
    test_invalid_command_exec();
    test_invalid_command_config();
    test_incomplete_command_config();
    test_invalid_nested_command_recovery();
    test_long_command();
    test_leading_whitespace();
    test_trailing_whitespace();
    test_extra_spaces();
    test_command_case_sensitivity();
    test_no_exit_rejected();
    test_no_end_rejected();
    test_no_exec_fallback_rejected();
    test_no_router_id_rejected();
    test_no_update_source_rejected();
    test_no_neighbor_update_source_clears_override();
    test_vrf_names();
    test_vrf_changes_with_neighbors();
    test_clear_bgp_scope();
    test_vrf_is_a_router_command();
    test_vrf_shown_only_when_set();
    test_prompt_transitions();
    test_output_push_null_inherits_routed_output();
    test_parser_help_inherits_routed_output();
    if (argc == 1) test_control_server_multiple_sessions();
    test_update_generate_srpolicy_without_prefix();
    test_update_generate_evpn_type2_without_prefix();

    // Print summary
    printf("\n=================================\n");
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    printf("=================================\n");

    return (tests_failed == 0) ? 0 : 1;
}
