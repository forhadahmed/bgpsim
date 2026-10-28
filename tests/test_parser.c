#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "parser.h"
#include "commands.h"
#include "test_result.h"

/*
 * Test context
 */
typedef struct {
    int      handler_called;
    uint32_t as_number;
    char     ribout_name[64];
} test_ctx_t;

typedef struct {
    const char *keyword;
    int         is_parameter;
} completion_expectation_t;

typedef struct {
    const char                     *name;
    const char                     *input;
    const completion_expectation_t *expected;
    int                             expected_count;
} completion_case_t;

// Test helpers

static cmd_def_t production_parser_commands[256];
static int production_parser_commands_count = 0;

static int completion_contains_keyword(const completion_entry_t *entries, int count,
                                       const char *keyword, int is_parameter) {
    for (int i = 0; i < count; i++) {
        if (strcmp(entries[i].keyword, keyword) == 0 &&
            entries[i].is_parameter == is_parameter) {
            return 1;
        }
    }
    return 0;
}

static const completion_entry_t *completion_find_keyword(
    const completion_entry_t *entries, int count,
    const char *keyword, int is_parameter) {
    for (int i = 0; i < count; i++) {
        if (strcmp(entries[i].keyword, keyword) == 0 &&
            entries[i].is_parameter == is_parameter) {
            return &entries[i];
        }
    }

    return NULL;
}

static void print_completions(const completion_entry_t *entries, int count) {
    printf("Actual completions:");
    if (count == 0) {
        printf(" <none>");
    }

    for (int i = 0; i < count; i++) {
        printf(" %s%s", entries[i].keyword, entries[i].is_parameter ? "(param)" : "");
    }
    printf("\n");
}

static int test_noop_handler(void *ctx, match_result_t *result) {
    (void)ctx;
    (void)result;
    return 0;
}

static void init_production_parser_commands(void) {
    if (production_parser_commands_count > 0) {
        return;
    }

    for (int i = 0; i < cli_exec_commands_count && i < 256; i++) {
        production_parser_commands[i] = cli_exec_commands[i];
        production_parser_commands[i].handler = test_noop_handler;
        production_parser_commands_count++;
    }
}

static int completion_matches_exact(const completion_entry_t *entries, int count,
                                    const completion_expectation_t *expected,
                                    int expected_count) {
    if (count != expected_count) {
        return 0;
    }

    for (int i = 0; i < expected_count; i++) {
        if (!completion_contains_keyword(entries, count,
                                         expected[i].keyword,
                                         expected[i].is_parameter)) {
            return 0;
        }
    }

    return 1;
}

// Test Command Handlers

static int handle_show_bgp_summary(void *ctx, match_result_t *result) {
    (void)result;
    test_ctx_t *test_ctx = (test_ctx_t *)ctx;
    test_ctx->handler_called = 1;
    return 0;
}

static int handle_show_bgp_neighbors(void *ctx, match_result_t *result) {
    test_ctx_t *test_ctx = (test_ctx_t *)ctx;
    test_ctx->handler_called = 1;

    // Extract optional AS number
    if (result->token_count > 3) {
        test_ctx->as_number = result->tokens[3].uint_value;
    } else {
        test_ctx->as_number = 0;
    }
    return 0;
}

static int handle_router_bgp(void *ctx, match_result_t *result) {
    test_ctx_t *test_ctx = (test_ctx_t *)ctx;
    test_ctx->handler_called = 1;
    test_ctx->as_number = result->tokens[2].uint_value;
    return 0;
}

static int handle_show_ribout(void *ctx, match_result_t *result) {
    test_ctx_t *test_ctx = (test_ctx_t *)ctx;
    test_ctx->handler_called = 1;

    // Extract optional network name
    if (result->token_count > 2) {
        snprintf(test_ctx->ribout_name, sizeof(test_ctx->ribout_name), "%s", result->tokens[2].value);
    }
    return 0;
}

/*
 * Shared synthetic parser fixture.
 * Keep parser-core tests isolated from the full production CLI grammar,
 * but avoid re-declaring the same command tables in every test.
 */
static cmd_def_t parser_test_commands[] = {
    {
        "config",
        {
            {TOKEN_KEYWORD, "config", NULL, NULL, NULL},
            {TOKEN_END, NULL, NULL, NULL, NULL}
        },
        NULL,
        "Enter configuration mode",
        0
    },
    {
        "configure terminal",
        {
            {TOKEN_KEYWORD, "configure", NULL, NULL, NULL},
            {TOKEN_KEYWORD, "terminal", NULL, NULL, NULL},
            {TOKEN_END, NULL, NULL, NULL, NULL}
        },
        NULL,
        "Enter configuration mode",
        0
    },
    {
        "show log",
        {
            {TOKEN_KEYWORD, "show", NULL, NULL, NULL},
            {TOKEN_KEYWORD, "log", NULL, NULL, NULL},
            {TOKEN_OPTIONAL, NULL, NULL, NULL, NULL},
            {TOKEN_KEYWORD, "all", NULL, NULL, NULL},
            {TOKEN_END, NULL, NULL, NULL, NULL}
        },
        NULL,
        "Show log output",
        0
    },
    {
        "show bgp summary",
        {
            {TOKEN_KEYWORD, "show", NULL, NULL, NULL},
            {TOKEN_KEYWORD, "bgp", NULL, NULL, NULL},
            {TOKEN_KEYWORD, "summary", NULL, NULL, NULL},
            {TOKEN_END, NULL, NULL, NULL, NULL}
        },
        handle_show_bgp_summary,
        "Show BGP summary",
        0
    },
    {
        "show bgp neighbors <AS>",
        {
            {TOKEN_KEYWORD, "show", NULL, NULL, NULL},
            {TOKEN_KEYWORD, "bgp", NULL, NULL, NULL},
            {TOKEN_KEYWORD, "neighbors", NULL, NULL, NULL},
            {TOKEN_OPTIONAL, NULL, NULL, NULL, NULL},
            {TOKEN_UINT32, NULL, "AS", "AS", "AS number (1-4294967295)"},
            {TOKEN_END, NULL, NULL, NULL, NULL}
        },
        handle_show_bgp_neighbors,
        "Show BGP neighbors for AS",
        0
    },
    {
        "show ribout <name> [preview <count>]",
        {
            {TOKEN_KEYWORD, "show", NULL, NULL, NULL},
            {TOKEN_KEYWORD, "ribout", NULL, NULL, NULL},
            {TOKEN_OPTIONAL, NULL, NULL, NULL, NULL},
            {TOKEN_STRING, NULL, "name", "name", "ribout name"},
            {TOKEN_OPTIONAL, NULL, NULL, NULL, NULL},
            {TOKEN_KEYWORD, "preview", NULL, NULL, NULL},
            {TOKEN_OPTIONAL, NULL, NULL, NULL, NULL},
            {TOKEN_UINT32, NULL, "count", "count", "Preview route count"},
            {TOKEN_END, NULL, NULL, NULL, NULL}
        },
        handle_show_ribout,
        "Show generated ribout data",
        0
    },
    {
        "router bgp <AS>",
        {
            {TOKEN_KEYWORD, "router", NULL, NULL, NULL},
            {TOKEN_KEYWORD, "bgp", NULL, NULL, NULL},
            {TOKEN_UINT32, NULL, "AS", "AS", "AS number (1-4294967295)"},
            {TOKEN_END, NULL, NULL, NULL, NULL}
        },
        handle_router_bgp,
        "Configure BGP router",
        0
    },
    {
        "capability graceful-restart [restart-time <time>]",
        {
            {TOKEN_KEYWORD, "capability", NULL, NULL, NULL},
            {TOKEN_KEYWORD, "graceful-restart", NULL, NULL, NULL},
            {TOKEN_OPTIONAL, NULL, NULL, NULL, NULL},
            {TOKEN_KEYWORD, "restart-time", NULL, NULL, NULL},
            {TOKEN_UINT32, NULL, "restart-time", "time", "Restart time in seconds"},
            {TOKEN_END, NULL, NULL, NULL, NULL}
        },
        NULL,
        "Enable graceful restart capability",
        0
    },
    {
        "show summary",
        {
            {TOKEN_KEYWORD, "show", NULL, NULL, NULL},
            {TOKEN_KEYWORD, "summary", NULL, NULL, NULL},
            {TOKEN_END, NULL, NULL, NULL, NULL}
        },
        handle_show_bgp_summary,
        "Show summary",
        0
    },
    {
        "show status",
        {
            {TOKEN_KEYWORD, "show", NULL, NULL, NULL},
            {TOKEN_KEYWORD, "status", NULL, NULL, NULL},
            {TOKEN_END, NULL, NULL, NULL, NULL}
        },
        handle_show_bgp_summary,
        "Show status",
        0
    }
};

// Test Suites

void test_exact_keyword_matching() {
    printf("\n=== Exact Keyword Matching ===\n");

    test_ctx_t   ctx = {0};
    parser_ctx_t parser;
    parser_init(&parser, parser_test_commands,
                (int)(sizeof(parser_test_commands) / sizeof(parser_test_commands[0])), &ctx);

    // Test exact match
    ctx.handler_called = 0;
    int result = parser_execute(&parser, "show bgp summary");
    test_result(result == 0 && ctx.handler_called == 1, "Exact match 'show bgp summary'");

    ctx.handler_called = 0;
    result = parser_execute(&parser, "show bgp neighbors");
    test_result(result == 0 && ctx.handler_called == 1, "Exact match 'show bgp neighbors'");
}

void test_partial_keyword_matching() {
    printf("\n=== Partial Keyword Matching ===\n");

    test_ctx_t   ctx = {0};
    parser_ctx_t parser;
    parser_init(&parser, parser_test_commands,
                (int)(sizeof(parser_test_commands) / sizeof(parser_test_commands[0])), &ctx);

    // Test partial matches
    ctx.handler_called = 0;
    int result = parser_execute(&parser, "sh bgp sum");
    test_result(result == 0 && ctx.handler_called == 1, "Partial match 'sh bgp sum'");

    ctx.handler_called = 0;
    result = parser_execute(&parser, "sho b nei");
    test_result(result == 0 && ctx.handler_called == 1, "Partial match 'sho b nei'");

    ctx.handler_called = 0;
    result = parser_execute(&parser, "s b n");
    test_result(result == 0 && ctx.handler_called == 1, "Partial match 's b n'");
}

void test_ambiguous_commands() {
    printf("\n=== Ambiguous Command Detection ===\n");

    test_ctx_t   ctx = {0};
    parser_ctx_t parser;
    parser_init(&parser, parser_test_commands,
                (int)(sizeof(parser_test_commands) / sizeof(parser_test_commands[0])), &ctx);

    // Test ambiguous partial - "show s" matches both "summary" and "status"
    ctx.handler_called = 0;
    int result = parser_execute(&parser, "show s");
    test_result(result == PARSER_AMBIGUOUS && ctx.handler_called == 0, "Reject ambiguous 'show s'");

    // Test unambiguous partials
    ctx.handler_called = 0;
    result = parser_execute(&parser, "show su");
    test_result(result == 0 && ctx.handler_called == 1, "Accept unambiguous 'show su' (summary)");

    ctx.handler_called = 0;
    result = parser_execute(&parser, "show st");
    test_result(result == 0 && ctx.handler_called == 1, "Accept unambiguous 'show st' (status)");
}

void test_numeric_parameters() {
    printf("\n=== Numeric Parameter Parsing ===\n");

    test_ctx_t   ctx = {0};
    parser_ctx_t parser;
    parser_init(&parser, parser_test_commands,
                (int)(sizeof(parser_test_commands) / sizeof(parser_test_commands[0])), &ctx);

    // Test with numeric parameter
    ctx.handler_called = 0;
    ctx.as_number = 0;
    int result = parser_execute(&parser, "router bgp 65001");
    test_result(result == 0 && ctx.handler_called == 1 && ctx.as_number == 65001, "Parse 'router bgp 65001'");

    // Test partial match with numeric
    ctx.handler_called = 0;
    ctx.as_number = 0;
    result = parser_execute(&parser, "rout b 65002");
    test_result(result == 0 && ctx.handler_called == 1 && ctx.as_number == 65002, "Partial match 'rout b 65002'");

    // Test optional numeric parameter
    ctx.handler_called = 0;
    ctx.as_number = 999;  /* Non-zero to detect if it's cleared */
    result = parser_execute(&parser, "show bgp neighbors");
    test_result(result == 0 && ctx.handler_called == 1 && ctx.as_number == 0, "Optional parameter omitted");

    ctx.handler_called = 0;
    ctx.as_number = 0;
    result = parser_execute(&parser, "show bgp neighbors 65003");
    test_result(result == 0 && ctx.handler_called == 1 && ctx.as_number == 65003, "Optional parameter provided");
}

void test_string_parameters() {
    printf("\n=== String Parameter Parsing ===\n");

    test_ctx_t   ctx = {0};
    parser_ctx_t parser;
    parser_init(&parser, parser_test_commands,
                (int)(sizeof(parser_test_commands) / sizeof(parser_test_commands[0])), &ctx);

    // Test with string parameter
    ctx.handler_called = 0;
    memset(ctx.ribout_name, 0, sizeof(ctx.ribout_name));
    int result = parser_execute(&parser, "show ribout mynetwork");
    test_result(result == 0 && ctx.handler_called == 1 &&
                strcmp(ctx.ribout_name, "mynetwork") == 0,
                "Parse 'show ribout mynetwork'");

    // Test without optional string parameter
    ctx.handler_called = 0;
    memset(ctx.ribout_name, 0, sizeof(ctx.ribout_name));
    result = parser_execute(&parser, "show ribout");
    test_result(result == 0 && ctx.handler_called == 1, "Optional string parameter omitted");
}

/*
 * The tail the last "set <tail>" command was given, for the long-token checks.
 */
static char captured_tail[MAX_TAIL_LEN];

static int handle_capture_tail(void *ctx, match_result_t *result) {
    ((test_ctx_t *)ctx)->handler_called = 1;
    snprintf(captured_tail, sizeof(captured_tail), "%s", result->tail);
    return 0;
}

static void test_input_capacity(void) {
    test_ctx_t         ctx = {0};
    parser_ctx_t       parser;
    completion_entry_t entries[4];
    char name[MAX_TOKEN_LEN + 1], line[1200];
    parser_init(&parser, parser_test_commands,
                (int)(sizeof(parser_test_commands) / sizeof(parser_test_commands[0])), &ctx);
    memset(name, 'a', MAX_TOKEN_LEN - 1);
    name[MAX_TOKEN_LEN - 1] = '\0';
    snprintf(line, sizeof(line), "show ribout %s", name);
    test_result(parser_execute(&parser, line) == 0 && ctx.handler_called,
                "Accept maximum-length token without truncation");
    ctx.handler_called = 0;
    snprintf(line, sizeof(line), "show ribout %sx", name);
    test_result(parser_execute(&parser, line) == PARSER_NO_MATCH && !ctx.handler_called,
                "Reject oversized token without invoking its handler");
    test_result(parser_find_matches(&parser, line, entries, 4) == 0, "Do not offer completions for a truncated token");
    memset(line, ' ', sizeof(line) - 1);
    memcpy(line, "show bgp summary", strlen("show bgp summary"));
    line[sizeof(line) - 1] = '\0';
    test_result(parser_execute(&parser, line) == PARSER_NO_MATCH && !ctx.handler_called,
                "Reject oversized line rather than executing its prefix");
    cmd_def_t tail_command = {
        "test <tail>", {{TOKEN_KEYWORD, "test"}, {TOKEN_TAIL, NULL, "tail"}, {TOKEN_END}},
        handle_show_bgp_summary, "Token count boundary", 0
    };
    parser_init(&parser, &tail_command, 1, &ctx);
    strcpy(line, "test");
    for (int i = 1; i < MAX_TOKENS; i++) strcat(line, " x");
    test_result(parser_execute(&parser, line) == 0 && ctx.handler_called, "Accept maximum token count");
    ctx.handler_called = 0;
    strcat(line, " x");
    test_result(parser_execute(&parser, line) == PARSER_NO_MATCH && !ctx.handler_called,
                "Reject excess tokens rather than executing a partial tail");

    // A free-form tail takes tokens of any length (a bracketed set of 16 values); values and keywords do not.
    cmd_def_t capture_command = {
        "set <tail>", {{TOKEN_KEYWORD, "set"}, {TOKEN_TAIL, NULL, "tail"}, {TOKEN_END}},
        handle_capture_tail, "Long tail tokens", 0
    };
    char set[960], expected[1000];
    int len = snprintf(set, sizeof(set), "[");
    for (int i = 0; i < 16; i++) {
        len += snprintf(set + len, sizeof(set) - (size_t)len, "%s4294967295:4294967295:%d", i ? "," : "", i);
    }
    snprintf(set + len, sizeof(set) - (size_t)len, "]");
    parser_init(&parser, &capture_command, 1, &ctx);
    ctx.handler_called = 0;
    snprintf(line, sizeof(line), "set   %s  x 3", set);
    snprintf(expected, sizeof(expected), "%s x 3", set);
    test_result(strlen(set) > 300 && parser_execute(&parser, line) == 0 && ctx.handler_called &&
                    strcmp(captured_tail, expected) == 0,
                "A tail takes a token of more than 300 octets intact");
    snprintf(line, sizeof(line), "set %.40s", set);
    test_result(parser_find_matches(&parser, line, entries, 4) == 1, "Complete a long tail token with its hint");
    snprintf(line, sizeof(line), "s%s", set);
    test_result(parser_execute(&parser, line) == PARSER_NO_MATCH, "A long token is no keyword");
    parser_init(&parser, parser_test_commands,
                (int)(sizeof(parser_test_commands) / sizeof(parser_test_commands[0])), &ctx);
    ctx.handler_called = 0;
    snprintf(line, sizeof(line), "show ribout %s", set);
    test_result(parser_execute(&parser, line) == PARSER_NO_MATCH && !ctx.handler_called,
                "A string parameter still refuses a token longer than it holds");
}

void test_invalid_commands() {
    printf("\n=== Invalid Command Handling ===\n");

    test_ctx_t   ctx = {0};
    parser_ctx_t parser;
    parser_init(&parser, parser_test_commands,
                (int)(sizeof(parser_test_commands) / sizeof(parser_test_commands[0])), &ctx);

    // Test completely wrong command
    ctx.handler_called = 0;
    int result = parser_execute(&parser, "invalid command");
    test_result(result == PARSER_NO_MATCH && ctx.handler_called == 0, "Reject invalid command");

    // Test incomplete command
    ctx.handler_called = 0;
    result = parser_execute(&parser, "show bgp");
    test_result(result == PARSER_INCOMPLETE && ctx.handler_called == 0, "Classify incomplete 'show bgp'");

    // Test extra parameters
    ctx.handler_called = 0;
    result = parser_execute(&parser, "show bgp summary extra");
    test_result(result == PARSER_NO_MATCH && ctx.handler_called == 0, "Reject extra parameters");
}

void test_partial_matching_unit() {
    printf("\n=== Unit Tests for parser_match_keyword ===\n");

    // Exact matches
    test_result(parser_match_keyword("show", "show") == 1, "Exact match 'show'");
    test_result(parser_match_keyword("bgp", "bgp") == 1, "Exact match 'bgp'");

    // Partial matches
    test_result(parser_match_keyword("sh", "show") == 1, "Partial match 'sh' -> 'show'");
    test_result(parser_match_keyword("sho", "show") == 1, "Partial match 'sho' -> 'show'");
    test_result(parser_match_keyword("n", "neighbors") == 1, "Partial match 'n' -> 'neighbors'");
    test_result(parser_match_keyword("neigh", "neighbors") == 1, "Partial match 'neigh' -> 'neighbors'");

    // Non-matches
    test_result(parser_match_keyword("shw", "show") == 0, "No match 'shw' vs 'show'");
    test_result(parser_match_keyword("x", "show") == 0, "No match 'x' vs 'show'");
    test_result(parser_match_keyword("summary", "show") == 0, "No match 'summary' vs 'show'");

    // Case sensitivity
    test_result(parser_match_keyword("Show", "show") == 0, "Case sensitive 'Show' vs 'show'");
}

void test_completion_matching() {
    printf("\n=== Completion Matching ===\n");

    parser_ctx_t parser;
    static const completion_expectation_t conf_expected[] = {
        {"config", 0},
        {"configure", 0},
    };
    static const completion_expectation_t configure_expected[] = {
        {"terminal", 0},
    };
    static const completion_expectation_t show_log_expected[] = {
        {"<cr>", 1},
        {"all", 0},
    };
    static const completion_expectation_t show_neighbors_expected[] = {
        {"<cr>", 1},
        {"<AS>", 1},
    };
    static const completion_expectation_t show_ribout_expected[] = {
        {"<cr>", 1},
        {"<name>", 1},
    };
    static const completion_expectation_t router_bgp_expected[] = {
        {"<AS>", 1},
    };
    static const completion_expectation_t graceful_restart_expected[] = {
        {"<cr>", 1},
        {"restart-time", 0},
    };
    static const completion_case_t completion_cases[] = {
        {
            "Completion returns both 'config' and 'configure' for 'conf'",
            "conf",
            conf_expected,
            (int)(sizeof(conf_expected) / sizeof(conf_expected[0]))
        },
        {
            "Completion narrows to 'terminal' after 'configure '",
            "configure ",
            configure_expected,
            (int)(sizeof(configure_expected) / sizeof(configure_expected[0]))
        },
        {
            "Optional tail offers both '<cr>' and 'all'",
            "show log ",
            show_log_expected,
            (int)(sizeof(show_log_expected) / sizeof(show_log_expected[0]))
        },
        {
            "Optional parameter completion offers '<cr>' and '<AS>'",
            "show bgp neighbors ",
            show_neighbors_expected,
            (int)(sizeof(show_neighbors_expected) / sizeof(show_neighbors_expected[0]))
        },
        {
            "Optional show ribout argument offers '<cr>' and '<name>'",
            "show ribout ",
            show_ribout_expected,
            (int)(sizeof(show_ribout_expected) / sizeof(show_ribout_expected[0]))
        },
        {
            "Parameter completion shows '<AS>' placeholder",
            "router bgp ",
            router_bgp_expected,
            (int)(sizeof(router_bgp_expected) / sizeof(router_bgp_expected[0]))
        },
        {
            "Optional keyword tail offers '<cr>' and 'restart-time'",
            "capability graceful-restart ",
            graceful_restart_expected,
            (int)(sizeof(graceful_restart_expected) / sizeof(graceful_restart_expected[0]))
        },
        {
            "Unknown prefix returns no completions",
            "xyz",
            NULL,
            0
        },
        {
            "Completion matching remains case-sensitive",
            "Conf",
            NULL,
            0
        }
    };
    completion_entry_t entries[16];

    parser_init(&parser, parser_test_commands,
                (int)(sizeof(parser_test_commands) / sizeof(parser_test_commands[0])), NULL);

    for (size_t i = 0; i < sizeof(completion_cases) / sizeof(completion_cases[0]); i++) {
        int count = parser_find_matches(&parser, completion_cases[i].input, entries, 16);
        int passed = completion_matches_exact(entries, count,
                                              completion_cases[i].expected,
                                              completion_cases[i].expected_count);

        if (!passed) {
            printf("Input: '%s'\n", completion_cases[i].input);
            print_completions(entries, count);
        }

        test_result(passed, completion_cases[i].name);
    }

    {
        int                       count = parser_find_matches(&parser, "", entries, 16);
        const completion_entry_t *show_entry = completion_find_keyword(entries, count, "show", 0);
        const completion_entry_t *router_entry = completion_find_keyword(entries, count, "router", 0);
        int                       show_help_ok = show_entry && strcmp(show_entry->help_text, "show commands") == 0;
        int                       router_help_ok = router_entry && strcmp(router_entry->help_text, "Configure BGP router") == 0;
        int                       router_count = parser_find_matches(&parser, "router bgp ", entries, 16);
        const completion_entry_t *router_as_entry = completion_find_keyword(entries, router_count, "<AS>", 1);
        int router_as_help_ok =
            router_as_entry && strcmp(router_as_entry->help_text, "AS number (1-4294967295)") == 0;
        int ribout_count =
            parser_find_matches(&parser, "show ribout demo preview ", entries, 16);
        const completion_entry_t *preview_count_entry = completion_find_keyword(entries, ribout_count, "<count>", 1);
        int preview_help_ok =
            preview_count_entry && strcmp(preview_count_entry->help_text, "Preview route count") == 0;

        test_result(show_help_ok, "Shared root keyword uses generic completion help");

        test_result(router_help_ok, "Unique root keyword keeps specific completion help");

        test_result(router_as_help_ok, "Leaf parameter uses token-level help text");

        test_result(preview_help_ok, "Leaf parameter help is specific to the value token");
    }
}

void test_production_cli_surface(void) {
    printf("\n=== Production CLI Surface ===\n");

    parser_ctx_t parser;
    int          result;

    init_production_parser_commands();
    parser_init(&parser, production_parser_commands, production_parser_commands_count, NULL);

    result = parser_execute(&parser, "show bgp summary");
    test_result(result == 0, "Production parse 'show bgp summary'");

    result = parser_execute(&parser, "show bgp neighbors");
    test_result(result == 0, "Production parse 'show bgp neighbors'");

    result = parser_execute(&parser, "show running-config");
    test_result(result == 0, "Production parse 'show running-config'");

    result = parser_execute(&parser, "shutdown");
    test_result(result == 0, "Production parse 'shutdown'");

    result = parser_execute(&parser, "sh b sum");
    test_result(result == 0, "Production partial 'sh b sum' -> 'show bgp summary'");

    result = parser_execute(&parser, "sho bgp nei");
    test_result(result == 0, "Production partial 'sho bgp nei' -> 'show bgp neighbors'");

    result = parser_execute(&parser, "show b n");
    test_result(result == 0, "Production partial 'show b n' -> 'show bgp neighbors'");

    result = parser_execute(&parser, "conf");
    test_result(result == 0, "Production partial 'conf' -> 'config'");

    result = parser_execute(&parser, "configure t");
    test_result(result == 0, "Production partial 'configure t' -> 'configure terminal'");

    result = parser_execute(&parser, "shut");
    test_result(result == 0, "Production partial 'shut' -> 'shutdown'");

    result = parser_execute(&parser, "show bgp neighbors 65001");
    test_result(result == 0, "Production parse 'show bgp neighbors 65001'");

    result = parser_execute(&parser, "sh b n 65002");
    test_result(result == 0, "Production partial 'sh b n 65002'");

    result = parser_execute(&parser, "show log");
    test_result(result == 0, "Production parse 'show log'");

    result = parser_execute(&parser, "show log all");
    test_result(result == 0, "Production parse 'show log all'");

    result = parser_execute(&parser, "sh l a");
    test_result(result == 0, "Production partial 'sh l a' -> 'show log all'");

    result = parser_execute(&parser, "show l");
    test_result(result == 0, "Production parse 'show l' -> 'show log'");

    result = parser_execute(&parser, "co");
    test_result(result == 0, "Production parse 'co' -> 'config'");

    result = parser_execute(&parser, "confi");
    test_result(result == 0, "Production parse 'confi' -> 'config'");
}

// Main Test Runner

int main(void) {
    printf("Parser Tests\n");
    printf("===============================================\n");

    test_partial_matching_unit();
    test_completion_matching();
    test_exact_keyword_matching();
    test_partial_keyword_matching();
    test_ambiguous_commands();
    test_numeric_parameters();
    test_string_parameters();
    test_input_capacity();
    test_invalid_commands();
    test_production_cli_surface();

    printf("\n===============================================\n");
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    printf("===============================================\n");

    return (tests_failed == 0) ? 0 : 1;
}
