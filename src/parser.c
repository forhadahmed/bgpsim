#define OUTPUT_STDIO_REMAP

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "util.h"
#include "output.h"
#include "parser.h"
#include "commands.h"

/*
 * Shared completion callback state
 */
static cli_mode_t *current_mode = NULL;
static config_mode_t current_config_mode = CONFIG_MODE_GLOBAL;

// Helper Functions

/*
 * Split line into tokens: pointers into buf (BGPSIM_COMMAND_SIZE octets), a copy of the line with each token
 * NUL-terminated. A token can be as long as the line, but only a command's free-form tail (TOKEN_TAIL) takes one of
 * MAX_TOKEN_LEN or more (match_token() refuses it as a keyword or value), so a long bracketed set such as
 * "[65000:1,...,65000:16]" can be entered.
 */
static int tokenize(const char *line, char *buf, char *tokens[], int max_tokens) {
    // Reject oversized input rather than executing a different, truncated command.
    if (!line || !command_input_valid(line, strlen(line))) return -1;
    strncpy(buf, line, BGPSIM_COMMAND_SIZE - 1);
    buf[BGPSIM_COMMAND_SIZE - 1] = '\0';

    char *ptr = str_trim(buf);
    int   count = 0;

    while (*ptr) {
        // Skip whitespace
        while (*ptr && isspace((unsigned char)*ptr)) ptr++;
        if (!*ptr) break;
        if (count == max_tokens) return -1;

        // Extract token
        tokens[count++] = ptr;
        while (*ptr && !isspace((unsigned char)*ptr)) ptr++;
        if (*ptr) *ptr++ = '\0';
    }

    return count;
}

// Token Matching

/*
 * Match a partial keyword
 * Returns: 1 if prefix uniquely matches keyword, 0 otherwise
 */
static int parser_keyword_match_type(const char *prefix, const char *keyword) {
    size_t prefix_len = strlen(prefix);
    size_t keyword_len = strlen(keyword);

    if (strcmp(prefix, keyword) == 0) {
        return 2;
    }

    if (prefix_len < keyword_len && strncmp(prefix, keyword, prefix_len) == 0) {
        return 1;
    }

    return 0;
}

int parser_match_keyword(const char *prefix, const char *keyword) {
    return parser_keyword_match_type(prefix, keyword) != 0;
}

/*
 * Try to match a token against a token definition
 */
static int match_token(const char *input_token, token_def_t *def, parsed_token_t *result) {
    result->type = def->type;
    result->param_name = def->param_name;
    result->uint_value = 0;

    // A keyword or value never takes a token longer than its parsed form holds: no truncation.
    if (strlen(input_token) >= MAX_TOKEN_LEN) {
        return 0;
    }

    switch (def->type) {
        case TOKEN_KEYWORD: {
            int match_type = parser_keyword_match_type(input_token, def->keyword);

            // Simple match - don't check ambiguity here, do it at command level
            if (match_type != 0) {
                strncpy(result->value, def->keyword, MAX_TOKEN_LEN - 1);
                result->value[MAX_TOKEN_LEN - 1] = '\0';
                result->uint_value = (uint32_t)match_type;
                return 1;
            }
            return 0;
        }

        case TOKEN_UINT32: {
            uint32_t val;
            if (is_uint32(input_token, &val)) {
                result->uint_value = val;
                strncpy(result->value, input_token, MAX_TOKEN_LEN - 1);
                result->value[MAX_TOKEN_LEN - 1] = '\0';
                return 1;
            }
            return 0;
        }

        case TOKEN_IP_ADDRESS: {
            if (is_ip_address(input_token)) {
                strncpy(result->value, input_token, MAX_TOKEN_LEN - 1);
                result->value[MAX_TOKEN_LEN - 1] = '\0';
                return 1;
            }
            return 0;
        }

        case TOKEN_STRING: {
            // Accept any string
            strncpy(result->value, input_token, MAX_TOKEN_LEN - 1);
            result->value[MAX_TOKEN_LEN - 1] = '\0';
            return 1;
        }

        default:
            return 0;
    }
}

typedef enum {
    CMD_MATCH_NONE       = 0,
    CMD_MATCH_INCOMPLETE = 1,
    CMD_MATCH_FULL       = 2
} cmd_match_state_t;

/*
 * Try to match input tokens against a command definition
 */
static cmd_match_state_t match_command(char *const input_tokens[],
                                       int input_count,
                                       cmd_def_t *cmd,
                                       match_result_t *result,
                                       int negated) {
    result->token_count = 0;
    result->tail[0] = '\0';
    memset(result->keyword_rank, 0, sizeof(result->keyword_rank));

    int def_index = 0;
    int input_index = 0;
    int in_optional_section = 0;

    // Match each token
    while (def_index < MAX_TOKENS && cmd->tokens[def_index].type != TOKEN_END) {
        token_def_t *def = &cmd->tokens[def_index];

        // Mark when we enter optional section
        if (def->type == TOKEN_OPTIONAL) {
            in_optional_section = 1;
            def_index++;
            continue;
        }

        // TOKEN_TAIL: capture all remaining input as a single string
        if (def->type == TOKEN_TAIL) {
            if (input_index >= input_count) {
                if (negated && cmd->supports_no) {
                    break;
                }
                return in_optional_section ? CMD_MATCH_FULL
                                           : CMD_MATCH_INCOMPLETE;
            }

            result->tail[0] = '\0';
            for (int i = input_index; i < input_count; i++) {
                if (i > input_index) {
                    strncat(result->tail, " ", MAX_TAIL_LEN - strlen(result->tail) - 1);
                }
                strncat(result->tail, input_tokens[i], MAX_TAIL_LEN - strlen(result->tail) - 1);
            }
            input_index = input_count;  /* All consumed */
            break;
        }

        // Check if we're out of input tokens
        if (input_index >= input_count) {
            if (in_optional_section) {
                break;  /* All input consumed, remaining defs optional */
            }
            return CMD_MATCH_INCOMPLETE;
        }

        // Try to match current token
        parsed_token_t parsed;
        int            match_res = match_token(input_tokens[input_index], def, &parsed);

        if (match_res == 0) {
            if (in_optional_section) {
                break;  /* Fall through to extra-parameters check */
            }
            // Required token didn't match
            return CMD_MATCH_NONE;
        }

        // Token matched
        int pos = result->token_count;
        result->tokens[pos] = parsed;
        if (parsed.type == TOKEN_KEYWORD) {
            result->keyword_rank[pos] = (int)parsed.uint_value;
        }
        result->token_count++;
        input_index++;
        def_index++;
    }

    // Check if there are extra input tokens
    if (input_index < input_count) {
        return CMD_MATCH_NONE;
    }

    return CMD_MATCH_FULL;
}

// Parser API Implementation

void parser_init(parser_ctx_t *ctx, cmd_def_t *commands, int command_count, void *user_ctx) {
    ctx->commands = commands;
    ctx->command_count = command_count;
    ctx->user_ctx = user_ctx;
    ctx->negated = 0;
}

/*
 * Compare two keyword rank arrays lexicographically.
 * Returns: >0 if a wins, <0 if b wins, 0 if equal.
 */
static int compare_keyword_rank(const int *a, const int *b, int count) {
    for (int i = 0; i < count; i++) {
        if (a[i] != b[i]) return a[i] - b[i];
    }
    return 0;
}

int parser_execute(parser_ctx_t *ctx, const char *line) {
    char           buf[BGPSIM_COMMAND_SIZE];
    char          *input_tokens[MAX_TOKENS];
    int            input_count;
    match_result_t result;
    match_result_t best_result;

    // Tokenize input
    input_count = tokenize(line, buf, input_tokens, MAX_TOKENS);
    if (input_count < 0) return PARSER_NO_MATCH;
    if (input_count == 0) {
        return 1;  /* Empty line */
    }

    // Try to match against each command
    cmd_def_t *matched_cmd = NULL;
    int        best_match_count = 0;
    int        saw_incomplete = 0;

    for (int i = 0; i < ctx->command_count; i++) {
        cmd_match_state_t match_state =
            match_command(input_tokens, input_count, &ctx->commands[i], &result, ctx->negated);

        if (match_state == CMD_MATCH_INCOMPLETE) {
            saw_incomplete = 1;
            continue;
        }

        if (match_state == CMD_MATCH_FULL) {
            int cmp = best_match_count == 0 ? 1 :
                      compare_keyword_rank(result.keyword_rank, best_result.keyword_rank, result.token_count);
            if (cmp > 0) {
                matched_cmd = &ctx->commands[i];
                best_result = result;
                best_match_count = 1;
            } else if (cmp == 0) {
                best_match_count++;
            }
        }
    }

    // Handle match results
    if (best_match_count == 0) {
        if (saw_incomplete) {
            return PARSER_INCOMPLETE;
        }
        // Don't print error here - let caller decide what to print
        return PARSER_NO_MATCH;
    }

    if (best_match_count > 1) {
        return PARSER_AMBIGUOUS;
    }

    // Reject "no <command>" when the command doesn't support negation
    if (ctx->negated && !matched_cmd->supports_no) {
        return PARSER_UNSUPPORTED_NEGATION;
    }

    // Execute matched command
    if (matched_cmd->handler) {
        return matched_cmd->handler(ctx->user_ctx, &best_result);
    }

    return 0;
}

static completion_entry_t *completion_find(completion_entry_t *entries,
                                           int count,
                                           const char *keyword,
                                           int is_parameter) {
    for (int i = 0; i < count; i++) {
        if (entries[i].is_parameter == is_parameter &&
            strcmp(entries[i].keyword, keyword) == 0) {
            return &entries[i];
        }
    }

    return NULL;
}

static void completion_set_group_help(completion_entry_t *entry) {
    if (!entry || entry->is_parameter) {
        return;
    }

    snprintf(entry->generated_help, sizeof(entry->generated_help), "%s commands", entry->keyword);
    entry->help_text = entry->generated_help;
}

static void completion_add(completion_entry_t *entries, int *count,
                           int max_entries, const char *keyword,
                           const char *help_text, int is_parameter,
                           int root_keyword_group) {
    completion_entry_t *existing = completion_find(entries, *count, keyword, is_parameter);

    if (existing) {
        if (root_keyword_group) {
            completion_set_group_help(existing);
        }
        return;
    }

    if (*count >= max_entries) {
        return;
    }

    strncpy(entries[*count].keyword, keyword, MAX_TOKEN_LEN - 1);
    entries[*count].keyword[MAX_TOKEN_LEN - 1] = '\0';
    entries[*count].help_text = help_text;
    entries[*count].generated_help[0] = '\0';
    entries[*count].is_parameter = is_parameter;
    (*count)++;
}

static int parser_help_name_width(const cmd_def_t *commands, int command_count) {
    int width = 0;

    if (!commands) {
        return 0;
    }

    for (int i = 0; i < command_count; i++) {
        int candidate = help_label_width(commands[i].name);
        if (candidate > width) {
            width = candidate;
        }
    }

    return width;
}

static const char *parser_completion_display_name(const token_def_t *def, const char *fallback) {
    if (def->display_name && def->display_name[0] != '\0') {
        return def->display_name;
    }
    if (def->param_name && def->param_name[0] != '\0') {
        return def->param_name;
    }
    return fallback;
}

static const char *parser_completion_value_help(const token_def_t *def, const cmd_def_t *cmd) {
    if (def->value_help && def->value_help[0] != '\0') {
        return def->value_help;
    }

    switch (def->type) {
        case TOKEN_UINT32:
            return "Unsigned integer value";
        case TOKEN_IP_ADDRESS:
            return "IPv4 or IPv6 address";
        case TOKEN_STRING:
            return "Value";
        case TOKEN_TAIL:
            return cmd->help_text;
        default:
            return cmd->help_text;
    }
}

int parser_find_matches(parser_ctx_t *ctx, const char *line, completion_entry_t *entries, int max_entries) {
    char  buf[BGPSIM_COMMAND_SIZE];
    char *input_tokens[MAX_TOKENS];
    int   input_count = tokenize(line, buf, input_tokens, MAX_TOKENS);
    if (input_count < 0) return 0;
    int entry_count = 0;
    int best_prefix_rank[MAX_TOKENS];
    int have_best = 0;
    int candidate_matched[256];

    memset(best_prefix_rank, 0, sizeof(best_prefix_rank));

    // Determine if completing the last token or starting a new one
    size_t      line_len = strlen(line);
    int         completing_last = (line_len > 0 && !isspace((unsigned char)line[line_len - 1]) && input_count > 0);
    int         complete_pos   = completing_last ? input_count - 1 : input_count;
    const char *partial = completing_last ? input_tokens[complete_pos] : "";

    if (ctx->command_count > (int)(sizeof(candidate_matched) /
                                   sizeof(candidate_matched[0]))) {
        return 0;
    }

    // Per-candidate prefix rank arrays
    int prefix_ranks[256][MAX_TOKENS];

    for (int i = 0; i < ctx->command_count; i++) {
        candidate_matched[i] = 0;
        memset(prefix_ranks[i], 0, sizeof(prefix_ranks[i]));
    }

    for (int cmd_idx = 0; cmd_idx < ctx->command_count; cmd_idx++) {
        cmd_def_t *cmd = &ctx->commands[cmd_idx];
        int        def_idx = 0;
        int        matched = 1;

        if (ctx->negated && !cmd->supports_no) {
            continue;
        }

        // Match prefix tokens [0 .. complete_pos) against definitions
        for (int i = 0; i < complete_pos && matched; i++) {
            // Skip TOKEN_OPTIONAL markers
            while (def_idx < MAX_TOKENS &&
                   cmd->tokens[def_idx].type == TOKEN_OPTIONAL) {
                def_idx++;
            }

            if (def_idx >= MAX_TOKENS ||
                cmd->tokens[def_idx].type == TOKEN_END) {
                matched = 0;
                break;
            }

            // TOKEN_TAIL absorbs all remaining prefix tokens
            if (cmd->tokens[def_idx].type == TOKEN_TAIL) {
                break;
            }

            parsed_token_t tmp;
            if (!match_token(input_tokens[i], &cmd->tokens[def_idx], &tmp))
                matched = 0;
            else if (tmp.type == TOKEN_KEYWORD)
                prefix_ranks[cmd_idx][i] = (int)tmp.uint_value;
            def_idx++;
        }

        if (!matched) continue;

        candidate_matched[cmd_idx] = 1;
        int cmp = have_best ? compare_keyword_rank(prefix_ranks[cmd_idx], best_prefix_rank, complete_pos) : 1;
        if (cmp > 0) {
            memcpy(best_prefix_rank, prefix_ranks[cmd_idx], sizeof(best_prefix_rank));
            have_best = 1;
        }
    }

    if (!have_best) {
        return 0;
    }

    for (int cmd_idx = 0; cmd_idx < ctx->command_count; cmd_idx++) {
        cmd_def_t *cmd = &ctx->commands[cmd_idx];
        int        optional_tail = 0;
        int        def_idx = 0;

        if (!candidate_matched[cmd_idx] ||
            compare_keyword_rank(prefix_ranks[cmd_idx], best_prefix_rank,
                                 complete_pos) != 0) {
            continue;
        }

        // Advance past TOKEN_OPTIONAL at the completion position
        for (int i = 0; i < complete_pos; i++) {
            while (def_idx < MAX_TOKENS &&
                   cmd->tokens[def_idx].type == TOKEN_OPTIONAL) {
                optional_tail = 1;
                def_idx++;
            }
            def_idx++;
        }

        while (def_idx < MAX_TOKENS &&
               cmd->tokens[def_idx].type == TOKEN_OPTIONAL) {
            optional_tail = 1;
            def_idx++;
        }

        if (def_idx >= MAX_TOKENS) continue;

        token_def_t *next = &cmd->tokens[def_idx];

        if (partial[0] == '\0' &&
            (next->type == TOKEN_END || optional_tail)) {
            completion_add(entries, &entry_count, max_entries, "<cr>", "Execute command", 1, 0);
        }

        if (next->type == TOKEN_END) {
            continue;
        }

        /*
         * TOKEN_TAIL captures rest-of-line as raw text for domain-specific
         * parsing.  We show a param placeholder (from param_name) but never
         * offer <cr> — the tail is required input, not optional.
         */
        if (next->type == TOKEN_TAIL) {
            char        hint[MAX_TOKEN_LEN];
            const char *display = next->display_name;

            if (ctx->negated && cmd->supports_no && partial[0] == '\0') {
                completion_add(entries, &entry_count, max_entries, "<cr>", "Execute command", 1, 0);
                continue;
            }

            if (display && display[0] != '\0') {
                snprintf(hint, sizeof(hint), "%s", display);
            } else {
                const char *name = parser_completion_display_name(next, "args");
                snprintf(hint, sizeof(hint), "<%s>", name);
            }
            completion_add(entries, &entry_count, max_entries, hint, parser_completion_value_help(next, cmd), 1, 0);
            continue;
        }

        if (next->type == TOKEN_KEYWORD) {
            if (parser_match_keyword(partial, next->keyword) ||
                partial[0] == '\0') {
                int root_keyword_group = (complete_pos == 0);
                completion_add(entries, &entry_count, max_entries,
                               next->keyword, cmd->help_text, 0,
                               root_keyword_group);
            }
        } else if (strlen(partial) < MAX_TOKEN_LEN) {
            // Parameter placeholder (UINT32, STRING, IP_ADDRESS); none for a partial value too long to take
            const char *name = parser_completion_display_name(next, "value");
            char        hint[MAX_TOKEN_LEN];
            snprintf(hint, sizeof(hint), "<%s>", name);

            completion_add(entries, &entry_count, max_entries, hint, parser_completion_value_help(next, cmd), 1, 0);
        }
    }

    return entry_count;
}

void parser_show_help_with_output(parser_ctx_t *ctx, const output_t *output) {
    int             name_width;
    const output_t *previous_output = output_push(output);

    printf("\n");
    name_width = parser_help_name_width(ctx->commands, ctx->command_count);

    for (int i = 0; i < ctx->command_count; i++) {
        cmd_def_t *cmd = &ctx->commands[i];
        char       line[512];

        /*
         * Keep parser help on the same routed-output path as completion help
         * so control-session captures and tests see identical help output.
         */
        help_snprint_line(line, sizeof(line), name_width, cmd->name, cmd->help_text);
        printf("%s\n", line);
    }
    printf("\n");

    output_pop(previous_output);
}

void parser_show_help(parser_ctx_t *ctx) {
    parser_show_help_with_output(ctx, NULL);
}

int match_get_uint32(match_result_t *result, const char *param_name, uint32_t *value) {
    // Search by param_name first
    for (int i = 0; i < result->token_count; i++) {
        if (result->tokens[i].type == TOKEN_UINT32 &&
            result->tokens[i].param_name &&
            strcmp(result->tokens[i].param_name, param_name) == 0) {
            *value = result->tokens[i].uint_value;
            return 1;
        }
    }

    // Fall back to first uint32 token (for commands with a single param)
    for (int i = 0; i < result->token_count; i++) {
        if (result->tokens[i].type == TOKEN_UINT32) {
            *value = result->tokens[i].uint_value;
            return 1;
        }
    }
    return 0;
}

int match_get_string(match_result_t *result, const char *param_name, char *value, int max_len) {
    // Search by param_name first
    for (int i = 0; i < result->token_count; i++) {
        if ((result->tokens[i].type == TOKEN_STRING ||
             result->tokens[i].type == TOKEN_IP_ADDRESS) &&
            result->tokens[i].param_name &&
            strcmp(result->tokens[i].param_name, param_name) == 0) {
            strncpy(value, result->tokens[i].value, max_len - 1);
            value[max_len - 1] = '\0';
            return 1;
        }
    }

    // Fall back to first string/IP token (for commands with a single param)
    for (int i = 0; i < result->token_count; i++) {
        if (result->tokens[i].type == TOKEN_STRING ||
            result->tokens[i].type == TOKEN_IP_ADDRESS) {
            strncpy(value, result->tokens[i].value, max_len - 1);
            value[max_len - 1] = '\0';
            return 1;
        }
    }
    return 0;
}

#define COMPLETION_MAX_REACHABLE_TABLES (CONFIG_MODE_COUNT + 1)
#define COMPLETION_MAX_LOCAL_ENTRIES 64

static int completion_contains_entry(const completion_entry_t *entries, int count,
                                     const completion_entry_t *candidate) {
    for (int i = 0; i < count; i++) {
        if (entries[i].is_parameter == candidate->is_parameter &&
            strcmp(entries[i].keyword, candidate->keyword) == 0) {
            return 1;
        }
    }

    return 0;
}

static void completion_copy_entry(completion_entry_t *dst, const completion_entry_t *src) {
    *dst = *src;

    if (src->help_text == src->generated_help) {
        dst->help_text = dst->generated_help;
    }
}

static int completion_collect_matches(const cmd_reachable_table_t *tables,
                                      int table_count,
                                      int negated,
                                      const char *input,
                                      completion_entry_t *entries,
                                      int max_entries) {
    int entry_count = 0;

    for (int i = 0; i < table_count; i++) {
        parser_ctx_t       parser;
        completion_entry_t local_entries[COMPLETION_MAX_LOCAL_ENTRIES];
        int                local_count;

        if (!tables[i].commands || tables[i].count <= 0) {
            continue;
        }

        parser_init(&parser, tables[i].commands, tables[i].count, NULL);
        parser.negated = negated;
        local_count = parser_find_matches(&parser, input, local_entries, COMPLETION_MAX_LOCAL_ENTRIES);

        for (int j = 0; j < local_count && entry_count < max_entries; j++) {
            if (!completion_contains_entry(entries, entry_count, &local_entries[j])) {
                completion_copy_entry(&entries[entry_count], &local_entries[j]);
                entry_count++;
            }
        }
    }

    return entry_count;
}

static int completion_help_width(const completion_entry_t *entries, int count) {
    int width = 0;

    for (int i = 0; i < count; i++) {
        int candidate = help_label_width(entries[i].keyword);
        if (candidate > width) {
            width = candidate;
        }
    }

    return width;
}

static void completion_normalize_input(cli_mode_t mode, const char *buf, int *has_no_prefix, const char **input) {
    const char *normalized = buf ? buf : "";
    int         negated = 0;

    if (mode == CLI_MODE_CONFIG && strncmp(normalized, "no ", 3) == 0) {
        negated = 1;
        normalized += 3;
        while (isspace((unsigned char)*normalized)) {
            normalized++;
        }
    }

    if (has_no_prefix) {
        *has_no_prefix = negated;
    }
    if (input) {
        *input = normalized;
    }
}

static int completion_collect_for_mode(cli_mode_t mode,
                                       config_mode_t config_mode,
                                       const char *buf,
                                       completion_entry_t *entries,
                                       int max_entries,
                                       int *has_no_prefix_out) {
    const char *input = "";
    int         has_no_prefix = 0;

    completion_normalize_input(mode, buf, &has_no_prefix, &input);

    if (has_no_prefix_out) {
        *has_no_prefix_out = has_no_prefix;
    }

    if (mode == CLI_MODE_EXEC) {
        parser_ctx_t parser;

        parser_init(&parser, cli_exec_commands, cli_exec_commands_count, NULL);
        parser.negated = has_no_prefix;
        return parser_find_matches(&parser, input, entries, max_entries);
    }

    if (mode == CLI_MODE_CONFIG) {
        cmd_reachable_table_t tables[COMPLETION_MAX_REACHABLE_TABLES];
        int table_count = command_collect_reachable_tables(
            config_mode, has_no_prefix ? 0 : 1, tables,
            COMPLETION_MAX_REACHABLE_TABLES);

        return completion_collect_matches(tables, table_count, has_no_prefix, input, entries, max_entries);
    }

    return 0;
}

void completion_show_help(cli_mode_t mode, config_mode_t config_mode, const char *buf, FILE *out) {
    completion_entry_t entries[64];
    int                count;
    int                help_width;

    if (!out) {
        return;
    }

    count = completion_collect_for_mode(mode, config_mode, buf, entries, 64, NULL);
    help_width = completion_help_width(entries, count);

    fprintf(out, "\n");
    for (int i = 0; i < count; i++) {
        help_print_line(out, help_width, entries[i].keyword, entries[i].help_text);
    }
    fprintf(out, "\n");
}

void completion_show_help_with_output(cli_mode_t mode, config_mode_t config_mode,
                                      const char *buf, const output_t *output) {
    completion_entry_t entries[64];
    int                count;
    int                help_width;
    const output_t    *previous_output = output_push(output);

    count = completion_collect_for_mode(mode, config_mode, buf, entries, 64, NULL);
    help_width = completion_help_width(entries, count);

    printf("\n");
    for (int i = 0; i < count; i++) {
        char line[512];

        help_snprint_line(line, sizeof(line), help_width, entries[i].keyword, entries[i].help_text);
        printf("%s\n", line);
    }
    printf("\n");

    output_pop(previous_output);
}

void tab_completion_init(cli_mode_t *mode_ptr) {
    current_mode = mode_ptr;
}

void tab_completion_set_config_mode(config_mode_t mode) {
    current_config_mode = mode;
}

void tab_completion_callback(const char *buf, linenoiseCompletions *lc) {
    if (!current_mode) {
        return;
    }

    int                is_help = (linenoiseGetCompletionKey() == '?');
    completion_entry_t entries[64];
    int                has_no_prefix = 0;
    const char        *input = buf ? buf : "";
    int                count = completion_collect_for_mode(*current_mode, current_config_mode, buf, entries, 64, &has_no_prefix);

    completion_normalize_input(*current_mode, buf, NULL, &input);

    if (is_help) {
        int help_width = completion_help_width(entries, count);

        for (int i = 0; i < count; i++) {
            char line[512];

            help_snprint_line(line, sizeof(line), help_width, entries[i].keyword, entries[i].help_text);
            linenoiseAddCompletion(lc, line);
        }
        return;
    }

    for (int i = 0; i < count; i++) {
        if (entries[i].is_parameter) {
            continue;
        }

        char   completion[512] = "";
        size_t input_len = strlen(input);
        int    trailing_space = (input_len > 0 && isspace((unsigned char)input[input_len - 1]));

        if (has_no_prefix) {
            strcat(completion, "no ");
        }

        if (trailing_space || input_len == 0) {
            strncat(completion, input, sizeof(completion) - strlen(completion) - 1);
        } else {
            const char *last_sp = strrchr(input, ' ');

            if (last_sp) {
                size_t prefix_len = (size_t)(last_sp - input + 1);

                strncat(completion, input,
                        prefix_len < sizeof(completion) - strlen(completion) - 1 ?
                        prefix_len : sizeof(completion) - strlen(completion) - 1);
            }
        }

        size_t used = strlen(completion);
        size_t count = strnlen(entries[i].keyword, sizeof(completion) - used - 1);
        memcpy(completion + used, entries[i].keyword, count);
        completion[used + count] = '\0';
        strncat(completion, " ", sizeof(completion) - strlen(completion) - 1);
        linenoiseAddCompletion(lc, completion);
    }
}
