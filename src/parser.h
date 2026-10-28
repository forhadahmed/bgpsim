#ifndef TOKEN_PARSER_H
#define TOKEN_PARSER_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "cli.h"
#include "output.h"
#include "linenoise.h"

// Maximum tokens in a command
#define MAX_TOKENS 32

// Maximum token length
#define MAX_TOKEN_LEN 64

/*
 * Token types
 */
typedef enum {
    TOKEN_KEYWORD,     /* Fixed keyword (e.g., "show", "bgp")       */
    TOKEN_UINT32,      /* Unsigned 32-bit integer (e.g., AS number) */
    TOKEN_STRING,      /* Generic string (e.g., network name)       */
    TOKEN_IP_ADDRESS,  /* IPv4 or IPv6 address                      */
    TOKEN_OPTIONAL,    /* Optional parameter marker                 */
    TOKEN_TAIL,        /* Capture all remaining input as raw string */
    TOKEN_END          /* End of command definition                 */
} token_type_t;

/*
 * Token definition for command matching
 */
typedef struct {
    token_type_t type;
    const char  *keyword;       /* For TOKEN_KEYWORD, the expected keyword */
    const char  *param_name;    /* Internal lookup key for non-keywords    */
    const char  *display_name;  /* User-visible placeholder name           */
    const char  *value_help;    /* User-visible leaf help for '?'          */
} token_def_t;

/*
 * Parsed token result
 */
typedef struct {
    token_type_t type;
    char         value[MAX_TOKEN_LEN];
    uint32_t     uint_value;  /* For TOKEN_UINT32                     */
    const char  *param_name;  /* Parameter name from token definition */
} parsed_token_t;

// Maximum tail capture length
#define MAX_TAIL_LEN 1024

/*
 * Command match result
 */
typedef struct {
    int            token_count;               /* Number of tokens parsed                     */
    int            keyword_rank[MAX_TOKENS];  /* Per-token match quality (2=exact, 1=prefix) */
    parsed_token_t tokens[MAX_TOKENS];
    char           tail[MAX_TAIL_LEN];        /* Captured rest-of-line for TOKEN_TAIL        */
} match_result_t;

/*
 * Command handler callback
 */
typedef int (*cmd_handler_t)(void *ctx, match_result_t *result);

/*
 * Command definition
 */
typedef struct cmd_def {
    const char   *name;                /* Command name/description                    */
    token_def_t   tokens[MAX_TOKENS];  /* Token definitions                           */
    cmd_handler_t handler;             /* Command handler function                    */
    const char   *help_text;           /* Help text for this command                  */
    int           supports_no;         /* 1 if "no <command>" is valid in config mode */
} cmd_def_t;

/*
 * Parser context
 */
typedef struct {
    cmd_def_t *commands;       /* Array of command definitions                           */
    int        command_count;  /* Number of commands                                     */
    void      *user_ctx;       /* User context passed to handlers                        */
    int        negated;        /* 1 if "no" prefix; rejects commands with supports_no==0 */
} parser_ctx_t;

// Token Parser API

/*
 * Initialize a parser context
 */
void parser_init(parser_ctx_t *ctx, cmd_def_t *commands, int command_count, void *user_ctx);

/*
 * Parse and execute a command line
 * Returns:
 *   1               empty input line (no-op)
 *   0 or positive   handler ran successfully
 *  -1               command matched but handler/validation failed
 *  PARSER_INCOMPLETE input is a valid command prefix but missing required input
 *  PARSER_UNSUPPORTED_NEGATION input is recognised but "no" is not supported
 *  PARSER_AMBIGUOUS input matches multiple commands equally
 *  PARSER_NO_MATCH  no command definition matched the input at all
 *
 * Callers that unwind a mode stack (command_execute) should only retry
 * in parent modes on PARSER_NO_MATCH.  A -1 or PARSER_INCOMPLETE means the
 * command was recognised in the current search scope, so retrying in a parent
 * mode would be wrong.
 */
#define PARSER_INCOMPLETE (-3)
#define PARSER_NO_MATCH (-2)
#define PARSER_UNSUPPORTED_NEGATION (-4)
#define PARSER_AMBIGUOUS (-5)
int parser_execute(parser_ctx_t *ctx, const char *line);

/*
 * Match a partial keyword
 * Returns: 1 if prefix uniquely matches keyword, 0 otherwise
 */
int parser_match_keyword(const char *prefix, const char *keyword);

// Completion match entry for TAB and '?'
#define MAX_COMPLETION_HELP_LEN (MAX_TOKEN_LEN + 16)

typedef struct {
    char        keyword[MAX_TOKEN_LEN];  /* Keyword or <param_name> placeholder */
    const char *help_text;               /* Help text (from cmd_def_t)          */
    char        generated_help[MAX_COMPLETION_HELP_LEN];
    int         is_parameter;            /* 1 = type placeholder, not keyword   */
} completion_entry_t;

/*
 * Find valid next-token completions for partial input.
 * Returns: number of entries written to entries[].
 */
int parser_find_matches(parser_ctx_t *ctx, const char *line, completion_entry_t *entries, int max_entries);

/*
 * Initialize tab completion system
 */
void tab_completion_init(cli_mode_t *mode_ptr);

/*
 * Set current config mode for filtering completions
 */
void tab_completion_set_config_mode(config_mode_t mode);

/*
 * Main completion callback for linenoise
 */
void tab_completion_callback(const char *buf, linenoiseCompletions *lc);

/*
 * Render flat '?' help using the same reachable completion surface as the
 * interactive linenoise callback.
 */
void completion_show_help(cli_mode_t mode, config_mode_t config_mode, const char *buf, FILE *out);
void completion_show_help_with_output(cli_mode_t mode, config_mode_t config_mode,
                                      const char *buf, const output_t *output);

/*
 * Get help text for a command or list all commands
 */
void parser_show_help(parser_ctx_t *ctx);
void parser_show_help_with_output(parser_ctx_t *ctx, const output_t *output);

/*
 * Helper: Get uint32 parameter by name from match result
 */
int match_get_uint32(match_result_t *result, const char *param_name, uint32_t *value);

/*
 * Helper: Get string parameter by name from match result
 */
int match_get_string(match_result_t *result, const char *param_name, char *value, int max_len);

/*
 * Help-text formatting helpers used by parser completion and '?' output.
 * Previously lived in help_format.h; folded here since only parser.c
 * uses them.
 */

enum { HELP_TEXT_GAP = 4 };

static inline int help_label_width(const char *label) {
    return (int)strlen(label ? label : "") + HELP_TEXT_GAP;
}

static inline void help_print_line(FILE *out, int width, const char *label, const char *help_text) {
    fprintf(out, "  %-*s%s\n", width, label ? label : "", help_text ? help_text : "");
}

static inline void help_snprint_line(char *buf, size_t buflen, int width, const char *label, const char *help_text) {
    const char *safe_label = label ? label : "";
    const char *safe_help = help_text ? help_text : "";
    size_t      used;
    size_t      label_len;
    size_t      pad_len = 0;

    if (!buf || buflen == 0) {
        return;
    }

    /*
     * Avoid the "%-*s" snprintf form here: with -O2 GCC treats the dynamic
     * field width as effectively unbounded and raises -Wformat-truncation,
     * which breaks release benchmark builds under -Werror even though this
     * helper is intentionally truncation-safe.
     */
    used = (size_t)snprintf(buf, buflen, "  %s", safe_label);
    if (used >= buflen) {
        return;
    }

    label_len = strlen(safe_label);
    if (width > 0 && (size_t)width > label_len) {
        pad_len = (size_t)width - label_len;
    }

    while (pad_len > 0 && used + 1 < buflen) {
        buf[used++] = ' ';
        pad_len--;
    }
    buf[used] = '\0';

    if (used + 1 < buflen) {
        (void)snprintf(buf + used, buflen - used, "%s", safe_help);
    }
}

#endif /* TOKEN_PARSER_H */
