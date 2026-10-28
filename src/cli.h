#ifndef CLI_H
#define CLI_H

#include <stddef.h>
#include <stdint.h>

/*
 * CLI modes
 */
typedef enum {
    CLI_MODE_EXEC,
    CLI_MODE_CONFIG
} cli_mode_t;

/*
 * Configuration mode hierarchy
 */
typedef enum {
    CONFIG_MODE_GLOBAL = 0,  /* Top-level config mode       */
    CONFIG_MODE_ROUTER_BGP,  /* router bgp <AS> mode        */
    CONFIG_MODE_NEIGHBOR,    /* neighbor configuration mode */
    CONFIG_MODE_RIBOUT,      /* ribout configuration mode   */
    CONFIG_MODE_SCRIPT       /* script definition mode      */
} config_mode_t;

// Maximum depth of mode hierarchy
#define MAX_MODE_DEPTH 8

/*
 * Per-session CLI context. This tracks hierarchical config state explicitly
 * instead of relying on process-global variables. The context stores stable
 * identifiers instead of raw object pointers so router/neighbor/ribout
 * removal does not leave dangling references behind.
 */
typedef struct {
    config_mode_t config_mode;
    int           terminal_monitor;
    int           has_router;
    uint32_t      current_router_as;
    int           has_neighbor;
    char          current_neighbor_ip[64];
    int           has_ribout;
    char          current_ribout_name[32];
    char          current_script_name[64];
    config_mode_t mode_stack[MAX_MODE_DEPTH];
    int           mode_stack_depth;
} cli_session_t;

void cli_session_init(cli_session_t *session);
void cli_session_reset_exec_context(cli_session_t *session);
void cli_build_prompt(cli_mode_t mode, const cli_session_t *session, char *prompt, size_t prompt_size, int use_color);

#endif /* CLI_H */
