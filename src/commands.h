#ifndef COMMANDS_H
#define COMMANDS_H

#include "cli.h"
#include "bgpsim.h"
#include "parser.h"

/*
 * Command context shared between CLI and config parsing
 */
typedef struct {
    bgp_sim_t           *sim;
    cli_mode_t          *mode;              /* NULL for config file parsing               */
    cli_session_t       *session;           /* NULL for stateless config-file parsing     */
    config_mode_t        config_mode;       /* Current configuration mode                 */
    int                  is_no_command;     /* 1 if "no" prefix was used                  */
    const char          *raw_line;          /* Original input line (after "no" stripping) */
    bgp_ribout_config_t *current_ribout;    /* Current ribout context                     */
    bgp_router_t        *current_router;    /* Current router context                     */
    bgp_neighbor_t      *current_neighbor;  /* Current neighbor context                   */
    char                 current_script_name[SCRIPT_NAME_SIZE];

    // Mode stack for hierarchical navigation
    config_mode_t mode_stack[MAX_MODE_DEPTH];
    int           mode_stack_depth;
} cmd_ctx_t;

// Mode Stack Management

/*
 * Push current mode onto stack and enter new mode
 */
static inline void cmd_push_mode(cmd_ctx_t *ctx, config_mode_t new_mode) {
    if (ctx->mode_stack_depth < MAX_MODE_DEPTH) {
        ctx->mode_stack[ctx->mode_stack_depth++] = ctx->config_mode;
        ctx->config_mode = new_mode;
    }
}

/*
 * Pop mode from stack and return to parent
 */
static inline config_mode_t cmd_pop_mode(cmd_ctx_t *ctx) {
    if (ctx->mode_stack_depth > 0) {
        ctx->config_mode = ctx->mode_stack[--ctx->mode_stack_depth];
    } else {
        // Stack empty - we're at global config, exit to EXEC
        ctx->config_mode = CONFIG_MODE_GLOBAL;
    }
    return ctx->config_mode;
}

// Command Execution Infrastructure

/*
 * Structure to save/restore mode state during command rewinding
 */
typedef struct {
    int                  stack_depth;
    config_mode_t        mode;
    bgp_router_t        *router;
    bgp_neighbor_t      *neighbor;
    bgp_ribout_config_t *ribout;
    char                 script_name[SCRIPT_NAME_SIZE];
} saved_mode_state_t;

/*
 * Command table: array + count pair
 */
typedef struct {
    cmd_def_t *commands;
    int        count;
} cmd_table_t;

typedef enum {
    CMD_REACHABLE_CURRENT_CONFIG,
    CMD_REACHABLE_PARENT_CONFIG,
    CMD_REACHABLE_EXEC
} cmd_reachable_kind_t;

typedef struct {
    cmd_def_t           *commands;
    int                  count;
    config_mode_t        config_mode;
    cmd_reachable_kind_t kind;
} cmd_reachable_table_t;

#define CONFIG_MODE_COUNT 5

/*
 * Execution options for command_execute
 */
typedef struct {
    // Per-mode config command tables (indexed by config_mode_t)
    cmd_table_t config_tables[CONFIG_MODE_COUNT];

    // Exec mode commands (for GLOBAL fallback)
    cmd_def_t *exec_commands;
    int        exec_commands_count;
} cmd_exec_options_t;

/*
 * Save current mode state
 */
void save_mode_state(saved_mode_state_t *saved, cmd_ctx_t *ctx);

/*
 * Restore mode state from saved snapshot
 */
void restore_mode_state(saved_mode_state_t *saved, cmd_ctx_t *ctx);

/*
 * Core command execution with mode stack unwinding
 */
int command_execute(const char *input_line, cmd_ctx_t *cmd_ctx, const cmd_exec_options_t *options);

/*
 * Reachable command-table enumeration for help and completion.
 */
int command_collect_reachable_tables(config_mode_t current_mode,
                                     int include_exec,
                                     cmd_reachable_table_t *tables,
                                     int max_tables);

/*
 * Build the default config+exec command surface shared by CLI and config-file parsing.
 */
void command_init_exec_options(cmd_exec_options_t *options);

// Shared Command Handlers

/*
 * Router commands
 */
int cmd_handle_router_bgp(void *ctx, match_result_t *result);
int cmd_handle_router_id(void *ctx, match_result_t *result);
int cmd_handle_update_source(void *ctx, match_result_t *result);
int cmd_handle_update_generate(void *ctx, match_result_t *result);

/*
 * Neighbor commands
 */
int cmd_handle_neighbor(void *ctx, match_result_t *result);

/*
 * Address family commands
 */
int cmd_handle_address_family(void *ctx, match_result_t *result);

/*
 * Capability commands
 */
int cmd_handle_capability_graceful_restart(void *ctx, match_result_t *result);
int cmd_handle_capability_route_refresh(void *ctx, match_result_t *result);
int cmd_handle_capability_four_byte_asn(void *ctx, match_result_t *result);
int cmd_handle_capability_add_path(void *ctx, match_result_t *result);
int cmd_handle_capability_ext_nh(void *ctx, match_result_t *result);

/*
 * RIB-OUT commands
 */
int cmd_handle_ribout(void *ctx, match_result_t *result);
int cmd_handle_ribout_prefix(void *ctx, match_result_t *result);
int cmd_handle_ribout_rd(void *ctx, match_result_t *result);
int cmd_handle_ribout_label(void *ctx, match_result_t *result);
int cmd_handle_ribout_ethernet_tag(void *ctx, match_result_t *result);
int cmd_handle_ribout_path_id(void *ctx, match_result_t *result);
int cmd_handle_ribout_next_hop(void *ctx, match_result_t *result);
int cmd_handle_ribout_gateway_ip(void *ctx, match_result_t *result);
int cmd_handle_ribout_esi(void *ctx, match_result_t *result);
int cmd_handle_ribout_aspath(void *ctx, match_result_t *result);
int cmd_handle_ribout_localpref(void *ctx, match_result_t *result);
int cmd_handle_ribout_med(void *ctx, match_result_t *result);
int cmd_handle_ribout_rt(void *ctx, match_result_t *result);
int cmd_handle_ribout_rt_set(void *ctx, match_result_t *result);
int cmd_handle_ribout_soo(void *ctx, match_result_t *result);
int cmd_handle_ribout_encap(void *ctx, match_result_t *result);
int cmd_handle_ribout_router_mac(void *ctx, match_result_t *result);
int cmd_handle_ribout_origin(void *ctx, match_result_t *result);
int cmd_handle_ribout_distinguisher(void *ctx, match_result_t *result);
int cmd_handle_ribout_color(void *ctx, match_result_t *result);
int cmd_handle_ribout_endpoint(void *ctx, match_result_t *result);
int cmd_handle_ribout_enlp(void *ctx, match_result_t *result);
int cmd_handle_ribout_priority(void *ctx, match_result_t *result);
int cmd_handle_ribout_preference(void *ctx, match_result_t *result);
int cmd_handle_ribout_binding_sid(void *ctx, match_result_t *result);
int cmd_handle_ribout_segment_list(void *ctx, match_result_t *result);
int cmd_handle_ribout_address_family(void *ctx, match_result_t *result);
int cmd_handle_ribout_action(void *ctx, match_result_t *result);

/*
 * CLI-only commands
 */
int cmd_handle_shutdown(void *ctx, match_result_t *result);
int cmd_handle_show_bgp_summary(void *ctx, match_result_t *result);
int cmd_handle_show_bgp_neighbors(void *ctx, match_result_t *result);
int cmd_handle_show_bgp_neighbors_as(void *ctx, match_result_t *result);
int cmd_handle_config_mode(void *ctx, match_result_t *result);
int cmd_handle_show_config(void *ctx, match_result_t *result);
int cmd_handle_show_log(void *ctx, match_result_t *result);
int cmd_handle_show_log_all(void *ctx, match_result_t *result);
int cmd_handle_show_ribout(void *ctx, match_result_t *result);
int cmd_handle_show_ribout_name(void *ctx, match_result_t *result);
int cmd_handle_show_ribout_preview(void *ctx, match_result_t *result);
int cmd_handle_show_ribout_map(void *ctx, match_result_t *result);
int cmd_handle_show_ribout_map_name(void *ctx, match_result_t *result);
int cmd_handle_exit_config(void *ctx, match_result_t *result);
int cmd_handle_end_config(void *ctx, match_result_t *result);
int cmd_handle_clear_bgp_neighbor(void *ctx, match_result_t *result);
int cmd_handle_clear_bgp_all(void *ctx, match_result_t *result);
int cmd_handle_terminal_monitor(void *ctx, match_result_t *result);
// NOTE: Generate handlers removed - ribout maps are now auto-generated

// Command Definition Arrays

/*
 * Per-mode configuration command tables
 */
extern cmd_table_t config_tables[CONFIG_MODE_COUNT];

/*
 * CLI exec mode commands
 */
extern cmd_def_t cli_exec_commands[];
extern int cli_exec_commands_count;

/*
 * Outbound UPDATE exec commands (tx_cli.c).
 */
int cmd_handle_tx_ribout(void *ctx, match_result_t *result);
int cmd_handle_tx_withdraw_all(void *ctx, match_result_t *result);

/*
 * Script/run CLI adapters; execution remains disconnected from the peer engine.
 */
int cmd_handle_script(void *ctx, match_result_t *result);
int cmd_handle_script_action(void *ctx, match_result_t *result);
int cmd_handle_script_sleep(void *ctx, match_result_t *result);
int cmd_handle_script_remove_step(void *ctx, match_result_t *result);
int cmd_handle_run_script(void *ctx, match_result_t *result);
int cmd_handle_show_scripts(void *ctx, match_result_t *result);
int cmd_handle_show_runs(void *ctx, match_result_t *result);
int cmd_handle_cancel_run(void *ctx, match_result_t *result);
int cmd_handle_clear_run(void *ctx, match_result_t *result);
void script_print_config(const script_store_t *store);

#endif /* COMMANDS_H */
