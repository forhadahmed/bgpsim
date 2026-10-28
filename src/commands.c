#define OUTPUT_STDIO_REMAP

#include <stdio.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#if defined(__GLIBC__)
#include <malloc.h>   /* malloc_trim: return regeneration's freed heap to the OS (glibc only) */
#endif
#include "log.h"
#include "output.h"
#include "runtime.h"
#include "tx_exec.h"
#include "commands.h"
#include "bgp_router.h"
#include "bgp_peer_tx.h"
#include "bgp_neighbor.h"
#include "bgp_ribout_config.h"

/*
 * Forward declarations for CLI functions
 */
extern void cli_show_routers(bgp_sim_t *sim);
extern void cli_show_neighbors(bgp_sim_t *sim, uint32_t as_filter);
extern void cli_show_config(bgp_sim_t *sim);
extern void cli_show_ribout(bgp_sim_t *sim);
extern void cli_show_ribout_detail(bgp_sim_t *sim, const char *name);
extern void cli_show_ribout_preview(bgp_sim_t *sim, const char *name, int count);
extern void cli_show_ribout_map_summary(bgp_sim_t *sim);
extern void cli_show_ribout_map_detail(bgp_sim_t *sim, const char *ribout_name);
extern void show_log(int lines);

// Helper Functions

/*
 * NOTE: Auto-generation has been removed. Ribout maps must be generated
 * explicitly via manual command or on mode exit (to be implemented).
 */

/*
 * Address-family lookup uses the unified bgp_families[] table from bgp.h.
 * The old neighbor_af_option_t type and k_neighbor_af_options[] are gone;
 * command handlers reference bgp_family_t directly.
 */

static int command_extract_keyword_tail(const match_result_t *result,
                                        const char *anchor_keyword,
                                        char *buffer,
                                        size_t buffer_size) {
    int    seen_anchor = 0;
    size_t used = 0;

    if (!buffer || buffer_size == 0) {
        return -1;
    }

    buffer[0] = '\0';

    for (int i = 0; i < result->token_count; i++) {
        const char *value;
        size_t      value_len;

        if (result->tokens[i].type != TOKEN_KEYWORD) {
            continue;
        }

        value = result->tokens[i].value;
        if (!seen_anchor) {
            if (strcmp(value, anchor_keyword) == 0) {
                seen_anchor = 1;
            }
            continue;
        }

        value_len = strlen(value);
        if (used > 0) {
            if (used + 1 >= buffer_size) {
                return -1;
            }
            buffer[used++] = ' ';
            buffer[used] = '\0';
        }

        if (used + value_len >= buffer_size) {
            return -1;
        }

        memcpy(buffer + used, value, value_len + 1);
        used += value_len;
    }

    return seen_anchor ? 0 : -1;
}

static int command_error(const char *message) {
    fprintf(stderr, "Error: %s\n", message);
    return -1;
}

static int command_require_neighbor(const cmd_ctx_t *cmd_ctx, const char *command_name) {
    if (cmd_ctx && cmd_ctx->current_neighbor) {
        return 1;
    }

    fprintf(stderr, "Error: No neighbor context for %s command\n", command_name);
    return 0;
}

static int command_error_no_update_source_context(void) {
    return command_error("No context for update-source");
}

// Command Execution Infrastructure

/*
 * Save current mode state
 */
void save_mode_state(saved_mode_state_t *saved, cmd_ctx_t *ctx) {
    saved->stack_depth = ctx->mode_stack_depth;
    saved->mode = ctx->config_mode;
    saved->router = ctx->current_router;
    saved->neighbor = ctx->current_neighbor;
    saved->ribout = ctx->current_ribout;
    memcpy(saved->script_name, ctx->current_script_name, sizeof(saved->script_name));
}

/*
 * Restore mode state from saved snapshot
 */
void restore_mode_state(saved_mode_state_t *saved, cmd_ctx_t *ctx) {
    ctx->mode_stack_depth = saved->stack_depth;
    ctx->config_mode = saved->mode;
    ctx->current_router = saved->router;
    ctx->current_neighbor = saved->neighbor;
    ctx->current_ribout = saved->ribout;
    memcpy(ctx->current_script_name, saved->script_name, sizeof(ctx->current_script_name));
}

/*
 * Mode that a command of mode returns to when it leaves (exit, or a parent-mode command).
 */
static config_mode_t command_parent_mode(config_mode_t mode) {
    switch (mode) {
        case CONFIG_MODE_NEIGHBOR:
            return CONFIG_MODE_ROUTER_BGP;
        case CONFIG_MODE_ROUTER_BGP:
        case CONFIG_MODE_RIBOUT:
        case CONFIG_MODE_SCRIPT:
            return CONFIG_MODE_GLOBAL;
        case CONFIG_MODE_GLOBAL:
        default:
            return CONFIG_MODE_GLOBAL;
    }
}

int command_collect_reachable_tables(config_mode_t current_mode,
                                     int include_exec,
                                     cmd_reachable_table_t *tables,
                                     int max_tables) {
    config_mode_t mode = current_mode;
    int           count = 0;
    int           first = 1;

    if (!tables || max_tables <= 0) {
        return 0;
    }

    while (count < max_tables) {
        tables[count].commands = config_tables[mode].commands;
        tables[count].count = config_tables[mode].count;
        tables[count].config_mode = mode;
        tables[count].kind = first ? CMD_REACHABLE_CURRENT_CONFIG
                                   : CMD_REACHABLE_PARENT_CONFIG;
        count++;

        if (mode == CONFIG_MODE_GLOBAL) {
            break;
        }

        mode = command_parent_mode(mode);
        first = 0;
    }

    if (include_exec && count < max_tables) {
        tables[count].commands = cli_exec_commands;
        tables[count].count = cli_exec_commands_count;
        tables[count].config_mode = CONFIG_MODE_GLOBAL;
        tables[count].kind = CMD_REACHABLE_EXEC;
        count++;
    }

    return count;
}

/*
 * Fill the command tables of every config mode and the exec table into options.
 */
void command_init_exec_options(cmd_exec_options_t *options) {
    if (!options) {
        return;
    }

    for (int mode = 0; mode < CONFIG_MODE_COUNT; mode++) {
        options->config_tables[mode] = config_tables[mode];
    }
    options->exec_commands = cli_exec_commands;
    options->exec_commands_count = cli_exec_commands_count;
}

/*
 * Core command execution with mode stack unwinding
 */
int command_execute(const char *input_line, cmd_ctx_t *cmd_ctx, const cmd_exec_options_t *options) {
    parser_ctx_t parser;
    int          result = PARSER_NO_MATCH;

    // Always save state so we can restore on failure or exec fallback
    saved_mode_state_t saved_state;
    save_mode_state(&saved_state, cmd_ctx);

    // Try current mode's command table
    const cmd_table_t *tbl = &options->config_tables[cmd_ctx->config_mode];
    if (tbl->commands && tbl->count > 0) {
        parser_init(&parser, tbl->commands, tbl->count, cmd_ctx);
        parser.negated = cmd_ctx->is_no_command;
        result = parser_execute(&parser, input_line);
    }

    /*
     * If no command matched, rewind up mode stack trying parent modes.
     * Only unwind on PARSER_NO_MATCH — handler errors (-1) and ambiguous
     * commands already printed their own diagnostics.
     */
    while (result == PARSER_NO_MATCH && cmd_ctx->mode_stack_depth > 0) {
        // Pop to parent mode and clear context for mode we're leaving
        config_mode_t leaving_mode = cmd_ctx->config_mode;
        cmd_ctx->config_mode = cmd_ctx->mode_stack[--cmd_ctx->mode_stack_depth];

        // Clear context for the mode we left
        if (leaving_mode == CONFIG_MODE_NEIGHBOR) {
            cmd_ctx->current_neighbor = NULL;
        } else if (leaving_mode == CONFIG_MODE_ROUTER_BGP) {
            cmd_ctx->current_router = NULL;
            cmd_ctx->current_neighbor = NULL;
        } else if (leaving_mode == CONFIG_MODE_RIBOUT) {
            cmd_ctx->current_ribout = NULL;
        } else if (leaving_mode == CONFIG_MODE_SCRIPT) {
            cmd_ctx->current_script_name[0] = '\0';
        }

        // Try command in parent mode
        tbl = &options->config_tables[cmd_ctx->config_mode];
        if (tbl->commands && tbl->count > 0) {
            parser_init(&parser, tbl->commands, tbl->count, cmd_ctx);
            parser.negated = cmd_ctx->is_no_command;
            result = parser_execute(&parser, input_line);
        }
    }

    // If still no match and we're at GLOBAL, try EXEC mode
    int exec_mode_used = 0;
    if (!cmd_ctx->is_no_command &&
        result == PARSER_NO_MATCH && cmd_ctx->config_mode == CONFIG_MODE_GLOBAL &&
        options->exec_commands && options->exec_commands_count > 0) {
        parser_init(&parser, options->exec_commands, options->exec_commands_count, cmd_ctx);
        result = parser_execute(&parser, input_line);
        if (result >= 0) {
            exec_mode_used = 1;
        }
    }

    // On failure or exec-mode fallback, restore original state
    if (result < 0 || exec_mode_used) {
        restore_mode_state(&saved_state, cmd_ctx);
    }

    return result;
}

// Shared Command Handlers

int cmd_handle_router_bgp(void *ctx, match_result_t *result) {
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;
    uint32_t   as_number = 0;

    if (!match_get_uint32(result, "AS", &as_number)) {
        fprintf(stderr, "Error: AS number required\n");
        return -1;
    }

    if (cmd_ctx->is_no_command) {
        // Removing router - return to global mode
        cmd_ctx->config_mode = CONFIG_MODE_GLOBAL;
        cmd_ctx->current_router = NULL;
        cmd_ctx->current_neighbor = NULL;
        return bgp_remove_router(cmd_ctx->sim, as_number);
    } else {
        // Add or select router
        int result_code = bgp_add_router(cmd_ctx->sim, as_number);
        if (result_code >= 0) {
            // Successfully added (1) or already exists (0) - select router
            cmd_ctx->current_router = bgp_find_router(cmd_ctx->sim, as_number);
            cmd_ctx->current_neighbor = NULL;  /* Clear neighbor context */
            // Enter router mode
            cmd_push_mode(cmd_ctx, CONFIG_MODE_ROUTER_BGP);
        }
        return result_code;
    }
}

int cmd_handle_router_id(void *ctx, match_result_t *result) {
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;
    char       router_id[64];

    if (!match_get_string(result, "router-id", router_id, sizeof(router_id))) {
        fprintf(stderr, "Error: Router ID required\n");
        return -1;
    }

    if (!cmd_ctx->current_router) {
        fprintf(stderr, "Error: No router configured for router-id\n");
        return -1;
    }

    return bgp_set_router_id(cmd_ctx->sim, cmd_ctx->current_router->local_as, router_id);
}

int cmd_handle_update_source(void *ctx, match_result_t *result) {
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;
    char       source_ip[64];

    if (cmd_ctx->is_no_command) {
        if (cmd_ctx->current_neighbor && cmd_ctx->current_router) {
            return bgp_clear_neighbor_source_ip(cmd_ctx->sim,
                                                cmd_ctx->current_router->local_as,
                                                cmd_ctx->current_neighbor->ip);
        }

        if (cmd_ctx->current_router) {
            return bgp_clear_source_ip(cmd_ctx->sim, cmd_ctx->current_router->local_as);
        }

        return command_error_no_update_source_context();
    }

    if (!match_get_string(result, "source-ip", source_ip, sizeof(source_ip))) {
        fprintf(stderr, "Error: Source IP required\n");
        return -1;
    }

    if (cmd_ctx->current_neighbor && cmd_ctx->current_router) {
        return bgp_set_neighbor_source_ip(cmd_ctx->sim,
                                          cmd_ctx->current_router->local_as,
                                          cmd_ctx->current_neighbor->ip,
                                          source_ip);
    }

    if (cmd_ctx->current_router) {
        return bgp_set_source_ip(cmd_ctx->sim, cmd_ctx->current_router->local_as, source_ip);
    }

    return command_error_no_update_source_context();
}

int cmd_handle_vrf(void *ctx, match_result_t *result) {
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;
    char       name[BGP_VRF_NAME_SIZE];
    int        has_name = match_get_string(result, "name", name, sizeof(name));

    if (!cmd_ctx->current_router) {
        fprintf(stderr, "Error: No router configured for vrf\n");
        return -1;
    }

    if (cmd_ctx->is_no_command) {
        return bgp_clear_vrf(cmd_ctx->sim, cmd_ctx->current_router->local_as, has_name ? name : NULL);
    }

    if (!has_name) {
        fprintf(stderr, "Error: VRF name required\n");
        return -1;
    }

    return bgp_set_vrf(cmd_ctx->sim, cmd_ctx->current_router->local_as, name);
}

int cmd_handle_update_generate(void *ctx, match_result_t *result) {
    cmd_ctx_t            *cmd_ctx = ctx;
    bgp_ribout_config_t **selected = NULL;
    int                   capacity = 0, count = 0;
    int                   changed = result->token_count > 2 && !strcmp(result->tokens[2].value, "changed");
    if (result->tail[0]) {
        char *save = NULL;
        /*
         * Resolve the complete selection before publishing anything: a misspelled later name must not
         * regenerate earlier blocks. Duplicate names refer to one generation, not repeated work.
         */
        for (char *name = strtok_r(result->tail, " \t", &save); name; name = strtok_r(NULL, " \t", &save)) {
            bgp_ribout_config_t *block = bgp_sim_find_ribout(cmd_ctx->sim, name);
            if (!block) {
                fprintf(stderr, "Error: ribout '%s' not found\n", name);
                free(selected);
                return -1;
            }
            int i;
            for (i = 0; i < count && selected[i] != block; i++) {}
            if (i < count) continue;
            bgp_ribout_config_t **grown = array_reserve(selected, sizeof(*selected), &capacity, count + 1);
            if (!grown) {
                fprintf(stderr, "Error: no memory for ribout selection\n");
                free(selected);
                return -1;
            }
            selected = grown;
            selected[count++] = block;
        }
    }
    int failed = 0;
    int generated = 0;
    for (int i = 0; i < (selected ? count : cmd_ctx->sim->ribout_count); i++) {
        bgp_ribout_config_t *ribout = selected ? selected[i] : cmd_ctx->sim->ribouts[i];
        if (changed && !ribout->dirty && ribout->snapshot) continue;
        switch (bgp_ribout_generate(ribout)) {
            case BGP_RIBOUT_GENERATED:
                generated++;
                printf("ribout %s: Generated %zu UPDATE messages\n", ribout->name, ribout->message_count);
                tx_standing_regenerated(cmd_ctx->sim, ribout->name);
                break;
            case BGP_RIBOUT_INCOMPLETE:
                printf("  %s: Skipped (incomplete ribout configuration)\n", ribout->name);
                break;
            case BGP_RIBOUT_MAP_FAILED:
                printf("ribout %s: Map generation failed\n", ribout->name);
                failed = 1;
                break;
            case BGP_RIBOUT_MESSAGES_FAILED:
                printf("ribout %s: Message generation failed\n", ribout->name);
                failed = 1;
                break;
        }
    }
    if (changed && !generated && !failed) printf("No changed ribouts generated.\n");
    free(selected);
    #if defined(__GLIBC__)
    /*
     * Regeneration frees large transients: each block's map arena (bgp_ribout_map_destroy) and the superseded
     * snapshot it replaces (released here or as standing peers rebind). glibc keeps that freed heap in its arenas
     * rather than returning it to the OS, so after a bulk regenerate RSS stays high. This command is the single
     * choke point for that churn and runs off the hot path, so one trim here returns the memory. No-op on musl/macOS.
     */
    if (generated > 0) {
        malloc_trim(0);
    }
    #endif
    return failed ? -1 : 0;
}

int cmd_handle_neighbor(void *ctx, match_result_t *result) {
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;
    char       neighbor_ip[64];
    uint32_t   remote_as = 0;
    int        has_remote_as = 0;

    if (!match_get_string(result, "neighbor-ip", neighbor_ip, sizeof(neighbor_ip))) {
        fprintf(stderr, "Error: Neighbor IP required\n");
        return -1;
    }

    // For 'no' commands, remote-as is optional. For add commands, it's required.
    has_remote_as = match_get_uint32(result, "remote-as", &remote_as);

    bgp_router_t *router = cmd_ctx->current_router;
    if (!router) {
        fprintf(stderr, "Error: No router configured for neighbor\n");
        return -1;
    }

    if (cmd_ctx->is_no_command) {
        // Removing neighbor - remote-as not required, just IP
        cmd_ctx->current_neighbor = NULL;
        return bgp_remove_neighbor(cmd_ctx->sim, router->local_as, neighbor_ip);
    } else {
        // Add or select neighbor - remote-as is required
        if (!has_remote_as) {
            fprintf(stderr, "Error: Remote AS number required when adding neighbor\n");
            return -1;
        }
        int result_code = bgp_add_neighbor(cmd_ctx->sim, router->local_as, neighbor_ip, remote_as);
        if (result_code >= 0) {
            cmd_ctx->current_neighbor = bgp_find_neighbor(router, neighbor_ip);
            cmd_push_mode(cmd_ctx, CONFIG_MODE_NEIGHBOR);
        }
        return result_code;
    }
}

int cmd_handle_advertise(void *ctx, match_result_t *result) {
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;
    char       ribout[64];
    int        has_ribout = 0;

    // Extract RIBOUT ID
    has_ribout = match_get_string(result, "ribout", ribout, sizeof(ribout));
    if (has_ribout && !bgp_ribout_name_valid(ribout)) {
        fprintf(stderr, "Error: Invalid ribout name\n");
        return -1;
    }
    if (!has_ribout) {
        fprintf(stderr, "Error: name of the ribout is required\n");
        return -1;
    }

    if (!cmd_ctx->current_neighbor) {
        fprintf(stderr, "Error: No neighbor context for advertise command\n");
        return -1;
    }

    bgp_neighbor_t *neighbor = cmd_ctx->current_neighbor;

    // "no advertise <ribout>" stops advertising it in later sessions; it does not withdraw what was sent.
    if (cmd_ctx->is_no_command) {
        for (int i = 0; i < neighbor->advertise_count; i++) {
            if (strcmp(neighbor->advertise[i], ribout) == 0) {
                memmove(neighbor->advertise[i], neighbor->advertise[i + 1],
                        (size_t)(neighbor->advertise_count - i - 1) * sizeof(neighbor->advertise[0]));
                neighbor->advertise_count--;
                if (neighbor->tx) {
                    bgp_peer_tx_clear_withheld(neighbor->tx, ribout);
                }
                break;
            }
        }
        return 0;
    }

    for (int i = 0; i < neighbor->advertise_count; i++) {
        if (strcmp(neighbor->advertise[i], ribout) == 0) {
            return 0;
        }
    }
    char (*names)[BGP_NEIGHBOR_RIBOUT_NAME] = neighbor->advertise_count == INT_MAX ? NULL :
        array_reserve(neighbor->advertise, sizeof(*names), &neighbor->advertise_capacity, neighbor->advertise_count + 1);
    if (!names) {
        fprintf(stderr, "Error: no memory for standing advertisement\n");
        return -1;
    }
    neighbor->advertise = names;
    snprintf(neighbor->advertise[neighbor->advertise_count], sizeof(neighbor->advertise[0]), "%.*s",
             BGP_NEIGHBOR_RIBOUT_NAME - 1, ribout);
    neighbor->advertise_count++;
    tx_standing_added(neighbor, ribout);
    return 0;
}

/*
 * Neighbor "[no] address-family <family>": switch one MP-BGP family of the neighbor, named as in bgp_families[].
 */
int cmd_handle_address_family(void *ctx, match_result_t *result) {
    cmd_ctx_t          *cmd_ctx = (cmd_ctx_t *)ctx;
    char                af_name[32];
    const bgp_family_t *af;

    if (!command_require_neighbor(cmd_ctx, "address-family")) {
        return -1;
    }

    if (command_extract_keyword_tail(result, "address-family",
                                     af_name, sizeof(af_name)) < 0 ||
        af_name[0] == '\0') {
        fprintf(stderr, "Error: Address family type not specified\n");
        return -1;
    }

    af = bgp_family_find(af_name);
    if (!af || af->mp_offset == NO_CAP_OFFSET) {
        fprintf(stderr, "Error: Unknown address family '%s'\n", af_name);
        return -1;
    }

    bgp_capabilities_t caps = cmd_ctx->current_neighbor->capabilities;
    *(int *)((char *)&caps + af->mp_offset) = !cmd_ctx->is_no_command;
    return bgp_neighbor_apply_capabilities(cmd_ctx->current_neighbor, &caps);
}

int cmd_handle_capability_graceful_restart(void *ctx, match_result_t *result) {
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;

    if (!command_require_neighbor(cmd_ctx, "capability")) {
        return -1;
    }

    bgp_capabilities_t caps = cmd_ctx->current_neighbor->capabilities;
    caps.graceful_restart = !cmd_ctx->is_no_command;
    caps.restart_time = 0;
    if (caps.graceful_restart && !match_get_uint32(result, "restart-time", &caps.restart_time)) {
        caps.restart_time = 120;
    }
    return bgp_neighbor_apply_capabilities(cmd_ctx->current_neighbor, &caps);
}

/*
 * Neighbor "[no] capability add-path [<family>]": ADD-PATH send and receive for one family, or for all families that
 * support it.
 */
int cmd_handle_capability_add_path(void *ctx, match_result_t *result) {
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;
    char       af_name[32];
    uint8_t    mode = cmd_ctx->is_no_command ? 0 :
                   (ADD_PATH_SEND | ADD_PATH_RECEIVE);

    if (!command_require_neighbor(cmd_ctx, "capability")) {
        return -1;
    }

    if (command_extract_keyword_tail(result, "add-path",
                                     af_name, sizeof(af_name)) < 0) {
        fprintf(stderr, "Error: Invalid add-path command\n");
        return -1;
    }

    const bgp_family_t *af = bgp_family_find(af_name);
    if (af_name[0] && (!af || af->add_path_offset == NO_CAP_OFFSET)) {
        fprintf(stderr, "Error: Unknown add-path address family '%s'\n", af_name);
        return -1;
    }

    bgp_capabilities_t caps = cmd_ctx->current_neighbor->capabilities;
    for (int i = 0; i < BGP_NUM_FAMILIES; i++) {
        if (!af || af == &bgp_families[i]) {
            bgp_caps_set_add_path(&caps, bgp_families[i].afi, bgp_families[i].safi, mode);
        }
    }
    return bgp_neighbor_apply_capabilities(cmd_ctx->current_neighbor, &caps);
}

/*
 * Neighbor "[no] capability ext-nh [<family>]": RFC 8950 extended next hop for one family, or for all families that
 * support it.
 */
int cmd_handle_capability_ext_nh(void *ctx, match_result_t *result) {
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;
    char       af_name[32];
    int        enabled = cmd_ctx->is_no_command ? 0 : 1;

    if (!command_require_neighbor(cmd_ctx, "capability")) {
        return -1;
    }

    if (command_extract_keyword_tail(result, "ext-nh",
                                     af_name, sizeof(af_name)) < 0) {
        fprintf(stderr, "Error: Invalid ext-nh command\n");
        return -1;
    }

    const bgp_family_t *af = bgp_family_find(af_name);
    if (af_name[0] && !af) {
        fprintf(stderr, "Error: Unknown ext-nh address family '%s'\n", af_name);
        return -1;
    }
    if (af && af->ext_nh_offset == NO_CAP_OFFSET) {
        fprintf(stderr, "Error: Address family '%s' does not support ext-nh\n", af_name);
        return -1;
    }

    bgp_capabilities_t caps = cmd_ctx->current_neighbor->capabilities;
    for (int i = 0; i < BGP_NUM_FAMILIES; i++) {
        if (!af || af == &bgp_families[i]) {
            bgp_caps_set_ext_nh(&caps, bgp_families[i].afi, bgp_families[i].safi, AFI_IPV6, enabled);
        }
    }
    return bgp_neighbor_apply_capabilities(cmd_ctx->current_neighbor, &caps);
}

int cmd_handle_capability_route_refresh(void *ctx, match_result_t *result) {
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;
    (void)result;

    if (!command_require_neighbor(cmd_ctx, "capability")) {
        return -1;
    }

    bgp_capabilities_t caps = cmd_ctx->current_neighbor->capabilities;
    caps.route_refresh = !cmd_ctx->is_no_command;
    return bgp_neighbor_apply_capabilities(cmd_ctx->current_neighbor, &caps);
}

/*
 * "hold-time <seconds>" sets the hold time proposed in OPEN; "no hold-time" restores the default.
 */
int cmd_handle_hold_time(void *ctx, match_result_t *result) {
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;
    uint32_t   seconds = BGP_HOLD_TIME;

    if (!command_require_neighbor(cmd_ctx, "hold-time")) {
        return -1;
    }
    if (!cmd_ctx->is_no_command && !match_get_uint32(result, "seconds", &seconds)) {
        return command_error("hold-time needs a number of seconds");
    }
    return bgp_neighbor_set_hold_time(cmd_ctx->current_neighbor, seconds);
}

/*
 * "shutdown [text]" holds the neighbor down, with the text as the Shutdown Communication; "no shutdown" connects again.
 */
int cmd_handle_neighbor_shutdown(void *ctx, match_result_t *result) {
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;

    if (!command_require_neighbor(cmd_ctx, "shutdown")) {
        return -1;
    }
    return bgp_neighbor_set_shutdown(cmd_ctx->current_neighbor, !cmd_ctx->is_no_command, result->tail);
}

/*
 * "ttl-security hops <n>" turns on the Generalized TTL Security Mechanism; "no ttl-security" turns it off.
 */
int cmd_handle_ttl_security(void *ctx, match_result_t *result) {
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;
    uint32_t   hops = 0;

    if (!command_require_neighbor(cmd_ctx, "ttl-security")) {
        return -1;
    }
    if (!cmd_ctx->is_no_command && (!match_get_uint32(result, "hops", &hops) || hops == 0)) {
        return command_error("ttl-security hops is 1-254");
    }
    return bgp_neighbor_set_ttl_security(cmd_ctx->current_neighbor, hops);
}

/*
 * "password <text>" sets the TCP MD5 key of the session; "no password" removes it.
 */
int cmd_handle_password(void *ctx, match_result_t *result) {
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;

    if (!command_require_neighbor(cmd_ctx, "password")) {
        return -1;
    }
    if (!cmd_ctx->is_no_command && result->tail[0] == '\0') {
        return command_error("password needs a text");
    }
    return bgp_neighbor_set_password(cmd_ctx->current_neighbor, cmd_ctx->is_no_command ? "" : result->tail);
}

int cmd_handle_capability_extended_message(void *ctx, match_result_t *result) {
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;
    (void)result;

    if (!command_require_neighbor(cmd_ctx, "capability")) {
        return -1;
    }

    bgp_capabilities_t caps = cmd_ctx->current_neighbor->capabilities;
    caps.extended_message = !cmd_ctx->is_no_command;
    return bgp_neighbor_apply_capabilities(cmd_ctx->current_neighbor, &caps);
}

int cmd_handle_capability_four_byte_asn(void *ctx, match_result_t *result) {
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;

    (void)result;

    if (!command_require_neighbor(cmd_ctx, "capability") ||
        !cmd_ctx->current_router) {
        return -1;
    }

    bgp_capabilities_t caps = cmd_ctx->current_neighbor->capabilities;
    caps.four_byte_asn = !cmd_ctx->is_no_command;
    return bgp_neighbor_apply_capabilities(cmd_ctx->current_neighbor, &caps);
}

/*
 * "ribout <name>" opens (or creates) a ribout block and enters ribout mode; "no ribout <name>" removes it.
 */
int cmd_handle_ribout(void *ctx, match_result_t *result) {
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;
    char       name[64];

    if (!match_get_string(result, "name", name, sizeof(name)) || !bgp_ribout_name_valid(name)) {
        fprintf(stderr, "Error: invalid ribout name (maximum %d characters; letters, digits, '.', '_' or '-')\n",
                BGP_RIBOUT_NAME_SIZE - 1);
        return -1;
    }

    if (cmd_ctx->is_no_command) {
        // Find and remove the ribout
        bgp_ribout_config_t *block = bgp_sim_find_ribout(cmd_ctx->sim, name);
        if (!block) {
            fprintf(stderr, "Error: ribout '%s' not found\n", name);
            return -1;
        }
        bgp_sim_remove_ribout(cmd_ctx->sim, name);
        cmd_ctx->current_ribout = NULL;
        log_write("Removed ribout block '%s'\n", name);
        return 0;
    } else {
        // Create or find ribout
        bgp_ribout_config_t *existing = bgp_sim_find_ribout(cmd_ctx->sim, name);
        if (existing) {
            cmd_ctx->current_ribout = existing;
            cmd_push_mode(cmd_ctx, CONFIG_MODE_RIBOUT);
            return 0;
        }

        // Create new ribout
        bgp_ribout_config_t *block = bgp_sim_add_ribout(cmd_ctx->sim, name);
        if (!block) {
            fprintf(stderr, "Error: Failed to allocate ribout '%s'\n", name);
            return -1;
        }
        cmd_ctx->current_ribout = block;
        // Enter ribout mode
        cmd_push_mode(cmd_ctx, CONFIG_MODE_RIBOUT);
        log_write("Created ribout block '%s'\n", name);
        return 0;
    }
}

static int ribout_tail_handler(cmd_ctx_t *ctx, match_result_t *result, const char *keyword) {
    if (!ctx->current_ribout) {
        fprintf(stderr, "Error: No ribout context\n");
        return -1;
    }
    int rc = bgp_ribout_edit(ctx->current_ribout, keyword, result->tail, ctx->is_no_command);
    if (rc == 0 && ctx->is_no_command)
        printf("Reset %s in ribout block '%s'\n", keyword, ctx->current_ribout->name);
    return rc;
}

#define RIBOUT_HANDLER(name, keyword)                              \
int name(void *ctx, match_result_t *result) {                      \
    return ribout_tail_handler((cmd_ctx_t *)ctx, result, keyword); \
}

RIBOUT_HANDLER(cmd_handle_ribout_prefix, "prefix")
RIBOUT_HANDLER(cmd_handle_ribout_rd, "rd")
RIBOUT_HANDLER(cmd_handle_ribout_label, "label")
RIBOUT_HANDLER(cmd_handle_ribout_label2, "label2")
RIBOUT_HANDLER(cmd_handle_ribout_ethernet_tag, "ethernet-tag")
RIBOUT_HANDLER(cmd_handle_ribout_mac, "mac")
RIBOUT_HANDLER(cmd_handle_ribout_ip, "ip")
RIBOUT_HANDLER(cmd_handle_ribout_path_id, "path-id")
RIBOUT_HANDLER(cmd_handle_ribout_next_hop, "next-hop")
RIBOUT_HANDLER(cmd_handle_ribout_gateway_ip, "gateway-ip")
RIBOUT_HANDLER(cmd_handle_ribout_esi, "esi")
RIBOUT_HANDLER(cmd_handle_ribout_aspath, "as-path")
RIBOUT_HANDLER(cmd_handle_ribout_localpref, "localpref")
RIBOUT_HANDLER(cmd_handle_ribout_med, "med")
RIBOUT_HANDLER(cmd_handle_ribout_rt, "rt")
RIBOUT_HANDLER(cmd_handle_ribout_rt_set, "rt-set")
RIBOUT_HANDLER(cmd_handle_ribout_community, "community")
RIBOUT_HANDLER(cmd_handle_ribout_large_community, "large-community")
RIBOUT_HANDLER(cmd_handle_ribout_rotate_every, "rotate-every")
RIBOUT_HANDLER(cmd_handle_ribout_rotate_period, "rotate-period")
RIBOUT_HANDLER(cmd_handle_ribout_message_size, "message-size")
RIBOUT_HANDLER(cmd_handle_ribout_soo, "soo")
RIBOUT_HANDLER(cmd_handle_ribout_encap, "encap")
RIBOUT_HANDLER(cmd_handle_ribout_router_mac, "router-mac")
RIBOUT_HANDLER(cmd_handle_ribout_origin, "origin")
RIBOUT_HANDLER(cmd_handle_ribout_distinguisher, "distinguisher")
RIBOUT_HANDLER(cmd_handle_ribout_color, "color")
RIBOUT_HANDLER(cmd_handle_ribout_endpoint, "endpoint")
RIBOUT_HANDLER(cmd_handle_ribout_enlp, "enlp")
RIBOUT_HANDLER(cmd_handle_ribout_priority, "priority")
RIBOUT_HANDLER(cmd_handle_ribout_preference, "preference")
RIBOUT_HANDLER(cmd_handle_ribout_binding_sid, "binding-sid")
RIBOUT_HANDLER(cmd_handle_ribout_segment_list, "segment-list")
RIBOUT_HANDLER(cmd_handle_ribout_address_family, "address-family")
RIBOUT_HANDLER(cmd_handle_ribout_nlri, "nlri")
RIBOUT_HANDLER(cmd_handle_ribout_pmsi, "pmsi")
RIBOUT_HANDLER(cmd_handle_ribout_l2_info, "l2-info")
RIBOUT_HANDLER(cmd_handle_ribout_esi_label, "esi-label")
RIBOUT_HANDLER(cmd_handle_ribout_es_import, "es-import")
RIBOUT_HANDLER(cmd_handle_ribout_link_bandwidth, "link-bandwidth")
RIBOUT_HANDLER(cmd_handle_ribout_mac_mobility, "mac-mobility")
RIBOUT_HANDLER(cmd_handle_ribout_default_gateway, "default-gateway")
RIBOUT_HANDLER(cmd_handle_ribout_ext_community, "ext-community")
RIBOUT_HANDLER(cmd_handle_ribout_ls_attribute, "ls-attribute")
RIBOUT_HANDLER(cmd_handle_ribout_ls, "ls")
RIBOUT_HANDLER(cmd_handle_ribout_aggregator, "aggregator")
RIBOUT_HANDLER(cmd_handle_ribout_atomic_aggregate, "atomic-aggregate")
RIBOUT_HANDLER(cmd_handle_ribout_originator_id, "originator-id")
RIBOUT_HANDLER(cmd_handle_ribout_cluster_list, "cluster-list")
RIBOUT_HANDLER(cmd_handle_ribout_aigp, "aigp")
RIBOUT_HANDLER(cmd_handle_ribout_otc, "otc")
RIBOUT_HANDLER(cmd_handle_ribout_prefix_sid, "prefix-sid")
RIBOUT_HANDLER(cmd_handle_ribout_attribute, "attribute")
#undef RIBOUT_HANDLER

// Help text of the FlowSpec action kinds.
#define RIBOUT_FLOWSPEC_ACTION_HELP                                                            \
    "redirect-ip <addr>... [copy] | redirect-ip <addr> x <n> [copy] | redirect-vrf <rt>... | " \
    "mark <dscp>... | mark <dscp> x <n> | traffic-rate bytes|packets <rate> [as <asn>] | "     \
    "traffic-action [terminal] [sample] | redirect-next-hop [copy] | interface-set <asn>:<group> [in] [out]"

/*
 * "action ..." lines: each one adds a community to every FlowSpec route of the block; a value list rotates, one value
 * per path. "no action" removes all lines.
 */
int cmd_handle_ribout_action(void *ctx, match_result_t *result) {
    return ribout_tail_handler(ctx, result, "action");
}

/*
 * FlowSpec components (src-prefix and the operator components): one handler per keyword, all with the same tail
 * logic. "no <keyword>" removes the component.
 */
static int ribout_flowspec_component_handler(cmd_ctx_t *cmd_ctx, match_result_t *result, const char *keyword) {
    return ribout_tail_handler(cmd_ctx, result, keyword);
}

// One handler per FlowSpec component keyword; each passes its keyword to ribout_flowspec_component_handler.
#define RIBOUT_FLOWSPEC_COMPONENT_HANDLER(name, keyword)                         \
static int name(void *ctx, match_result_t *result) {                             \
    return ribout_flowspec_component_handler((cmd_ctx_t *)ctx, result, keyword); \
}

RIBOUT_FLOWSPEC_COMPONENT_HANDLER(cmd_handle_ribout_src_prefix, "src-prefix")
#define RIBOUT_OP_COMPONENT_HANDLER(id, kw, type, bitmask, help) \
    RIBOUT_FLOWSPEC_COMPONENT_HANDLER(cmd_handle_ribout_op_component_##id, kw)
BGP_RIBOUT_FLOWSPEC_OP_COMPONENTS(RIBOUT_OP_COMPONENT_HANDLER)
#undef RIBOUT_OP_COMPONENT_HANDLER

/*
 * CLI-only commands
 */
int cmd_handle_shutdown(void *ctx, match_result_t *result) {
    (void)result;
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;
    printf("Shutting down...\n");
    if (cmd_ctx->sim) {
        cmd_ctx->sim->shutdown = 1;
    }
    return 0;
}

int cmd_handle_show_bgp_summary(void *ctx, match_result_t *result) {
    (void)result;
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;
    cli_show_routers(cmd_ctx->sim);
    return 0;
}

int cmd_handle_show_bgp_neighbors(void *ctx, match_result_t *result) {
    (void)result;
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;
    cli_show_neighbors(cmd_ctx->sim, 0);
    return 0;
}

int cmd_handle_show_bgp_neighbors_as(void *ctx, match_result_t *result) {
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;
    uint32_t   as_number = 0;
    match_get_uint32(result, "AS", &as_number);
    cli_show_neighbors(cmd_ctx->sim, as_number);
    return 0;
}

int cmd_handle_config_mode(void *ctx, match_result_t *result) {
    (void)result;
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;
    if (cmd_ctx->mode) {
        *cmd_ctx->mode = CLI_MODE_CONFIG;
        printf("Entering configuration mode.\n");
    }
    return 0;
}

int cmd_handle_show_config(void *ctx, match_result_t *result) {
    (void)result;
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;
    cli_show_config(cmd_ctx->sim);
    return 0;
}

int cmd_handle_show_log(void *ctx, match_result_t *result) {
    (void)ctx;
    (void)result;
    show_log(20);
    return 0;
}

int cmd_handle_show_log_all(void *ctx, match_result_t *result) {
    (void)ctx;
    (void)result;
    show_log(0);
    return 0;
}

int cmd_handle_terminal_monitor(void *ctx, match_result_t *result) {
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;

    (void)result;

    if (!cmd_ctx->session) {
        return 0;
    }

    cmd_ctx->session->terminal_monitor = cmd_ctx->is_no_command ? 0 : 1;
    printf("Terminal monitor %s.\n", cmd_ctx->session->terminal_monitor ? "enabled" : "disabled");
    return 0;
}

int cmd_handle_show_ribout(void *ctx, match_result_t *result) {
    (void)result;
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;
    cli_show_ribout(cmd_ctx->sim);
    return 0;
}

int cmd_handle_show_ribout_name(void *ctx, match_result_t *result) {
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;
    char       name[64] = "";
    match_get_string(result, "name", name, sizeof(name));
    cli_show_ribout_detail(cmd_ctx->sim, name);
    return 0;
}

int cmd_handle_show_ribout_preview(void *ctx, match_result_t *result) {
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;
    char       name[64] = "";
    uint32_t   count = 10;
    match_get_string(result, "name", name, sizeof(name));
    match_get_uint32(result, "count", &count);
    cli_show_ribout_preview(cmd_ctx->sim, name, (int)count);
    return 0;
}

/*
 * Handle 'show ribout <name> detail' - shows map detail
 */
int cmd_handle_show_ribout_map(void *ctx, match_result_t *result) {
    (void)result;
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;
    cli_show_ribout_map_summary(cmd_ctx->sim);
    return 0;
}

int cmd_handle_show_ribout_map_name(void *ctx, match_result_t *result) {
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;
    char       name[64] = "";
    match_get_string(result, "name", name, sizeof(name));
    cli_show_ribout_map_detail(cmd_ctx->sim, name);
    return 0;
}

/*
 * Handle 'exit' - go up one level in hierarchy using mode stack
 */
int cmd_handle_exit_config(void *ctx, match_result_t *result) {
    (void)result;
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;

    // Clear context based on mode we're leaving
    switch (cmd_ctx->config_mode) {
        case CONFIG_MODE_NEIGHBOR:
            cmd_ctx->current_neighbor = NULL;
            if (cmd_ctx->mode) {
                printf("Exiting neighbor configuration mode.\n");
            }
            break;
        case CONFIG_MODE_ROUTER_BGP:
            cmd_ctx->current_router = NULL;
            cmd_ctx->current_neighbor = NULL;
            if (cmd_ctx->mode) {
                printf("Exiting router configuration mode.\n");
            }
            break;
        case CONFIG_MODE_RIBOUT:
            cmd_ctx->current_ribout = NULL;
            if (cmd_ctx->mode) {
                printf("Exiting ribout configuration mode.\n");
            }
            break;
        case CONFIG_MODE_GLOBAL:
            // Exiting global config -> go to EXEC mode
            if (cmd_ctx->mode) {
                *cmd_ctx->mode = CLI_MODE_EXEC;
            }
            cmd_ctx->mode_stack_depth = 0;  /* Clear stack */
            if (cmd_ctx->mode) {
                printf("Exiting configuration mode.\n");
            }
            return 0;
        case CONFIG_MODE_SCRIPT:
            cmd_ctx->current_script_name[0] = '\0';
            break;
    }

    // Pop back to parent mode using stack
    cmd_pop_mode(cmd_ctx);

    return 0;
}

/*
 * Handle 'end' - always go back to EXEC mode
 */
int cmd_handle_end_config(void *ctx, match_result_t *result) {
    (void)result;
    cmd_ctx_t *cmd_ctx = (cmd_ctx_t *)ctx;

    // Reset config state unconditionally
    cmd_ctx->config_mode = CONFIG_MODE_GLOBAL;
    cmd_ctx->mode_stack_depth = 0;
    cmd_ctx->current_router = NULL;
    cmd_ctx->current_neighbor = NULL;
    cmd_ctx->current_ribout = NULL;

    cmd_ctx->current_script_name[0] = '\0';

    // CLI-only: switch to exec mode and notify
    if (cmd_ctx->mode) {
        *cmd_ctx->mode = CLI_MODE_EXEC;
        printf("Exiting configuration mode.\n");
    }
    return 0;
}

int cmd_parse_scope(match_result_t *result, bgp_scope_t *scope) {
    memset(scope, 0, sizeof(*scope));
    if (match_get_uint32(result, "router", &scope->router_as) && scope->router_as == 0) {
        fprintf(stderr, "Error: Router AS must not be 0\n");
        return -1;
    }
    if (match_get_string(result, "vrf", scope->vrf, sizeof(scope->vrf)) && !vrf_name_valid(scope->vrf)) {
        fprintf(stderr, "Error: Invalid VRF name: %s\n", scope->vrf);
        return -1;
    }
    return 0;
}

/*
 * clear bgp [router <AS> | vrf <name|all|default>] <neighbor|*> [cease [text]]
 *
 * Without "cease" the TCP connection is closed with no NOTIFICATION. With it the peer first gets Cease /
 * Administrative Reset, with the text as its Shutdown Communication.
 */
int cmd_handle_clear_bgp_neighbor(void *ctx, match_result_t *result) {
    cmd_ctx_t       *cmd_ctx = (cmd_ctx_t *)ctx;
    char             neighbor_ip[INET6_ADDRSTRLEN] = "";
    bgp_scope_t      scope;
    bgp_neighbor_t **neighbors;
    size_t           count;
    int              routers;

    // Get the neighbor IP from matched tokens
    if (!match_get_string(result, "neighbor-ip", neighbor_ip,
                          sizeof(neighbor_ip))) {
        fprintf(stderr, "Error: Neighbor IP not specified\n");
        return -1;
    }
    if (cmd_parse_scope(result, &scope) < 0) {
        return -1;
    }

    int all = strcmp(neighbor_ip, "*") == 0;
    int cease = match_has_keyword(result, "cease");

    neighbors = bgp_scope_neighbors(cmd_ctx->sim, &scope, all ? "all" : neighbor_ip, &count, &routers);
    if (!neighbors) {
        fprintf(stderr, "Error: no memory\n");
        return -1;
    }
    if (cease && strlen(result->tail) > 255) {
        free(neighbors);
        return command_error("a Shutdown Communication is at most 255 octets");
    }
    for (size_t i = 0; i < count; i++) {
        if (cease) {
            bgpsim_runtime_cease_neighbor(neighbors[i], result->tail);
        } else {
            bgp_clear_neighbor(neighbors[i]);
        }
    }
    free(neighbors);

    if (all && routers == 0 && (scope.router_as != 0 || scope.vrf[0])) {
        fprintf(stderr, "Error: No router matches this scope\n");
        return -1;
    }
    if (all) {
        printf("Cleared %zu BGP session(s)\n", count);
        return 0;
    }
    if (count == 0) {
        printf("No BGP neighbor %s found\n", neighbor_ip);
        return -1;
    }
    printf("Cleared %zu BGP session(s) with %s\n", count, neighbor_ip);
    return 0;
}

// Generate ribout for a specific ribout
/*
 * NOTE: Manual "generate ribout" commands and auto-generation have been removed.
 * Ribout maps must now be generated explicitly via a future implementation
 * (e.g., on mode exit or via explicit command).
 */

// Command Definition Arrays

// Exit/end commands shared across all config modes
#define CONFIG_EXIT_COMMANDS                            \
    {                                                   \
        "exit",                                         \
        {                                               \
            {.type = TOKEN_KEYWORD, .keyword = "exit"}, \
            {.type = TOKEN_END}                         \
        },                                              \
        cmd_handle_exit_config,                         \
        "Exit current configuration level",             \
        0                                               \
    },                                                  \
    {                                                   \
        "end",                                          \
        {                                               \
            {.type = TOKEN_KEYWORD, .keyword = "end"},  \
            {.type = TOKEN_END}                         \
        },                                              \
        cmd_handle_end_config,                          \
        "Exit to privileged EXEC mode",                 \
        0                                               \
    }

/*
 * Global configuration commands
 */
static cmd_def_t global_config_commands[] = {
    {
        "script <name>",
        {
            {TOKEN_KEYWORD, "script"},
            {TOKEN_STRING, NULL, "name", "name", "Script name"},
            {TOKEN_END}
        },
        cmd_handle_script,
        "Define or select a script; no script <name> removes it",
        1
    },
    {
        "router bgp <AS>",
        {
            {.type = TOKEN_KEYWORD, .keyword = "router"},
            {.type = TOKEN_KEYWORD, .keyword = "bgp"},
            {TOKEN_UINT32, NULL, "AS", "AS", "AS number (1-4294967295)"},
            {.type = TOKEN_END}
        },
        cmd_handle_router_bgp,
        "Configure BGP routing",
        1
    },
    {
        "ribout <name>",
        {
            {.type = TOKEN_KEYWORD, .keyword = "ribout"},
            {TOKEN_STRING, NULL, "name", "name", "ribout name"},
            {.type = TOKEN_END}
        },
        cmd_handle_ribout,
        "Configure ribout and enter ribout mode",
        1
    },
    CONFIG_EXIT_COMMANDS,
};

/*
 * Router BGP configuration commands
 */
static cmd_def_t router_bgp_commands[] = {
    {
        "router-id <router-id>",
        {
            {.type = TOKEN_KEYWORD, .keyword = "router-id"},
            {TOKEN_IP_ADDRESS, NULL, "router-id", "router-id", "Router ID IPv4 address"},
            {.type = TOKEN_END}
        },
        cmd_handle_router_id,
        "Set router ID",
        0
    },
    {
        "vrf <name>",
        {
            {.type = TOKEN_KEYWORD, .keyword = "vrf"},
            {TOKEN_STRING, NULL, "name", "name", "Existing network namespace name"},
            {.type = TOKEN_END}
        },
        cmd_handle_vrf,
        "Open this router's sockets in an existing network namespace",
        1
    },
    {
        "vrf",
        {
            {.type = TOKEN_KEYWORD, .keyword = "vrf"},
            {.type = TOKEN_END}
        },
        cmd_handle_vrf,
        "Return this router to bgpsim's own namespace with no vrf",
        1,
        1
    },
    {
        "update-source <source-ip>",
        {
            {.type = TOKEN_KEYWORD, .keyword = "update-source"},
            {TOKEN_IP_ADDRESS, NULL, "source-ip", "source-ip", "Update-source IP address"},
            {.type = TOKEN_END}
        },
        cmd_handle_update_source,
        "Set update source IP",
        1
    },
    {
        "neighbor <ip> remote-as <AS>",
        {
            {.type = TOKEN_KEYWORD, .keyword = "neighbor"},
            {TOKEN_IP_ADDRESS, NULL, "neighbor-ip", "ip", "Neighbor IP address"},
            {.type = TOKEN_KEYWORD, .keyword = "remote-as"},
            {TOKEN_UINT32, NULL, "remote-as", "AS", "Remote AS number (1-4294967295)"},
            {.type = TOKEN_END}
        },
        cmd_handle_neighbor,
        "Configure BGP neighbor and enter neighbor mode",
        1
    },
    CONFIG_EXIT_COMMANDS,
};

/*
 * Neighbor configuration commands
 */
static cmd_def_t neighbor_commands[] = {
    {
        "update-source <source-ip>",
        {
            {.type = TOKEN_KEYWORD, .keyword = "update-source"},
            {TOKEN_IP_ADDRESS, NULL, "source-ip", "source-ip", "Update-source IP address"},
            {.type = TOKEN_END}
        },
        cmd_handle_update_source,
        "Set update source IP",
        1
    },
    {
        "advertise <ribout>",
        {
            {.type = TOKEN_KEYWORD, .keyword = "advertise"},
            {TOKEN_STRING, NULL, "ribout", "ribout", "ribout name"},
            {.type = TOKEN_END}
        },
        cmd_handle_advertise,
        "Configure advertise <ribout> to a neighbor",
        1
    },
    {
        "address-family ipv4",
        {
            {.type = TOKEN_KEYWORD, .keyword = "address-family"},
            {.type = TOKEN_KEYWORD, .keyword = "ipv4"},
            {.type = TOKEN_END}
        },
        cmd_handle_address_family,
        "Enable IPv4 unicast address family",
        1
    },
    {
        "address-family ipv4 labels",
        {
            {.type = TOKEN_KEYWORD, .keyword = "address-family"},
            {.type = TOKEN_KEYWORD, .keyword = "ipv4"},
            {.type = TOKEN_KEYWORD, .keyword = "labels"},
            {.type = TOKEN_END}
        },
        cmd_handle_address_family,
        "Enable IPv4 labeled-unicast address family",
        1
    },
    {
        "address-family ipv6",
        {
            {.type = TOKEN_KEYWORD, .keyword = "address-family"},
            {.type = TOKEN_KEYWORD, .keyword = "ipv6"},
            {.type = TOKEN_END}
        },
        cmd_handle_address_family,
        "Enable IPv6 unicast address family",
        1
    },
    {
        "address-family ipv6 labels",
        {
            {.type = TOKEN_KEYWORD, .keyword = "address-family"},
            {.type = TOKEN_KEYWORD, .keyword = "ipv6"},
            {.type = TOKEN_KEYWORD, .keyword = "labels"},
            {.type = TOKEN_END}
        },
        cmd_handle_address_family,
        "Enable IPv6 labeled-unicast address family",
        1
    },
    {
        "address-family vpnv4",
        {
            {.type = TOKEN_KEYWORD, .keyword = "address-family"},
            {.type = TOKEN_KEYWORD, .keyword = "vpnv4"},
            {.type = TOKEN_END}
        },
        cmd_handle_address_family,
        "Enable VPNv4 unicast address family",
        1
    },
    {
        "address-family vpnv6",
        {
            {.type = TOKEN_KEYWORD, .keyword = "address-family"},
            {.type = TOKEN_KEYWORD, .keyword = "vpnv6"},
            {.type = TOKEN_END}
        },
        cmd_handle_address_family,
        "Enable VPNv6 unicast address family",
        1
    },
    {
        "address-family l2vpn evpn",
        {
            {.type = TOKEN_KEYWORD, .keyword = "address-family"},
            {.type = TOKEN_KEYWORD, .keyword = "l2vpn"},
            {.type = TOKEN_KEYWORD, .keyword = "evpn"},
            {.type = TOKEN_END}
        },
        cmd_handle_address_family,
        "Enable L2VPN EVPN address family",
        1
    },
    {
        "address-family ipv4 flowspec",
        {
            {.type = TOKEN_KEYWORD, .keyword = "address-family"},
            {.type = TOKEN_KEYWORD, .keyword = "ipv4"},
            {.type = TOKEN_KEYWORD, .keyword = "flowspec"},
            {.type = TOKEN_END}
        },
        cmd_handle_address_family,
        "Enable IPv4 FlowSpec address family",
        1
    },
    {
        "address-family ipv4 flowspec-vpn",
        {
            {.type = TOKEN_KEYWORD, .keyword = "address-family"},
            {.type = TOKEN_KEYWORD, .keyword = "ipv4"},
            {.type = TOKEN_KEYWORD, .keyword = "flowspec-vpn"},
            {.type = TOKEN_END}
        },
        cmd_handle_address_family,
        "Enable IPv4 VPN FlowSpec address family",
        1
    },
    {
        "address-family ipv6 flowspec",
        {
            {.type = TOKEN_KEYWORD, .keyword = "address-family"},
            {.type = TOKEN_KEYWORD, .keyword = "ipv6"},
            {.type = TOKEN_KEYWORD, .keyword = "flowspec"},
            {.type = TOKEN_END}
        },
        cmd_handle_address_family,
        "Enable IPv6 FlowSpec address family",
        1
    },
    {
        "address-family ipv6 flowspec-vpn",
        {
            {.type = TOKEN_KEYWORD, .keyword = "address-family"},
            {.type = TOKEN_KEYWORD, .keyword = "ipv6"},
            {.type = TOKEN_KEYWORD, .keyword = "flowspec-vpn"},
            {.type = TOKEN_END}
        },
        cmd_handle_address_family,
        "Enable IPv6 VPN FlowSpec address family",
        1
    },
    {
        "address-family ipv4 srpolicy",
        {
            {.type = TOKEN_KEYWORD, .keyword = "address-family"},
            {.type = TOKEN_KEYWORD, .keyword = "ipv4"},
            {.type = TOKEN_KEYWORD, .keyword = "srpolicy"},
            {.type = TOKEN_END}
        },
        cmd_handle_address_family,
        "Enable IPv4 SR Policy address family",
        1
    },
    {
        "address-family ipv6 srpolicy",
        {
            {.type = TOKEN_KEYWORD, .keyword = "address-family"},
            {.type = TOKEN_KEYWORD, .keyword = "ipv6"},
            {.type = TOKEN_KEYWORD, .keyword = "srpolicy"},
            {.type = TOKEN_END}
        },
        cmd_handle_address_family,
        "Enable IPv6 SR Policy address family",
        1
    },
    {
        "address-family bgp-ls",
        {
            {.type = TOKEN_KEYWORD, .keyword = "address-family"},
            {.type = TOKEN_KEYWORD, .keyword = "bgp-ls"},
            {.type = TOKEN_END}
        },
        cmd_handle_address_family,
        "Enable BGP Link-State address family",
        1
    },
    {
        "address-family ipv4 mvpn",
        {
            {.type = TOKEN_KEYWORD, .keyword = "address-family"},
            {.type = TOKEN_KEYWORD, .keyword = "ipv4"},
            {.type = TOKEN_KEYWORD, .keyword = "mvpn"},
            {.type = TOKEN_END}
        },
        cmd_handle_address_family,
        "Enable IPv4 MVPN address family",
        1
    },
    {
        "address-family ipv6 mvpn",
        {
            {.type = TOKEN_KEYWORD, .keyword = "address-family"},
            {.type = TOKEN_KEYWORD, .keyword = "ipv6"},
            {.type = TOKEN_KEYWORD, .keyword = "mvpn"},
            {.type = TOKEN_END}
        },
        cmd_handle_address_family,
        "Enable IPv6 MVPN address family",
        1
    },
    {
        "address-family ipv4 rtc",
        {
            {.type = TOKEN_KEYWORD, .keyword = "address-family"},
            {.type = TOKEN_KEYWORD, .keyword = "ipv4"},
            {.type = TOKEN_KEYWORD, .keyword = "rtc"},
            {.type = TOKEN_END}
        },
        cmd_handle_address_family,
        "Enable Route Target Constraint address family",
        1
    },
    {
        "address-family l2vpn vpls",
        {
            {.type = TOKEN_KEYWORD, .keyword = "address-family"},
            {.type = TOKEN_KEYWORD, .keyword = "l2vpn"},
            {.type = TOKEN_KEYWORD, .keyword = "vpls"},
            {.type = TOKEN_END}
        },
        cmd_handle_address_family,
        "Enable L2VPN VPLS address family",
        1
    },
    {
        "capability graceful-restart",
        {
            {.type = TOKEN_KEYWORD, .keyword = "capability"},
            {.type = TOKEN_KEYWORD, .keyword = "graceful-restart"},
            {.type = TOKEN_END}
        },
        cmd_handle_capability_graceful_restart,
        "Enable graceful restart capability",
        1
    },
    {
        "capability graceful-restart restart-time <time>",
        {
            {.type = TOKEN_KEYWORD, .keyword = "capability"},
            {.type = TOKEN_KEYWORD, .keyword = "graceful-restart"},
            {.type = TOKEN_KEYWORD, .keyword = "restart-time"},
            {TOKEN_UINT32, NULL, "restart-time", "time", "Restart time in seconds"},
            {.type = TOKEN_END}
        },
        cmd_handle_capability_graceful_restart,
        "Set graceful restart timer",
        1
    },
    {
        "capability route-refresh",
        {
            {.type = TOKEN_KEYWORD, .keyword = "capability"},
            {.type = TOKEN_KEYWORD, .keyword = "route-refresh"},
            {.type = TOKEN_END}
        },
        cmd_handle_capability_route_refresh,
        "Enable route refresh capability",
        1
    },
    {
        "hold-time <seconds>",
        {
            {.type = TOKEN_KEYWORD, .keyword = "hold-time"},
            // Optional so that "no hold-time" is complete; the handler requires it otherwise.
            {.type = TOKEN_OPTIONAL},
            {TOKEN_UINT32, NULL, "seconds", "seconds", "Hold time proposed in OPEN: 0, or 3-65535 (default 180)"},
            {.type = TOKEN_END}
        },
        cmd_handle_hold_time,
        "Set the hold time; keepalives follow at a third of the negotiated value",
        1
    },
    {
        "ttl-security hops <hops>",
        {
            {.type = TOKEN_KEYWORD, .keyword = "ttl-security"},
            // Optional so that "no ttl-security" is complete; the handler requires the rest otherwise.
            {.type = TOKEN_OPTIONAL},
            {.type = TOKEN_KEYWORD, .keyword = "hops"},
            {TOKEN_UINT32, NULL, "hops", "hops", "Hops to the neighbor, 1-254; 1 for a directly connected one"},
            {.type = TOKEN_END}
        },
        cmd_handle_ttl_security,
        "RFC 5082 TTL security: send TTL 255, accept 256 minus hops or more",
        1
    },
    {
        "password <text>",
        {
            {.type = TOKEN_KEYWORD, .keyword = "password"},
            {.type = TOKEN_OPTIONAL},
            {TOKEN_TAIL, NULL, "text", "text", "TCP MD5 key of the session, up to 80 octets (RFC 2385)"},
            {.type = TOKEN_END}
        },
        cmd_handle_password,
        "Sign the TCP segments of the session with this key (TCP MD5)",
        1
    },
    {
        "shutdown [text]",
        {
            {.type = TOKEN_KEYWORD, .keyword = "shutdown"},
            {.type = TOKEN_OPTIONAL},
            {TOKEN_TAIL, NULL, "text", "text", "Shutdown Communication sent with the Cease (RFC 9003)"},
            {.type = TOKEN_END}
        },
        cmd_handle_neighbor_shutdown,
        "Hold the neighbor down: send Cease / Administrative Shutdown and do not reconnect",
        1
    },
    {
        "capability extended-message",
        {
            {.type = TOKEN_KEYWORD, .keyword = "capability"},
            {.type = TOKEN_KEYWORD, .keyword = "extended-message"},
            {.type = TOKEN_END}
        },
        cmd_handle_capability_extended_message,
        "Enable RFC 8654 Extended Message: UPDATEs up to 65535 octets",
        1
    },
    {
        "capability four-byte-asn",
        {
            {.type = TOKEN_KEYWORD, .keyword = "capability"},
            {.type = TOKEN_KEYWORD, .keyword = "four-byte-asn"},
            {.type = TOKEN_END}
        },
        cmd_handle_capability_four_byte_asn,
        "Enable RFC 6793 four-byte ASN capability",
        1
    },
    {
        "capability add-path",
        {
            {.type = TOKEN_KEYWORD, .keyword = "capability"},
            {.type = TOKEN_KEYWORD, .keyword = "add-path"},
            {.type = TOKEN_END}
        },
        cmd_handle_capability_add_path,
        "Enable add-path send and receive capability",
        1
    },
    {
        "capability add-path ipv4",
        {
            {.type = TOKEN_KEYWORD, .keyword = "capability"},
            {.type = TOKEN_KEYWORD, .keyword = "add-path"},
            {.type = TOKEN_KEYWORD, .keyword = "ipv4"},
            {.type = TOKEN_END}
        },
        cmd_handle_capability_add_path,
        "Enable add-path for IPv4 unicast",
        1
    },
    {
        "capability add-path ipv6",
        {
            {.type = TOKEN_KEYWORD, .keyword = "capability"},
            {.type = TOKEN_KEYWORD, .keyword = "add-path"},
            {.type = TOKEN_KEYWORD, .keyword = "ipv6"},
            {.type = TOKEN_END}
        },
        cmd_handle_capability_add_path,
        "Enable add-path for IPv6 unicast",
        1
    },
    {
        "capability add-path ipv4 labels",
        {
            {.type = TOKEN_KEYWORD, .keyword = "capability"},
            {.type = TOKEN_KEYWORD, .keyword = "add-path"},
            {.type = TOKEN_KEYWORD, .keyword = "ipv4"},
            {.type = TOKEN_KEYWORD, .keyword = "labels"},
            {.type = TOKEN_END}
        },
        cmd_handle_capability_add_path,
        "Enable add-path for IPv4 labeled-unicast",
        1
    },
    {
        "capability add-path ipv6 labels",
        {
            {.type = TOKEN_KEYWORD, .keyword = "capability"},
            {.type = TOKEN_KEYWORD, .keyword = "add-path"},
            {.type = TOKEN_KEYWORD, .keyword = "ipv6"},
            {.type = TOKEN_KEYWORD, .keyword = "labels"},
            {.type = TOKEN_END}
        },
        cmd_handle_capability_add_path,
        "Enable add-path for IPv6 labeled-unicast",
        1
    },
    {
        "capability add-path vpnv4",
        {
            {.type = TOKEN_KEYWORD, .keyword = "capability"},
            {.type = TOKEN_KEYWORD, .keyword = "add-path"},
            {.type = TOKEN_KEYWORD, .keyword = "vpnv4"},
            {.type = TOKEN_END}
        },
        cmd_handle_capability_add_path,
        "Enable add-path for VPNv4",
        1
    },
    {
        "capability add-path vpnv6",
        {
            {.type = TOKEN_KEYWORD, .keyword = "capability"},
            {.type = TOKEN_KEYWORD, .keyword = "add-path"},
            {.type = TOKEN_KEYWORD, .keyword = "vpnv6"},
            {.type = TOKEN_END}
        },
        cmd_handle_capability_add_path,
        "Enable add-path for VPNv6",
        1
    },
    {
        "capability add-path l2vpn evpn",
        {
            {.type = TOKEN_KEYWORD, .keyword = "capability"},
            {.type = TOKEN_KEYWORD, .keyword = "add-path"},
            {.type = TOKEN_KEYWORD, .keyword = "l2vpn"},
            {.type = TOKEN_KEYWORD, .keyword = "evpn"},
            {.type = TOKEN_END}
        },
        cmd_handle_capability_add_path,
        "Enable add-path for L2VPN EVPN",
        1
    },
    {
        "capability add-path ipv4 flowspec",
        {
            {.type = TOKEN_KEYWORD, .keyword = "capability"},
            {.type = TOKEN_KEYWORD, .keyword = "add-path"},
            {.type = TOKEN_KEYWORD, .keyword = "ipv4"},
            {.type = TOKEN_KEYWORD, .keyword = "flowspec"},
            {.type = TOKEN_END}
        },
        cmd_handle_capability_add_path,
        "Enable add-path for IPv4 FlowSpec",
        1
    },
    {
        "capability add-path ipv4 flowspec-vpn",
        {
            {.type = TOKEN_KEYWORD, .keyword = "capability"},
            {.type = TOKEN_KEYWORD, .keyword = "add-path"},
            {.type = TOKEN_KEYWORD, .keyword = "ipv4"},
            {.type = TOKEN_KEYWORD, .keyword = "flowspec-vpn"},
            {.type = TOKEN_END}
        },
        cmd_handle_capability_add_path,
        "Enable add-path for IPv4 VPN FlowSpec",
        1
    },
    {
        "capability add-path ipv6 flowspec",
        {
            {.type = TOKEN_KEYWORD, .keyword = "capability"},
            {.type = TOKEN_KEYWORD, .keyword = "add-path"},
            {.type = TOKEN_KEYWORD, .keyword = "ipv6"},
            {.type = TOKEN_KEYWORD, .keyword = "flowspec"},
            {.type = TOKEN_END}
        },
        cmd_handle_capability_add_path,
        "Enable add-path for IPv6 FlowSpec",
        1
    },
    {
        "capability add-path ipv6 flowspec-vpn",
        {
            {.type = TOKEN_KEYWORD, .keyword = "capability"},
            {.type = TOKEN_KEYWORD, .keyword = "add-path"},
            {.type = TOKEN_KEYWORD, .keyword = "ipv6"},
            {.type = TOKEN_KEYWORD, .keyword = "flowspec-vpn"},
            {.type = TOKEN_END}
        },
        cmd_handle_capability_add_path,
        "Enable add-path for IPv6 VPN FlowSpec",
        1
    },
    {
        "capability add-path ipv4 srpolicy",
        {
            {.type = TOKEN_KEYWORD, .keyword = "capability"},
            {.type = TOKEN_KEYWORD, .keyword = "add-path"},
            {.type = TOKEN_KEYWORD, .keyword = "ipv4"},
            {.type = TOKEN_KEYWORD, .keyword = "srpolicy"},
            {.type = TOKEN_END}
        },
        cmd_handle_capability_add_path,
        "Enable add-path for IPv4 SR Policy",
        1
    },
    {
        "capability add-path ipv6 srpolicy",
        {
            {.type = TOKEN_KEYWORD, .keyword = "capability"},
            {.type = TOKEN_KEYWORD, .keyword = "add-path"},
            {.type = TOKEN_KEYWORD, .keyword = "ipv6"},
            {.type = TOKEN_KEYWORD, .keyword = "srpolicy"},
            {.type = TOKEN_END}
        },
        cmd_handle_capability_add_path,
        "Enable add-path for IPv6 SR Policy",
        1
    },
    {
        "capability add-path bgp-ls",
        {
            {.type = TOKEN_KEYWORD, .keyword = "capability"},
            {.type = TOKEN_KEYWORD, .keyword = "add-path"},
            {.type = TOKEN_KEYWORD, .keyword = "bgp-ls"},
            {.type = TOKEN_END}
        },
        cmd_handle_capability_add_path,
        "Enable add-path for BGP-LS",
        1
    },
    {
        "capability add-path ipv4 mvpn",
        {
            {.type = TOKEN_KEYWORD, .keyword = "capability"},
            {.type = TOKEN_KEYWORD, .keyword = "add-path"},
            {.type = TOKEN_KEYWORD, .keyword = "ipv4"},
            {.type = TOKEN_KEYWORD, .keyword = "mvpn"},
            {.type = TOKEN_END}
        },
        cmd_handle_capability_add_path,
        "Enable add-path for IPv4 MVPN",
        1
    },
    {
        "capability add-path ipv6 mvpn",
        {
            {.type = TOKEN_KEYWORD, .keyword = "capability"},
            {.type = TOKEN_KEYWORD, .keyword = "add-path"},
            {.type = TOKEN_KEYWORD, .keyword = "ipv6"},
            {.type = TOKEN_KEYWORD, .keyword = "mvpn"},
            {.type = TOKEN_END}
        },
        cmd_handle_capability_add_path,
        "Enable add-path for IPv6 MVPN",
        1
    },
    {
        "capability add-path ipv4 rtc",
        {
            {.type = TOKEN_KEYWORD, .keyword = "capability"},
            {.type = TOKEN_KEYWORD, .keyword = "add-path"},
            {.type = TOKEN_KEYWORD, .keyword = "ipv4"},
            {.type = TOKEN_KEYWORD, .keyword = "rtc"},
            {.type = TOKEN_END}
        },
        cmd_handle_capability_add_path,
        "Enable add-path for RTC",
        1
    },
    {
        "capability add-path l2vpn vpls",
        {
            {.type = TOKEN_KEYWORD, .keyword = "capability"},
            {.type = TOKEN_KEYWORD, .keyword = "add-path"},
            {.type = TOKEN_KEYWORD, .keyword = "l2vpn"},
            {.type = TOKEN_KEYWORD, .keyword = "vpls"},
            {.type = TOKEN_END}
        },
        cmd_handle_capability_add_path,
        "Enable add-path for VPLS",
        1
    },
    {
        "capability ext-nh",
        {
            {.type = TOKEN_KEYWORD, .keyword = "capability"},
            {.type = TOKEN_KEYWORD, .keyword = "ext-nh"},
            {.type = TOKEN_END}
        },
        cmd_handle_capability_ext_nh,
        "Enable RFC 8950 extended next-hop for supported families",
        1
    },
    {
        "capability ext-nh ipv4",
        {
            {.type = TOKEN_KEYWORD, .keyword = "capability"},
            {.type = TOKEN_KEYWORD, .keyword = "ext-nh"},
            {.type = TOKEN_KEYWORD, .keyword = "ipv4"},
            {.type = TOKEN_END}
        },
        cmd_handle_capability_ext_nh,
        "Enable RFC 8950 extended next-hop for IPv4 unicast",
        1
    },
    {
        "capability ext-nh ipv4 labels",
        {
            {.type = TOKEN_KEYWORD, .keyword = "capability"},
            {.type = TOKEN_KEYWORD, .keyword = "ext-nh"},
            {.type = TOKEN_KEYWORD, .keyword = "ipv4"},
            {.type = TOKEN_KEYWORD, .keyword = "labels"},
            {.type = TOKEN_END}
        },
        cmd_handle_capability_ext_nh,
        "Enable RFC 8950 extended next-hop for IPv4 labeled-unicast",
        1
    },
    {
        "capability ext-nh vpnv4",
        {
            {.type = TOKEN_KEYWORD, .keyword = "capability"},
            {.type = TOKEN_KEYWORD, .keyword = "ext-nh"},
            {.type = TOKEN_KEYWORD, .keyword = "vpnv4"},
            {.type = TOKEN_END}
        },
        cmd_handle_capability_ext_nh,
        "Enable RFC 8950 extended next-hop for VPNv4",
        1
    },
    CONFIG_EXIT_COMMANDS,
};

// Ribout configuration commands
// Ribout command definition helper — keyword + TOKEN_TAIL
#define RIBOUT_CMD(name, kw, display, value_help, handler_fn, help) \
    { name,                                                         \
      {{.type = TOKEN_KEYWORD, .keyword = kw},                      \
       {TOKEN_TAIL, NULL, kw, display, value_help},                 \
       {.type = TOKEN_END}},                                        \
      handler_fn, help, 1 }

// A ribout command whose keyword is the whole line: the tail is optional, so the bare keyword is complete.
#define RIBOUT_BARE_CMD(kw, value_help, handler_fn, help) \
    { kw,                                                 \
      {{.type = TOKEN_KEYWORD, .keyword = kw},            \
       {.type = TOKEN_OPTIONAL},                          \
       {TOKEN_TAIL, NULL, kw, "", value_help},            \
       {.type = TOKEN_END}},                              \
      handler_fn, help, 1 }

// One ribout command per FlowSpec operator component
#define RIBOUT_OP_COMPONENT_CMD(id, kw, type, bitmask, help)                                                  \
    RIBOUT_CMD(kw " ...", kw, "[rotate] <expr> | <cmp> x <count> | each(<expr>, ...)",                        \
               "bare value = equal (numeric) or all bits (bitmask); != < <= > >= any(); & = AND, space = OR", \
               cmd_handle_ribout_op_component_##id, "FlowSpec " help " component"),

static cmd_def_t ribout_commands[] = {
    RIBOUT_CMD("nlri ...", "nlri", "<family> <typed fields> [step <field>] [x <count>]", "Typed NLRI template",
               cmd_handle_ribout_nlri, "RTC, VPLS, EVPN type1/3/4, mvpn4/6 type1..7, bgp-ls node/link/prefix/srv6-sid/sr-policy"),
    RIBOUT_CMD("pmsi ...", "pmsi", "flags <n> type <n> label <n> id <hex|ip|none>", "PMSI Tunnel attribute",
               cmd_handle_ribout_pmsi, "PMSI Tunnel: flags <n> type <n> label <n> id <hex|ip|none>"),
    RIBOUT_CMD("l2-info ...", "l2-info", "encap <n> flags <n> mtu <n>", "VPLS Layer2 Info community",
               cmd_handle_ribout_l2_info, "VPLS Layer2 Info: encap <n> flags <n> mtu <n>"),
    RIBOUT_CMD("esi-label ...", "esi-label", "[flags <n> | single-active] label <n>", "EVPN ESI Label community",
               cmd_handle_ribout_esi_label, "EVPN Type 1 ESI Label: [flags <0|1> | single-active] label <n>"),
    RIBOUT_CMD("es-import ...", "es-import", "mac <mac> | esi <esi>", "EVPN ES-Import Route Target",
               cmd_handle_ribout_es_import, "EVPN Type 4 ES-Import Route Target: mac <mac> | esi <esi>"),
    RIBOUT_CMD("link-bandwidth ...", "link-bandwidth", "<asn> <bits-per-second>[k|m|g] [transitive]",
               "Link Bandwidth community", cmd_handle_ribout_link_bandwidth,
               "Link Bandwidth: <2-octet asn> <bits-per-second>[k|m|g] [transitive]"),
    RIBOUT_CMD("mac-mobility ...", "mac-mobility", "<sequence> [sticky]", "EVPN MAC Mobility community",
               cmd_handle_ribout_mac_mobility, "EVPN MAC Mobility: <sequence> [sticky]"),
    RIBOUT_BARE_CMD("default-gateway", "EVPN Default Gateway community", cmd_handle_ribout_default_gateway,
                    "EVPN Default Gateway (no value)"),
    RIBOUT_CMD("ext-community ...", "ext-community", "<16 hex digits> ...", "Any extended community, raw",
               cmd_handle_ribout_ext_community, "Raw extended communities: <16 hex digits> ... (at most 8)"),
    RIBOUT_CMD("ls ...", "ls", "<tlv-name> <fields> [x <count>]", "BGP-LS Attribute TLV, one per line",
               cmd_handle_ribout_ls, "BGP-LS Attribute TLV: ls <tlv-name> <fields> [sub <tlv-name> ...] [x <count>]"),
    RIBOUT_CMD("ls-attribute ...", "ls-attribute", "type <n> value <hex>", "BGP-LS Attribute TLV (ls raw)",
               cmd_handle_ribout_ls_attribute, "Same as: ls raw type <n> value <hex>"),
    RIBOUT_CMD("aggregator ...", "aggregator", "<asn> <ipv4>", "AGGREGATOR attribute",
               cmd_handle_ribout_aggregator, "AGGREGATOR: <asn> <ipv4>"),
    RIBOUT_BARE_CMD("atomic-aggregate", "ATOMIC_AGGREGATE attribute", cmd_handle_ribout_atomic_aggregate,
                    "ATOMIC_AGGREGATE (no value)"),
    RIBOUT_CMD("originator-id ...", "originator-id", "<ipv4> [x <count>]", "ORIGINATOR_ID attribute",
               cmd_handle_ribout_originator_id, "ORIGINATOR_ID: <ipv4> [x <count>]"),
    RIBOUT_CMD("cluster-list ...", "cluster-list", "<id> ...", "CLUSTER_LIST attribute",
               cmd_handle_ribout_cluster_list, "CLUSTER_LIST: <ipv4|number> ..."),
    RIBOUT_CMD("aigp ...", "aigp", "<metric> [x <count>]", "AIGP attribute",
               cmd_handle_ribout_aigp, "AIGP metric: <0-18446744073709551615> [x <count>]"),
    RIBOUT_CMD("otc ...", "otc", "<asn>", "Only-to-Customer attribute",
               cmd_handle_ribout_otc, "Only-to-Customer (RFC 9234): <asn>"),
    RIBOUT_CMD("prefix-sid ...", "prefix-sid", "index <n> | srgb range <first> <size> ... | srv6-l3|srv6-l2 <sid> behavior <b> ...", "BGP Prefix-SID TLV, one per line",
               cmd_handle_ribout_prefix_sid, "BGP Prefix-SID TLV: index <n> | srgb range <first-label> <size> ... | srv6-l3|srv6-l2 <sid>[/<bits>] behavior <name|n> [structure <block> <node> <function> <argument> [transposition <length> <offset>]]"),
    RIBOUT_CMD("attribute ...", "attribute", "type <n> value <hex> [flags <hex>]", "Any other path attribute",
               cmd_handle_ribout_attribute, "Raw path attribute: type <0-255> value <hex> [flags <hex>]"),
    RIBOUT_CMD("prefix ...", "prefix", "<ip/len> [x <count>]", "IPv4/IPv6 prefix; IPv6 FlowSpec <ip>/<offset>-<len>",
               cmd_handle_ribout_prefix,
               "Set prefix range (FlowSpec: the destination prefix): <ip/len> [x <count>]"),
    RIBOUT_CMD("rd ...", "rd", "[rotate] <rd>... | [rotate] <base> x <count>", "RD values, sequential base/count",
               cmd_handle_ribout_rd,
               "Route distinguishers: [rotate] <rd> [<rd> ...] | [rotate] <base> x <count>; rotate: 1 per path"),
    RIBOUT_CMD("path-id ...", "path-id", "[rotate] <ids> | [rotate] <base> x <count> | range(A,B)",
               "u32 list or interval",
               cmd_handle_ribout_path_id,
               "Path identifiers: [rotate] <id> [<id> ...] | <base> x <count> | range(A,B); rotate: 1 per path"),
    RIBOUT_CMD("label ...", "label", "[rotate] <labels> | [rotate] <base> x <count>",
               "MPLS labels 0-1048575, EVPN VNIs 0-16777215",
               cmd_handle_ribout_label,
               "MPLS labels: [rotate] <label> [<label> ...] | [rotate] <base> x <count>; rotate: one per path in turn"),
    RIBOUT_CMD("label2 ...", "label2", "<labels> | <base> x <count>", "MPLS labels 0-1048575, EVPN VNIs 0-16777215",
               cmd_handle_ribout_label2,
               "EVPN Type 2 Label2 values: <label> [<label> ...] | <base> x <count>"),
    RIBOUT_CMD("ethernet-tag ...", "ethernet-tag", "[rotate] <tags> | [rotate] <base> x <count>",
               "u32 values, max (MAX-ET) or sequential range",
               cmd_handle_ribout_ethernet_tag,
               "EVPN Ethernet Tag values: [rotate] <tag> [<tag> ...] | [rotate] <base> x <count>; rotate: 1 per path"),
    RIBOUT_CMD("mac ...", "mac", "<mac|u64> [x <count>]", "48-bit MAC or u64, sequential count",
               cmd_handle_ribout_mac,
               "EVPN Type 2 MAC range: <mac|u64> [x <count>]"),
    RIBOUT_CMD("ip ...", "ip", "[rotate] <ip> [x <count>]", "IPv4/IPv6 address, sequential count",
               cmd_handle_ribout_ip,
               "EVPN Type 2 optional IP field: [rotate] <ip> [x <count>]; rotate: one IP per MAC, in turn"),
    RIBOUT_CMD("next-hop ...", "next-hop", "<ip> [x <count>] [link-local <ipv6>]",
               "IPv4/IPv6 next hop, optional IPv6 link-local",
               cmd_handle_ribout_next_hop,
               "Next-hop address: <ip> [x <count>] [link-local <ipv6>]"),
    RIBOUT_CMD("gateway-ip ...", "gateway-ip", "<ip> [x <count>]", "IPv4/IPv6 address, sequential count",
               cmd_handle_ribout_gateway_ip,
               "EVPN gateway IP: <ip> [x <count>]"),
    RIBOUT_CMD("esi ...", "esi", "<esi|hex|u64> [x <count>] | <esi|hex|u64>...", "10-octet ESI | 20-hex | u64",
               cmd_handle_ribout_esi,
               "EVPN ESI values: <esi|hex|u64> [x <count>] | <esi|hex|u64> [<esi|hex|u64> ...]"),
    RIBOUT_CMD("as-path ...", "as-path", "[two-byte] <segments>", "ASN literals, <asn> x <count>, sets, rand(N)",
               cmd_handle_ribout_aspath,
               "AS-path segments: [two-byte] <asn> [x <count>] ... [{ <asn> ... }] | rand(<N>) [x <count>]; "
               "two-byte: 2-octet AS numbers with AS4_PATH, for a session without 4-octet AS"),
    RIBOUT_CMD("localpref ...", "localpref", "<value|rand|range|none>", "u32 | rand(N) | range(A,B) | randrange(A,B) | none",
               cmd_handle_ribout_localpref,
               "Local preference: value | rand(N) | range(A,B) | randrange(A,B) | none (send no LOCAL_PREF)"),
    RIBOUT_CMD("med ...", "med", "<value|rand|range>", "u32 | rand(N) | range(A,B) | randrange(A,B)",
               cmd_handle_ribout_med,
               "MED: value | rand(N) | range(A,B) | randrange(A,B)"),
    RIBOUT_CMD("rt ...", "rt", "<rt>... | <base> x <count>", "route-target values",
               cmd_handle_ribout_rt,
               "Route targets: <val> [<val> ...] | <base> x <count>"),
    RIBOUT_CMD("rt-set ...", "rt-set", "[rt[,rt...]] ... | [rt[,rt...]] x <count>", "bracketed RT sets",
               cmd_handle_ribout_rt_set,
               "Rotating RT sets: [rt[,rt...]] ...; [set] x <count> adds count sets, each RT one larger"),
    RIBOUT_CMD("community ...", "community", "<set>... | <set> x <count>", "community sets, rotating",
               cmd_handle_ribout_community,
               "Communities: a set is [c,c,...] or one c (aa:nn or a well-known name, e.g. no-export); several sets "
               "rotate per path; <set> x <count> adds count sets, each aa:nn one larger (well-known ones stay); "
               "lines append"),
    RIBOUT_CMD("large-community ...", "large-community", "<set>... | <set> x <count>", "large-community sets",
               cmd_handle_ribout_large_community,
               "Large communities: a set is [g:l1:l2,...] or one g:l1:l2; several sets rotate per path; "
               "<set> x <count> adds count sets, each l2 one larger; lines append"),
    RIBOUT_CMD("rotate-every ...", "rotate-every", "<n>", "paths per rotation step",
               cmd_handle_ribout_rotate_every,
               "Attribute rotations advance once every <n> paths: blocks of paths share them"),
    RIBOUT_CMD("rotate-period ...", "rotate-period", "<n>", "length of every rotating list",
               cmd_handle_ribout_rotate_period,
               "Rotating lists must have <n> values (or one), so they stay in step"),
    RIBOUT_CMD("message-size ...", "message-size", "<octets>", "largest UPDATE, 64-65535 (default 4096)",
               cmd_handle_ribout_message_size,
               "Largest UPDATE in octets; above 4096 needs a session with capability extended-message"),
    RIBOUT_CMD("soo ...", "soo", "<soo>... | <base> x <count>", "site-of-origin values",
               cmd_handle_ribout_soo,
               "Site-of-origin: <val> [<val> ...] | <base> x <count>"),
    RIBOUT_CMD("encap ...", "encap", "<type>...", "vxlan|nvgre|gre|mpls|mpls-in-gre|l2tpv3|<u16>",
               cmd_handle_ribout_encap,
               "Encap ECs: vxlan|nvgre|gre|mpls|mpls-in-gre|l2tpv3|<tunnel-type> [ ... ]"),
    RIBOUT_CMD("router-mac ...", "router-mac", "<mac|u64> [x <count>] | <mac|u64>...", "unicast 48-bit MAC or u64",
               cmd_handle_ribout_router_mac,
               "EVPN Router's MAC ECs: <mac|u64> [x <count>] | <mac|u64> [<mac|u64> ...]"),
    RIBOUT_CMD("origin ...", "origin", "igp|egp|incomplete", "origin enum",
               cmd_handle_ribout_origin,
               "Origin attribute: igp | egp | incomplete"),
    RIBOUT_CMD("distinguisher ...", "distinguisher", "[rotate] <value>... | [rotate] <base> x <count>",
               "u32 values or sequential range",
               cmd_handle_ribout_distinguisher,
               "SR distinguisher values: [rotate] <val> ... | [rotate] <base> x <count>; rotate: 1 per path"),
    RIBOUT_CMD("color ...", "color", "[rotate|set] <c> [co <bits>]... | [rotate|set] <base> x <count> [co <bits>]",
               "SR Policy color; Color communities rotate, or set carries all on each path",
               cmd_handle_ribout_color,
               "SR Policy NLRI color (rotate: 1 per path); other families rotate one Color, or set carries all per path"),
    RIBOUT_CMD("endpoint ...", "endpoint", "[rotate] <ip> [x <count>]", "IPv4/IPv6 address, sequential count",
               cmd_handle_ribout_endpoint,
               "SR endpoint address: [rotate] <ip> [x <count>]; rotate: 1 per path"),
    RIBOUT_CMD("enlp ...", "enlp", "<value|rand|range>", "1-4 | rand(N) | range(A,B) | randrange(A,B)",
               cmd_handle_ribout_enlp,
               "SR ENLP: values | rand(N) | range(A,B) | randrange(A,B)"),
    RIBOUT_CMD("priority ...", "priority", "<value|rand|range>", "0-255 | rand(N) | range(A,B) | randrange(A,B)",
               cmd_handle_ribout_priority,
               "SR priority: values | rand(N) | range(A,B) | randrange(A,B)"),
    RIBOUT_CMD("preference ...", "preference", "<value|rand|range>", "u32 list | rand(N) | range(A,B) | randrange(A,B)",
               cmd_handle_ribout_preference,
               "SR preference: values | <base> x <count> | rand(N) | range(A,B) | randrange(A,B)"),
    RIBOUT_CMD("binding-sid ...", "binding-sid", "mpls <value|rand|range> | srv6 <sid> [x <count>]",
               "MPLS labels or SRv6 SIDs",
               cmd_handle_ribout_binding_sid,
               "SR binding SID: mpls labels/rand/range forms | srv6 <sid> [x <count>]"),
    RIBOUT_CMD("segment-list ...", "segment-list", "<id> weight <w> mpls|srv6 ...",
               "u32 id/weight, MPLS labels or SRv6 SIDs",
               cmd_handle_ribout_segment_list,
               "SR segment-list: <id> weight <w> mpls <label> [x <count>] ... | "
               "<id> weight <w> srv6 <sid> [behavior <u16> [structure <lb> <ln> <fn> <arg>]] [x <count>] ..."),
    RIBOUT_CMD("address-family ...", "address-family", "<afi> [<safi>]", "neighbor address-family names",
               cmd_handle_ribout_address_family,
               "Select the ribout family: ipv4 | ipv6 | ipv4 labels | vpnv4 | l2vpn evpn | ipv4 flowspec | "
               "ipv4 flowspec-vpn | ipv4 srpolicy ..."),
    RIBOUT_CMD("src-prefix ...", "src-prefix", "<ip/len> [x <count>]", "IPv4/IPv6 prefix; IPv6 <ip>/<offset>-<len>",
               cmd_handle_ribout_src_prefix,
               "FlowSpec source prefix: <ip/len> [x <count>]"),
    BGP_RIBOUT_FLOWSPEC_OP_COMPONENTS(RIBOUT_OP_COMPONENT_CMD)
    RIBOUT_CMD("action ...", "action", "<action>", "FlowSpec action; a value list rotates per path",
               cmd_handle_ribout_action,
               "FlowSpec action: " RIBOUT_FLOWSPEC_ACTION_HELP),
    CONFIG_EXIT_COMMANDS,
};
#undef RIBOUT_OP_COMPONENT_CMD

// Per-mode config command tables indexed by config_mode_t
/*
 * A command with an optional scope before its tail. Each form is a table entry of its own, because the parser only has
 * optional tails.
 */
#define SCOPED_COMMANDS(usage, tail_usage, tail, handler, help, hidden, ...)                                  \
    {usage " " tail_usage, {__VA_ARGS__, tail}, handler, help, 0, hidden},                                    \
    {usage " router <AS> " tail_usage,                                                                        \
     {__VA_ARGS__, {TOKEN_KEYWORD, "router"}, {TOKEN_UINT32, NULL, "router", "AS", "Local router AS"}, tail}, \
     handler, help, 0, hidden},                                                                               \
    {usage " vrf <name|all|default> " tail_usage,                                                             \
     {__VA_ARGS__, {TOKEN_KEYWORD, "vrf"},                                                                    \
      {TOKEN_STRING, NULL, "vrf", "name|all|default", "VRF name, all or default"}, tail},                     \
     handler, help, 0, hidden}

#define PEER_CLEAR_TAIL {TOKEN_STRING, NULL, "neighbor-ip", "neighbor", "Neighbor IP address or *"}, {TOKEN_END}

#define PEER_CEASE_TAIL                                                                                    \
    {TOKEN_STRING, NULL, "neighbor-ip", "neighbor", "Neighbor IP address or *"}, {TOKEN_KEYWORD, "cease"}, \
    {.type = TOKEN_OPTIONAL}, {TOKEN_TAIL, NULL, "text", "text", "Shutdown Communication (RFC 9003)"},     \
    {TOKEN_END}

#define PEER_TAIL(word) \
    {TOKEN_KEYWORD, word}, {TOKEN_STRING, NULL, "peer", "ip|all", "Peer IPv4/IPv6 address or all"}, {TOKEN_END}

// "neighbor" is accepted and completed everywhere "peer" is; help lists one spelling.
#define PEER_COMMANDS(usage, handler, help, ...)                                               \
    SCOPED_COMMANDS(usage, "peer <ip|all>", PEER_TAIL("peer"), handler, help, 0, __VA_ARGS__), \
    SCOPED_COMMANDS(usage, "neighbor <ip|all>", PEER_TAIL("neighbor"), handler, help, 1, __VA_ARGS__)

#define RIBOUT_PEER_COMMANDS(verb, handler, help)                                                         \
    PEER_COMMANDS(verb " ribout <name>", handler, help, {TOKEN_KEYWORD, verb}, {TOKEN_KEYWORD, "ribout"}, \
                  {TOKEN_STRING, NULL, "ribout", "name", "Ribout name"})

#define SCRIPT_ACTION_COMMAND(verb) RIBOUT_PEER_COMMANDS(verb, cmd_handle_script_action, "Append a " verb " step")

static cmd_def_t script_commands[] = {
    SCRIPT_ACTION_COMMAND("advertise"),
    SCRIPT_ACTION_COMMAND("withdraw"),
    SCRIPT_ACTION_COMMAND("replay"),
    {
        "sleep <duration>",
        {{TOKEN_KEYWORD, "sleep"},
         {TOKEN_STRING, NULL, "duration", "duration", "Integer duration: ms, s, m, h; bare values are seconds"},
         {TOKEN_END}},
        cmd_handle_script_sleep, "Append a nonblocking sleep step", 0
    },
    {
        "no step <number>",
        {{TOKEN_KEYWORD, "step"}, {TOKEN_UINT32, NULL, "step", "number", "One-based step number"}, {TOKEN_END}},
        cmd_handle_script_remove_step, "Remove a step with no step <number>", 1
    },
    CONFIG_EXIT_COMMANDS,
};
#undef SCRIPT_ACTION_COMMAND

#define TABLE(arr) { (arr), sizeof(arr) / sizeof(cmd_def_t) }
cmd_table_t config_tables[CONFIG_MODE_COUNT] = {
    [CONFIG_MODE_GLOBAL]     = TABLE(global_config_commands),
    [CONFIG_MODE_ROUTER_BGP] = TABLE(router_bgp_commands),
    [CONFIG_MODE_NEIGHBOR]   = TABLE(neighbor_commands),
    [CONFIG_MODE_RIBOUT]     = TABLE(ribout_commands),
    [CONFIG_MODE_SCRIPT]     = TABLE(script_commands),
};
#undef TABLE

#define TX_ACTION_COMMAND(verb, help) RIBOUT_PEER_COMMANDS(verb, cmd_handle_tx_ribout, help)

/*
 * CLI exec mode commands
 */
cmd_def_t cli_exec_commands[] = {
    TX_ACTION_COMMAND("advertise", "Send the ribout's current UPDATE snapshot to peers"),
    TX_ACTION_COMMAND("withdraw", "Withdraw the ribout's routes from peers"),
    TX_ACTION_COMMAND("replay", "Send the ribout snapshot bound to peers again"),
    PEER_COMMANDS("withdraw all", cmd_handle_tx_withdraw_all, "Withdraw every ribout advertised to peers",
                  {TOKEN_KEYWORD, "withdraw"}, {TOKEN_KEYWORD, "all"}),
    {
        "run script <name> [repeat <count|forever>]",
        {{TOKEN_KEYWORD, "run"}, {TOKEN_KEYWORD, "script"},
         {TOKEN_STRING, NULL, "name", "name", "Script name"},
         {TOKEN_OPTIONAL}, {TOKEN_KEYWORD, "repeat"},
         {TOKEN_STRING, NULL, "repeat", "count|forever", "Positive iteration count or forever"}, {TOKEN_END}},
        cmd_handle_run_script, "Run a script (pending only without the runtime)", 0
    },
    {
        "run script <name> json [repeat <count|forever>]",
        {{TOKEN_KEYWORD, "run"}, {TOKEN_KEYWORD, "script"},
         {TOKEN_STRING, NULL, "name", "name", "Script name"}, {TOKEN_KEYWORD, "json"},
         {TOKEN_OPTIONAL}, {TOKEN_KEYWORD, "repeat"},
         {TOKEN_STRING, NULL, "repeat", "count|forever", "Positive iteration count or forever"}, {TOKEN_END}},
        cmd_handle_run_script, "Start a script and return its run snapshot as JSON", 0
    },
    {
        "show scripts [color]",
        {{TOKEN_KEYWORD, "show"}, {TOKEN_KEYWORD, "scripts"},
         {TOKEN_OPTIONAL}, {TOKEN_KEYWORD, "color"}, {TOKEN_END}},
        cmd_handle_show_scripts, "List script definitions", 0
    },
    {
        "show script <name> [color]",
        {{TOKEN_KEYWORD, "show"}, {TOKEN_KEYWORD, "script"},
         {TOKEN_STRING, NULL, "name", "name", "Script name"},
         {TOKEN_OPTIONAL}, {TOKEN_KEYWORD, "color"}, {TOKEN_END}},
        cmd_handle_show_scripts, "Show a script definition", 0
    },
    {
        "show runs [color]",
        {{TOKEN_KEYWORD, "show"}, {TOKEN_KEYWORD, "runs"},
         {TOKEN_OPTIONAL}, {TOKEN_KEYWORD, "color"}, {TOKEN_END}},
        cmd_handle_show_runs, "List run states and phase/TX progress", 0
    },
    {
        "show run <id> [color]",
        {{TOKEN_KEYWORD, "show"}, {TOKEN_KEYWORD, "run"},
         {TOKEN_UINT32, NULL, "id", "id", "Run ID"},
         {TOKEN_OPTIONAL}, {TOKEN_KEYWORD, "color"}, {TOKEN_END}},
        cmd_handle_show_runs, "Show run phases, timing aggregates and per-peer TX progress", 0
    },
    {
        "show run <id> json",
        {{TOKEN_KEYWORD, "show"}, {TOKEN_KEYWORD, "run"},
         {TOKEN_UINT32, NULL, "id", "id", "Run ID"},
         {TOKEN_KEYWORD, "json"}, {TOKEN_END}},
        cmd_handle_show_runs, "Show the run model and TX observations as JSON", 0
    },
    {
        "cancel run <id>",
        {{TOKEN_KEYWORD, "cancel"}, {TOKEN_KEYWORD, "run"},
         {TOKEN_UINT32, NULL, "id", "id", "Run ID"}, {TOKEN_END}},
        cmd_handle_cancel_run, "Cancel a run; does not withdraw routes", 0
    },
    {
        "clear run <id>",
        {{TOKEN_KEYWORD, "clear"}, {TOKEN_KEYWORD, "run"},
         {TOKEN_UINT32, NULL, "id", "id", "Terminal run ID"}, {TOKEN_END}},
        cmd_handle_clear_run, "Remove a completed, failed or cancelled run record", 0
    },
    {
        "config",
        {
            {.type = TOKEN_KEYWORD, .keyword = "config"},
            {.type = TOKEN_END}
        },
        cmd_handle_config_mode,
        "Enter configuration mode",
        0
    },
    {
        "configure terminal",
        {
            {.type = TOKEN_KEYWORD, .keyword = "configure"},
            {.type = TOKEN_KEYWORD, .keyword = "terminal"},
            {.type = TOKEN_END}
        },
        cmd_handle_config_mode,
        "Enter configuration mode",
        0
    },
    {
        "show running-config",
        {
            {.type = TOKEN_KEYWORD, .keyword = "show"},
            {.type = TOKEN_KEYWORD, .keyword = "running-config"},
            {.type = TOKEN_END}
        },
        cmd_handle_show_config,
        "Show current running configuration",
        0
    },
    {
        "show log",
        {
            {.type = TOKEN_KEYWORD, .keyword = "show"},
            {.type = TOKEN_KEYWORD, .keyword = "log"},
            {.type = TOKEN_END}
        },
        cmd_handle_show_log,
        "Show recent log entries",
        0
    },
    {
        "show log all",
        {
            {.type = TOKEN_KEYWORD, .keyword = "show"},
            {.type = TOKEN_KEYWORD, .keyword = "log"},
            {.type = TOKEN_KEYWORD, .keyword = "all"},
            {.type = TOKEN_END}
        },
        cmd_handle_show_log_all,
        "Show all log entries",
        0
    },
    {
        "show bgp summary",
        {
            {.type = TOKEN_KEYWORD, .keyword = "show"},
            {.type = TOKEN_KEYWORD, .keyword = "bgp"},
            {.type = TOKEN_KEYWORD, .keyword = "summary"},
            {.type = TOKEN_END}
        },
        cmd_handle_show_bgp_summary,
        "Show BGP routing summary",
        0
    },
    {
        "show bgp neighbors",
        {
            {.type = TOKEN_KEYWORD, .keyword = "show"},
            {.type = TOKEN_KEYWORD, .keyword = "bgp"},
            {.type = TOKEN_KEYWORD, .keyword = "neighbors"},
            {.type = TOKEN_END}
        },
        cmd_handle_show_bgp_neighbors,
        "Show all BGP neighbors",
        0
    },
    {
        "show bgp neighbors <AS>",
        {
            {.type = TOKEN_KEYWORD, .keyword = "show"},
            {.type = TOKEN_KEYWORD, .keyword = "bgp"},
            {.type = TOKEN_KEYWORD, .keyword = "neighbors"},
            {TOKEN_UINT32, NULL, "AS", "AS", "Local AS number (1-4294967295)"},
            {.type = TOKEN_END}
        },
        cmd_handle_show_bgp_neighbors_as,
        "Show BGP neighbors for specific AS",
        0
    },
    {
        "show ribout",
        {
            {.type = TOKEN_KEYWORD, .keyword = "show"},
            {.type = TOKEN_KEYWORD, .keyword = "ribout"},
            {.type = TOKEN_END}
        },
        cmd_handle_show_ribout,
        "Show all ribout configurations",
        0
    },
    {
        "show ribout <name>",
        {
            {.type = TOKEN_KEYWORD, .keyword = "show"},
            {.type = TOKEN_KEYWORD, .keyword = "ribout"},
            {TOKEN_STRING, NULL, "name", "name", "Ribout name"},
            {.type = TOKEN_END}
        },
        cmd_handle_show_ribout_name,
        "Show specific ribout detail",
        0
    },
    {
        "show ribout <name> preview",
        {
            {.type = TOKEN_KEYWORD, .keyword = "show"},
            {.type = TOKEN_KEYWORD, .keyword = "ribout"},
            {TOKEN_STRING, NULL, "name", "name", "Ribout name"},
            {.type = TOKEN_KEYWORD, .keyword = "preview"},
            {.type = TOKEN_END}
        },
        cmd_handle_show_ribout_preview,
        "Preview ribout generated routes (default 10)",
        0
    },
    {
        "show ribout <name> preview <count>",
        {
            {.type = TOKEN_KEYWORD, .keyword = "show"},
            {.type = TOKEN_KEYWORD, .keyword = "ribout"},
            {TOKEN_STRING, NULL, "name", "name", "Ribout name"},
            {.type = TOKEN_KEYWORD, .keyword = "preview"},
            {TOKEN_UINT32, NULL, "count", "count", "Preview route count"},
            {.type = TOKEN_END}
        },
        cmd_handle_show_ribout_preview,
        "Preview ribout generated routes",
        0
    },
    {
        "show ribout-map",
        {
            {.type = TOKEN_KEYWORD, .keyword = "show"},
            {.type = TOKEN_KEYWORD, .keyword = "ribout-map"},
            {.type = TOKEN_END}
        },
        cmd_handle_show_ribout_map,
        "Show all ribout-map summaries",
        0
    },
    {
        "show ribout-map <name>",
        {
            {.type = TOKEN_KEYWORD, .keyword = "show"},
            {.type = TOKEN_KEYWORD, .keyword = "ribout-map"},
            {TOKEN_STRING, NULL, "name", "name", "Ribout name"},
            {.type = TOKEN_END}
        },
        cmd_handle_show_ribout_map_name,
        "Show specific ribout-map detail",
        0
    },
    SCOPED_COMMANDS("clear bgp", "<neighbor>",
                    PEER_CLEAR_TAIL, cmd_handle_clear_bgp_neighbor, "Clear BGP sessions (use * for all)", 0,
                    {TOKEN_KEYWORD, "clear"}, {TOKEN_KEYWORD, "bgp"}),
    SCOPED_COMMANDS("clear bgp", "<neighbor> cease [text]",
                    PEER_CEASE_TAIL, cmd_handle_clear_bgp_neighbor,
                    "Clear BGP sessions with Cease / Administrative Reset and an optional text", 0,
                    {TOKEN_KEYWORD, "clear"}, {TOKEN_KEYWORD, "bgp"}),
    {
        "update generate",
        {
            {.type = TOKEN_KEYWORD, .keyword = "update"},
            {.type = TOKEN_KEYWORD, .keyword = "generate"},
            {.type = TOKEN_END}
        },
        cmd_handle_update_generate,
        "Generate BGP updates for all ribouts",
        0
    },
    {
        "update generate changed",
        {
            {.type = TOKEN_KEYWORD, .keyword = "update"},
            {.type = TOKEN_KEYWORD, .keyword = "generate"},
            {.type = TOKEN_KEYWORD, .keyword = "changed"},
            {.type = TOKEN_END}
        },
        cmd_handle_update_generate,
        "Generate only dirty ribouts or blocks without a snapshot",
        0
    },
    {
        "update generate ribout <name>...",
        {
            {.type = TOKEN_KEYWORD, .keyword = "update"},
            {.type = TOKEN_KEYWORD, .keyword = "generate"},
            {.type = TOKEN_KEYWORD, .keyword = "ribout"},
            {TOKEN_TAIL, NULL, "names", "name...", "One or more ribout names"},
            {.type = TOKEN_END}
        },
        cmd_handle_update_generate,
        "Generate only the named ribouts",
        0
    },
    {
        "terminal monitor",
        {
            {.type = TOKEN_KEYWORD, .keyword = "terminal"},
            {.type = TOKEN_KEYWORD, .keyword = "monitor"},
            {.type = TOKEN_END}
        },
        cmd_handle_terminal_monitor,
        "Enable runtime monitor events on this session",
        1
    },
    {
        "shutdown",
        {
            {.type = TOKEN_KEYWORD, .keyword = "shutdown"},
            {.type = TOKEN_END}
        },
        cmd_handle_shutdown,
        "Stop the simulator runtime",
        0
    },
};

#undef TX_ACTION_COMMAND
#undef RIBOUT_PEER_COMMANDS
#undef PEER_COMMANDS
#undef PEER_TAIL
#undef PEER_CLEAR_TAIL
#undef PEER_CEASE_TAIL
#undef SCOPED_COMMANDS

int cli_exec_commands_count = sizeof(cli_exec_commands) / sizeof(cmd_def_t);
