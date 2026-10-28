#define OUTPUT_STDIO_REMAP

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bgp.h"
#include "util.h"
#include "output.h"
#include "commands.h"

int parse_config_file_with_output(const char *filename, bgp_sim_t *sim, const output_t *output) {
    FILE           *fp;
    char           *line = NULL;
    size_t          capacity = 0;
    ssize_t         length;
    int             line_num = 0;
    int             result;
    int             previous_config_loading;
    const output_t *previous_output = output_push(output);

    fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Error opening config file: %s\n", strerror(errno));
        output_pop(previous_output);
        return -1;
    }

    previous_config_loading = sim->config_loading;
    sim->config_loading = 1;

    // Single persistent context — no shadow state needed
    cmd_ctx_t cmd_ctx = {
        .sim = sim,
        .mode = NULL,  /* NULL for config file */
        .session = NULL,
        .config_mode = CONFIG_MODE_GLOBAL,
        .is_no_command = 0,
        .raw_line = NULL,
        .current_ribout = NULL,
        .current_router = NULL,
        .current_neighbor = NULL
    };

    cmd_exec_options_t opts;
    command_init_exec_options(&opts);

    while ((length = getline(&line, &capacity, fp)) >= 0) {
        line_num++;
        if (length && line[length - 1] == '\n') line[--length] = '\0';
        if (length && line[length - 1] == '\r') line[--length] = '\0';
        if (!command_input_valid(line, (size_t)length)) {
            fprintf(stderr, "Invalid command input on line %d (maximum %d bytes)\n", line_num, BGPSIM_COMMAND_SIZE - 1);
            continue;
        }

        char *trimmed = str_trim(line);
        char *display_line = trimmed;

        /*
         * Running-config emits '!' between top-level sections. Treat it as a
         * context barrier when loading config so a following top-level keyword
         * cannot be consumed as a ribout/router tail abbreviation.
         */
        if (trimmed[0] == '!') {
            cmd_ctx.config_mode = CONFIG_MODE_GLOBAL;
            cmd_ctx.mode_stack_depth = 0;
            cmd_ctx.current_ribout = NULL;
            cmd_ctx.current_router = NULL;
            cmd_ctx.current_neighbor = NULL;
            cmd_ctx.current_script_name[0] = '\0';
            continue;
        }

        // Skip empty lines and comments
        if (trimmed[0] == '\0' || trimmed[0] == '#') {
            continue;
        }

        // Check for "no" prefix
        cmd_ctx.is_no_command = 0;
        if (strncmp(trimmed, "no ", 3) == 0) {
            cmd_ctx.is_no_command = 1;
            trimmed += 3;
            while (isspace(*trimmed)) trimmed++;
        }

        cmd_ctx.raw_line = trimmed;

        result = command_execute(trimmed, &cmd_ctx, &opts);

        if (result == PARSER_NO_MATCH) {
            fprintf(stderr, "Unknown Command on line %d: %s\n", line_num, display_line);
        } else if (result == PARSER_INCOMPLETE) {
            fprintf(stderr, "Incomplete Command on line %d: %s\n", line_num, display_line);
        } else if (result == PARSER_AMBIGUOUS) {
            fprintf(stderr, "Ambiguous Command on line %d: %s\n", line_num, display_line);
        } else if (result == PARSER_UNSUPPORTED_NEGATION) {
            fprintf(stderr, "'%s' is not supported on line %d\n", display_line, line_num);
        } else if (result < 0) {
            fprintf(stderr, "Warning on line %d: %s\n", line_num, display_line);
        }
    }

    free(line);
    fclose(fp);
    sim->config_loading = previous_config_loading;
    output_pop(previous_output);
    return 0;
}

/*
 * Parse configuration file
 */
int parse_config_file(const char *filename, bgp_sim_t *sim) {
    return parse_config_file_with_output(filename, sim, NULL);
}
