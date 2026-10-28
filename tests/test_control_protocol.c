#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "control.h"
#include "test_result.h"

static void write_u32(uint8_t *buf, uint32_t value) {
    value = htonl(value);
    memcpy(buf, &value, sizeof(value));
}

static void test_build_frame_round_trip(void) {
    bgpsim_control_decoder_t decoder;
    bgpsim_control_frame_t   frame = {0};
    uint8_t                 *encoded = NULL;
    size_t                   encoded_len = 0;
    const char payload[] = "show bgp summary";
    int passed = 0;

    bgpsim_control_decoder_init(&decoder);

    if (bgpsim_control_build_frame(BGPSIM_CTRL_EXEC_REQ, payload, (uint32_t)strlen(payload),
                                   &encoded, &encoded_len) == 0 &&
        bgpsim_control_decoder_append(&decoder, encoded, encoded_len) == 0 &&
        bgpsim_control_decoder_next(&decoder, &frame) == 1) {
        passed = frame.type == BGPSIM_CTRL_EXEC_REQ &&
                 frame.payload_len == strlen(payload) &&
                 memcmp(frame.payload, payload, strlen(payload)) == 0;
    }

    test_result(passed, "Control frame encode/decode round-trip preserves type and payload");
    free(encoded);
    bgpsim_control_frame_reset(&frame);
    bgpsim_control_decoder_free(&decoder);
}

static void test_decoder_handles_partial_frame(void) {
    bgpsim_control_decoder_t decoder;
    bgpsim_control_frame_t   frame = {0};
    uint8_t                 *encoded = NULL;
    size_t                   encoded_len = 0;
    const char payload[] = "config";
    int passed = 0;

    bgpsim_control_decoder_init(&decoder);

    if (bgpsim_control_build_frame(BGPSIM_CTRL_EXEC_REQ, payload, (uint32_t)strlen(payload),
                                   &encoded, &encoded_len) == 0 &&
        encoded_len > 3 &&
        bgpsim_control_decoder_append(&decoder, encoded, 3) == 0 &&
        bgpsim_control_decoder_next(&decoder, &frame) == 0 &&
        bgpsim_control_decoder_append(&decoder, encoded + 3, encoded_len - 3) == 0 &&
        bgpsim_control_decoder_next(&decoder, &frame) == 1) {
        passed = frame.type == BGPSIM_CTRL_EXEC_REQ &&
                 frame.payload_len == strlen(payload) &&
                 memcmp(frame.payload, payload, strlen(payload)) == 0;
    }

    test_result(passed, "Control decoder waits for a complete frame before decoding");
    free(encoded);
    bgpsim_control_frame_reset(&frame);
    bgpsim_control_decoder_free(&decoder);
}

static void test_decoder_rejects_invalid_type(void) {
    bgpsim_control_decoder_t decoder;
    bgpsim_control_frame_t   frame = {0};
    uint8_t                  encoded[8];
    int                      passed = 0;

    bgpsim_control_decoder_init(&decoder);
    write_u32(encoded, 999);
    write_u32(encoded + 4, 0);

    if (bgpsim_control_decoder_append(&decoder, encoded, sizeof(encoded)) == 0) {
        passed = bgpsim_control_decoder_next(&decoder, &frame) < 0;
    }

    test_result(passed, "Control decoder rejects invalid frame types");
    bgpsim_control_frame_reset(&frame);
    bgpsim_control_decoder_free(&decoder);
}

static void test_exec_done_round_trip(void) {
    bgpsim_exec_done_t done = {0};
    bgpsim_exec_done_t decoded = {0};
    size_t             payload_len = bgpsim_control_exec_done_payload_len();
    uint8_t           *buf = calloc(1, payload_len);
    int                passed = 0;

    done.status = 7;
    done.mode = CLI_MODE_CONFIG;
    done.session.config_mode = CONFIG_MODE_NEIGHBOR;
    done.session.terminal_monitor = 1;
    done.session.has_router = 1;
    done.session.current_router_as = 65123;
    done.session.has_neighbor = 1;
    strncpy(done.session.current_neighbor_ip, "2001:db8::1", sizeof(done.session.current_neighbor_ip) - 1);
    done.session.has_ribout = 1;
    strncpy(done.session.current_ribout_name, "blue", sizeof(done.session.current_ribout_name) - 1);
    done.session.mode_stack_depth = 3;
    done.session.mode_stack[0] = CONFIG_MODE_GLOBAL;
    done.session.mode_stack[1] = CONFIG_MODE_ROUTER_BGP;
    done.session.mode_stack[2] = CONFIG_MODE_NEIGHBOR;

    if (buf != NULL &&
        bgpsim_control_encode_exec_done(buf, payload_len, &done) == 0 &&
        bgpsim_control_decode_exec_done(buf, payload_len, &decoded) == 0) {
        passed = decoded.status == done.status &&
                 decoded.mode == done.mode &&
                 decoded.session.config_mode == done.session.config_mode &&
                 decoded.session.terminal_monitor == done.session.terminal_monitor &&
                 decoded.session.has_router == done.session.has_router &&
                 decoded.session.current_router_as == done.session.current_router_as &&
                 decoded.session.has_neighbor == done.session.has_neighbor &&
                 strcmp(decoded.session.current_neighbor_ip, done.session.current_neighbor_ip) == 0 &&
                 decoded.session.has_ribout == done.session.has_ribout &&
                 strcmp(decoded.session.current_ribout_name, done.session.current_ribout_name) == 0 &&
                 decoded.session.mode_stack_depth == done.session.mode_stack_depth &&
                 decoded.session.mode_stack[2] == done.session.mode_stack[2];
    }

    test_result(passed, "EXEC_DONE payload round-trip preserves CLI session state");
    free(buf);
}

/*
 * Attach mode keeps the ribout mode with the longest ribout name. The buffer is exactly the payload length, so a field
 * list that drifts from the length fails instead of writing past the buffer.
 */
static void test_exec_done_round_trip_ribout_mode(void) {
    bgpsim_exec_done_t done = {0};
    bgpsim_exec_done_t decoded = {0};
    size_t             payload_len = bgpsim_control_exec_done_payload_len();
    uint8_t           *buf = calloc(1, payload_len);
    int                passed = 0;

    done.mode = CLI_MODE_CONFIG;
    done.session.config_mode = CONFIG_MODE_RIBOUT;
    done.session.has_ribout = 1;
    memset(done.session.current_ribout_name, 'f', sizeof(done.session.current_ribout_name) - 1);
    done.session.mode_stack_depth = 2;
    done.session.mode_stack[0] = CONFIG_MODE_GLOBAL;
    done.session.mode_stack[1] = CONFIG_MODE_RIBOUT;

    if (buf != NULL &&
        bgpsim_control_encode_exec_done(buf, payload_len, &done) == 0 &&
        bgpsim_control_decode_exec_done(buf, payload_len, &decoded) == 0) {
        passed = decoded.session.config_mode == CONFIG_MODE_RIBOUT &&
                 decoded.session.has_ribout == 1 &&
                 strcmp(decoded.session.current_ribout_name, done.session.current_ribout_name) == 0 &&
                 strlen(decoded.session.current_ribout_name) == sizeof(done.session.current_ribout_name) - 1 &&
                 decoded.session.mode_stack_depth == 2 &&
                 decoded.session.mode_stack[1] == CONFIG_MODE_RIBOUT;
    }

    test_result(passed, "EXEC_DONE payload round-trip keeps the ribout mode and the longest ribout name");
    free(buf);
}

static void test_socket_path_helpers(void) {
    char path[256];
    int  passed = 1;

    bgpsim_control_build_socket_path(NULL, path, sizeof(path));
    passed = passed && strcmp(path, BGPSIM_SOCK_PATH) == 0;

    bgpsim_control_build_socket_path("", path, sizeof(path));
    passed = passed && strcmp(path, BGPSIM_SOCK_PATH) == 0;

    bgpsim_control_build_socket_path("lab", path, sizeof(path));
    passed = passed &&
             strcmp(path, "/tmp/bgpsim_lab.sock") == 0;

    test_result(passed, "Socket path helper builds default and named session paths");
}

static void test_exec_done_script_context(void) {
    bgpsim_exec_done_t done = {.mode = CLI_MODE_CONFIG}, decoded = {0};
    done.session.config_mode = CONFIG_MODE_SCRIPT;
    strcpy(done.session.current_script_name, "churn");
    done.session.mode_stack_depth = 1;
    done.session.mode_stack[0] = CONFIG_MODE_GLOBAL;
    size_t   size = bgpsim_control_exec_done_payload_len();
    uint8_t *buf = calloc(1, size);
    char     prompt[256] = {0};
    int passed = buf && bgpsim_control_encode_exec_done(buf, size, &done) == 0 &&
                 bgpsim_control_decode_exec_done(buf, size, &decoded) == 0;
    if (passed) {
        cli_build_prompt(decoded.mode, &decoded.session, prompt, sizeof(prompt), 0);
        passed = strcmp(decoded.session.current_script_name, "churn") == 0 &&
                 strcmp(prompt, "bgpsim(config-script-churn)# ") == 0;
    }
    test_result(passed, "EXEC_DONE preserves script context and attached-client prompts");
    if (buf) {
        test_result(bgpsim_control_decode_exec_done(buf, size - 1, &decoded) < 0 &&
                    bgpsim_control_encode_exec_done(buf, size - 1, &done) < 0,
                    "Partial script context and undersized encodes are rejected");
        memset(done.session.current_script_name, 'x', sizeof(done.session.current_script_name));
        test_result(bgpsim_control_encode_exec_done(buf, size, &done) == 0 &&
                    bgpsim_control_decode_exec_done(buf, size, &decoded) == 0 &&
                    decoded.session.current_script_name[sizeof(decoded.session.current_script_name) - 1] == 0,
                    "Decoded script names are always terminated");
    }
    free(buf);
}

static void test_build_frame_validation(void) {
    uint8_t *encoded = NULL;
    size_t   encoded_len = 0;
    int      passed = 1;

    passed = passed &&
             bgpsim_control_build_frame(0, NULL, 0, &encoded, &encoded_len) != 0;
    passed = passed &&
             bgpsim_control_build_frame(BGPSIM_CTRL_EXEC_REQ, NULL,
                                        BGPSIM_CONTROL_MAX_PAYLOAD + 1, &encoded, &encoded_len) != 0;

    test_result(passed, "Control frame builder rejects invalid type and oversized payload");
}

int main(void) {
    printf("\n=== Control Protocol Tests ===\n\n");

    test_build_frame_round_trip();
    test_decoder_handles_partial_frame();
    test_decoder_rejects_invalid_type();
    test_exec_done_round_trip();
    test_exec_done_round_trip_ribout_mode();
    test_exec_done_script_context();
    test_socket_path_helpers();
    test_build_frame_validation();

    printf("\n=================================\n");
    printf("Tests passed: %d\nTests failed: %d\n", tests_passed, tests_failed);
    printf("=================================\n");

    return tests_failed > 0 ? 1 : 0;
}
