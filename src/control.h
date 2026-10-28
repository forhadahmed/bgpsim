#ifndef CONTROL_H
#define CONTROL_H

#include <stddef.h>
#include "bgp.h"
#include "util.h"

#define BGPSIM_CONTROL_SOCKET_PATH BGPSIM_SOCK_PATH

// Control Protocol

#define BGPSIM_CONTROL_VERSION "4"
#define BGPSIM_CONTROL_MAX_PAYLOAD (1024u * 1024u)

typedef enum {
    BGPSIM_CTRL_SYN          = 1,
    BGPSIM_CTRL_ACK          = 2,
    BGPSIM_CTRL_EXEC_REQ     = 3,
    BGPSIM_CTRL_STDOUT_CHUNK = 4,
    BGPSIM_CTRL_STDERR_CHUNK = 5,
    BGPSIM_CTRL_EXEC_DONE    = 6,
    BGPSIM_CTRL_EVENT        = 7,
    BGPSIM_CTRL_ERROR        = 8
} bgpsim_control_msg_type_t;

typedef struct {
    uint16_t type;
    uint32_t payload_len;
    uint8_t *payload;
} bgpsim_control_frame_t;

typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} bgpsim_control_decoder_t;

typedef struct {
    int           status;
    cli_mode_t    mode;
    cli_session_t session;
} bgpsim_exec_done_t;

void bgpsim_control_frame_reset(bgpsim_control_frame_t *frame);
void bgpsim_control_decoder_init(bgpsim_control_decoder_t *decoder);
void bgpsim_control_decoder_reset(bgpsim_control_decoder_t *decoder);
void bgpsim_control_decoder_free(bgpsim_control_decoder_t *decoder);
int bgpsim_control_decoder_append(bgpsim_control_decoder_t *decoder, const void *data, size_t len);
int bgpsim_control_decoder_next(bgpsim_control_decoder_t *decoder, bgpsim_control_frame_t *frame);
int bgpsim_control_build_frame(uint16_t type, const void *payload, uint32_t payload_len,
                               uint8_t **out_buf, size_t *out_len);
size_t bgpsim_control_exec_done_payload_len(void);
int bgpsim_control_encode_exec_done(uint8_t *buf, size_t buf_len, const bgpsim_exec_done_t *done);
int bgpsim_control_decode_exec_done(const uint8_t *buf, size_t buf_len, bgpsim_exec_done_t *done);

// Control Client

typedef struct {
    int                      fd;
    bgpsim_control_decoder_t decoder;
} bgpsim_control_client_t;

typedef void (*bgpsim_control_chunk_cb)(void *opaque, output_stream_t stream, const char *data, size_t len);
typedef void (*bgpsim_control_event_cb)(void *opaque, const char *data, size_t len);

void bgpsim_control_build_socket_path(const char *session_name, char *socket_path, size_t socket_path_size);
int bgpsim_control_connect(const char *socket_path);
int bgpsim_control_client_open(bgpsim_control_client_t *client, const char *socket_path);
void bgpsim_control_client_close(bgpsim_control_client_t *client);
int bgpsim_control_client_fd(const bgpsim_control_client_t *client);
int bgpsim_control_client_execute(bgpsim_control_client_t *client, const char *command, cli_mode_t *mode,
                                  cli_session_t *session, bgpsim_control_chunk_cb chunk_cb,
                                  bgpsim_control_event_cb event_cb, void *opaque, int *status_out);
int bgpsim_control_client_drain_events(bgpsim_control_client_t *client, bgpsim_control_event_cb event_cb, void *opaque);
int bgpsim_control_execute(int fd, const char *command, char **output);
int check_socket_active(const char *socket_path);

// Runtime Wrapper

int bgpsim_control_init(bgp_sim_t *sim, const char *socket_path);
void bgpsim_control_shutdown(void);

#endif /* CONTROL_H */
