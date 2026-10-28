#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "control.h"
#include "runtime.h"

// Control Protocol Helpers

#define BGPSIM_CONTROL_HEADER_LEN     8u

static uint32_t bgpsim_control_read_u32(const uint8_t *buf) {
    uint32_t value;

    memcpy(&value, buf, sizeof(value));
    return ntohl(value);
}

static void bgpsim_control_write_u32(uint8_t *buf, uint32_t value) {
    value = htonl(value);
    memcpy(buf, &value, sizeof(value));
}

void bgpsim_control_frame_reset(bgpsim_control_frame_t *frame) {
    if (!frame) {
        return;
    }

    free(frame->payload);
    memset(frame, 0, sizeof(*frame));
}

void bgpsim_control_decoder_init(bgpsim_control_decoder_t *decoder) {
    if (!decoder) {
        return;
    }

    memset(decoder, 0, sizeof(*decoder));
}

void bgpsim_control_decoder_reset(bgpsim_control_decoder_t *decoder) {
    if (!decoder) {
        return;
    }

    decoder->len = 0;
}

void bgpsim_control_decoder_free(bgpsim_control_decoder_t *decoder) {
    if (!decoder) {
        return;
    }

    free(decoder->data);
    memset(decoder, 0, sizeof(*decoder));
}

int bgpsim_control_decoder_append(bgpsim_control_decoder_t *decoder, const void *data, size_t len) {
    size_t   needed;
    size_t   new_cap;
    uint8_t *new_data;

    if (!decoder || !data || len == 0) {
        return 0;
    }

    needed = decoder->len + len;
    if (needed > decoder->cap) {
        new_cap = decoder->cap ? decoder->cap : 1024;
        while (new_cap < needed) {
            new_cap *= 2;
        }

        new_data = realloc(decoder->data, new_cap);
        if (!new_data) {
            return -1;
        }

        decoder->data = new_data;
        decoder->cap = new_cap;
    }

    memcpy(decoder->data + decoder->len, data, len);
    decoder->len += len;
    return 0;
}

int bgpsim_control_decoder_next(bgpsim_control_decoder_t *decoder, bgpsim_control_frame_t *frame) {
    uint32_t type;
    uint32_t payload_len;
    size_t   total_len;
    uint8_t *payload = NULL;

    if (!decoder || !frame) {
        return -1;
    }

    if (decoder->len < BGPSIM_CONTROL_HEADER_LEN) {
        return 0;
    }

    type = bgpsim_control_read_u32(decoder->data);
    if (type < BGPSIM_CTRL_SYN || type > BGPSIM_CTRL_ERROR) {
        return -1;
    }

    payload_len = bgpsim_control_read_u32(decoder->data + 4);
    if (payload_len > BGPSIM_CONTROL_MAX_PAYLOAD) {
        return -1;
    }

    total_len = BGPSIM_CONTROL_HEADER_LEN + (size_t)payload_len;
    if (decoder->len < total_len) {
        return 0;
    }

    bgpsim_control_frame_reset(frame);
    frame->type = (uint16_t)type;
    frame->payload_len = payload_len;

    if (payload_len > 0) {
        payload = malloc(payload_len);
        if (!payload) {
            return -1;
        }
        memcpy(payload, decoder->data + BGPSIM_CONTROL_HEADER_LEN, (size_t)payload_len);
    }

    frame->payload = payload;

    memmove(decoder->data, decoder->data + total_len, decoder->len - total_len);
    decoder->len -= total_len;
    return 1;
}

int bgpsim_control_build_frame(uint16_t type, const void *payload, uint32_t payload_len,
                               uint8_t **out_buf, size_t *out_len) {
    uint8_t *buf;
    size_t   total_len;

    if (!out_buf || !out_len || payload_len > BGPSIM_CONTROL_MAX_PAYLOAD ||
        type < BGPSIM_CTRL_SYN || type > BGPSIM_CTRL_ERROR) {
        return -1;
    }

    total_len = BGPSIM_CONTROL_HEADER_LEN + (size_t)payload_len;
    buf = malloc(total_len);
    if (!buf) {
        return -1;
    }

    bgpsim_control_write_u32(buf, type);
    bgpsim_control_write_u32(buf + 4, payload_len);

    if (payload_len > 0 && payload) {
        memcpy(buf + BGPSIM_CONTROL_HEADER_LEN, payload, payload_len);
    }

    *out_buf = buf;
    *out_len = total_len;
    return 0;
}

typedef struct {
    size_t offset;
    size_t size;
    int    string;
} exec_done_field_t;

#define EXEC_FIELD(member, text) \
    {offsetof(bgpsim_exec_done_t, member), sizeof(((bgpsim_exec_done_t *)0)->member), text}

/* The field order is the wire schema, independent of C padding. */
static const exec_done_field_t exec_done_fields[] = {
    EXEC_FIELD(status, 0), EXEC_FIELD(mode, 0),
    EXEC_FIELD(session.config_mode, 0), EXEC_FIELD(session.terminal_monitor, 0),
    EXEC_FIELD(session.has_router, 0), EXEC_FIELD(session.current_router_as, 0),
    EXEC_FIELD(session.has_neighbor, 0), EXEC_FIELD(session.current_neighbor_ip, 1),
    EXEC_FIELD(session.has_ribout, 0), EXEC_FIELD(session.current_ribout_name, 1),
    EXEC_FIELD(session.mode_stack_depth, 0), EXEC_FIELD(session.mode_stack, 0),
    EXEC_FIELD(session.current_script_name, 1)
};
#undef EXEC_FIELD
STATIC_ASSERT(sizeof(int) == sizeof(uint32_t) && sizeof(cli_mode_t) == sizeof(uint32_t) &&
              sizeof(config_mode_t) == sizeof(uint32_t), "control numeric fields must be 32 bits");

size_t bgpsim_control_exec_done_payload_len(void) {
    size_t size = 0;
    for (size_t i = 0; i < sizeof(exec_done_fields) / sizeof(*exec_done_fields); i++)
        size += exec_done_fields[i].size;
    return size;
}

/*
 * Write an EXEC_DONE payload: the command status, the CLI mode and the session context, so an attached client keeps
 * its config mode. buf_len must be at least bgpsim_control_exec_done_payload_len().
 */
int bgpsim_control_encode_exec_done(uint8_t *buf, size_t buf_len, const bgpsim_exec_done_t *done) {
    size_t offset = 0;

    if (!buf || !done || buf_len < bgpsim_control_exec_done_payload_len()) {
        return -1;
    }

    memset(buf, 0, buf_len);

    for (size_t i = 0; i < sizeof(exec_done_fields) / sizeof(*exec_done_fields); i++) {
        const exec_done_field_t *field = &exec_done_fields[i];
        const uint8_t           *value = (const uint8_t *)done + field->offset;
        if (field->string) memcpy(buf + offset, value, field->size);
        else for (size_t j = 0; j < field->size; j += sizeof(uint32_t)) {
            uint32_t number;
            memcpy(&number, value + j, sizeof(number));
            bgpsim_control_write_u32(buf + offset + j, number);
        }
        offset += field->size;
    }

    // A field list that drifts from the length must fail, not overrun.
    return (offset == bgpsim_control_exec_done_payload_len()) ? 0 : -1;
}

/*
 * Read an EXEC_DONE payload written by bgpsim_control_encode_exec_done(). Returns -1 for a short payload.
 */
int bgpsim_control_decode_exec_done(const uint8_t *buf, size_t buf_len, bgpsim_exec_done_t *done) {
    size_t offset = 0;
    size_t current_size = bgpsim_control_exec_done_payload_len();
    if (!buf || !done || buf_len < current_size) {
        return -1;
    }

    memset(done, 0, sizeof(*done));

    for (size_t i = 0; i < sizeof(exec_done_fields) / sizeof(*exec_done_fields) && offset < buf_len; i++) {
        const exec_done_field_t *field = &exec_done_fields[i];
        uint8_t                 *value = (uint8_t *)done + field->offset;
        if (field->string) {
            memcpy(value, buf + offset, field->size);
            value[field->size - 1] = '\0';
        } else for (size_t j = 0; j < field->size; j += sizeof(uint32_t)) {
            uint32_t number = bgpsim_control_read_u32(buf + offset + j);
            memcpy(value + j, &number, sizeof(number));
        }
        offset += field->size;
    }
    if ((unsigned)done->session.mode_stack_depth > MAX_MODE_DEPTH)
        done->session.mode_stack_depth = MAX_MODE_DEPTH;
    return 0;
}

static bgpsim_runtime_t *g_control_runtime = NULL;

typedef struct {
    output_buffer_t buffer;
} bgpsim_control_capture_t;

static int control_send_all(int fd, const void *data, size_t len) {
    const uint8_t *ptr = data;
    size_t         sent = 0;

    while (sent < len) {
        ssize_t nwritten = send(fd, ptr + sent, len - sent, 0);
        if (nwritten < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        sent += (size_t)nwritten;
    }

    return 0;
}

static int control_recv_frame(int fd, bgpsim_control_decoder_t *decoder, bgpsim_control_frame_t *frame) {
    uint8_t buf[4096];

    if (!decoder || !frame) {
        errno = EINVAL;
        return -1;
    }

    for (;;) {
        int rc = bgpsim_control_decoder_next(decoder, frame);
        if (rc != 0) {
            return rc;
        }

        ssize_t nread = recv(fd, buf, sizeof(buf), 0);
        if (nread < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (nread == 0) {
            errno = ECONNRESET;
            return -1;
        }
        if (bgpsim_control_decoder_append(decoder, buf, (size_t)nread) != 0) {
            errno = ENOMEM;
            return -1;
        }
    }
}

static int control_send_frame_raw(int fd, uint16_t type, const void *payload, uint32_t payload_len) {
    uint8_t *frame_data = NULL;
    size_t   frame_len = 0;
    int      rc;

    rc = bgpsim_control_build_frame(type, payload, payload_len, &frame_data, &frame_len);
    if (rc != 0) {
        return -1;
    }

    rc = control_send_all(fd, frame_data, frame_len);
    free(frame_data);
    return rc;
}

static void control_capture_chunk(void *opaque, output_stream_t stream, const char *data, size_t len) {
    bgpsim_control_capture_t *capture = opaque;

    (void)stream;

    if (!capture || !data || len == 0) {
        return;
    }

    output_buffer_write(&capture->buffer, data, len);
}

static void control_ignore_event(void *opaque, const char *data, size_t len) {
    (void)opaque;
    (void)data;
    (void)len;
}

void bgpsim_control_build_socket_path(const char *session_name, char *socket_path, size_t socket_path_size) {
    const char *name = session_name;

    if (!socket_path || socket_path_size == 0) {
        return;
    }

    if (!name || name[0] == '\0') {
        name = BGPSIM;
    }

    if (strcmp(name, BGPSIM) == 0) {
        snprintf(socket_path, socket_path_size, "%s", BGPSIM_SOCK_PATH);
    } else {
        snprintf(socket_path, socket_path_size, "/tmp/" BGPSIM "_%s.sock", name);
    }
}

int bgpsim_control_connect(const char *socket_path) {
    int                fd;
    struct sockaddr_un addr;

    if (!socket_path || socket_path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    return fd;
}

int bgpsim_control_client_open(bgpsim_control_client_t *client, const char *socket_path) {
    bgpsim_control_frame_t frame = {0};
    int                    fd;

    if (!client) {
        errno = EINVAL;
        return -1;
    }

    memset(client, 0, sizeof(*client));
    client->fd = -1;
    bgpsim_control_decoder_init(&client->decoder);

    fd = bgpsim_control_connect(socket_path);
    if (fd < 0) {
        bgpsim_control_decoder_free(&client->decoder);
        return -1;
    }

    client->fd = fd;
    if (control_send_frame_raw(client->fd, BGPSIM_CTRL_SYN, NULL, 0) != 0 ||
        control_recv_frame(client->fd, &client->decoder, &frame) <= 0 ||
        frame.type != BGPSIM_CTRL_ACK) {
        bgpsim_control_frame_reset(&frame);
        bgpsim_control_client_close(client);
        return -1;
    }

    if (frame.payload_len != strlen(BGPSIM_CONTROL_VERSION) ||
        memcmp(frame.payload, BGPSIM_CONTROL_VERSION, frame.payload_len) != 0) {
        bgpsim_control_frame_reset(&frame);
        bgpsim_control_client_close(client);
        errno = EPROTONOSUPPORT;
        return -1;
    }
    bgpsim_control_frame_reset(&frame);
    return 0;
}

void bgpsim_control_client_close(bgpsim_control_client_t *client) {
    if (!client) {
        return;
    }

    if (client->fd >= 0) {
        close(client->fd);
        client->fd = -1;
    }
    bgpsim_control_decoder_free(&client->decoder);
    memset(client, 0, sizeof(*client));
    client->fd = -1;
}

int bgpsim_control_client_fd(const bgpsim_control_client_t *client) {
    return client ? client->fd : -1;
}

/*
 * Send one command and wait for its EXEC_DONE. Output chunks go to chunk_cb and events to event_cb while it runs; then
 * mode, session and the status are copied out. Returns -1 when the connection fails or the server reports a protocol
 * error.
 */
int bgpsim_control_client_execute(bgpsim_control_client_t *client, const char *command, cli_mode_t *mode,
                                  cli_session_t *session, bgpsim_control_chunk_cb chunk_cb,
                                  bgpsim_control_event_cb event_cb, void *opaque, int *status_out) {
    bgpsim_control_frame_t frame = {0};
    bgpsim_exec_done_t     done;

    if (!client || client->fd < 0 || !command) {
        errno = EINVAL;
        return -1;
    }

    if (control_send_frame_raw(client->fd, BGPSIM_CTRL_EXEC_REQ, command, (uint32_t)strlen(command)) != 0) {
        return -1;
    }

    for (;;) {
        int rc = control_recv_frame(client->fd, &client->decoder, &frame);
        if (rc <= 0) {
            bgpsim_control_frame_reset(&frame);
            return -1;
        }

        if (frame.type == BGPSIM_CTRL_STDOUT_CHUNK || frame.type == BGPSIM_CTRL_STDERR_CHUNK) {
            if (chunk_cb) {
                output_stream_t stream = frame.type == BGPSIM_CTRL_STDERR_CHUNK ? OUTPUT_STREAM_STDERR
                                                                                : OUTPUT_STREAM_STDOUT;
                chunk_cb(opaque, stream, (const char *)frame.payload, frame.payload_len);
            }
        } else if (frame.type == BGPSIM_CTRL_EVENT) {
            if (event_cb) {
                event_cb(opaque, (const char *)frame.payload, frame.payload_len);
            }
        } else if (frame.type == BGPSIM_CTRL_ERROR) {
            bgpsim_control_frame_reset(&frame);
            errno = EPROTO;
            return -1;
        } else if (frame.type == BGPSIM_CTRL_EXEC_DONE) {
            if (bgpsim_control_decode_exec_done(frame.payload, frame.payload_len, &done) != 0) {
                bgpsim_control_frame_reset(&frame);
                errno = EPROTO;
                return -1;
            }

            if (mode) {
                *mode = done.mode;
            }
            if (session) {
                *session = done.session;
            }
            if (status_out) {
                *status_out = done.status;
            }

            bgpsim_control_frame_reset(&frame);
            return 0;
        }

        bgpsim_control_frame_reset(&frame);
    }
}

/*
 * Read what the server has sent without waiting, and pass any complete EVENT frames to event_cb. Returns -1 when the
 * connection is closed or fails.
 */
int bgpsim_control_client_drain_events(bgpsim_control_client_t *client, bgpsim_control_event_cb event_cb,
                                       void *opaque) {
    bgpsim_control_frame_t frame = {0};
    uint8_t                buf[4096];

    if (!client || client->fd < 0) {
        errno = EINVAL;
        return -1;
    }

    for (;;) {
        ssize_t nread = recv(client->fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (nread < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (nread == 0) {
            errno = ECONNRESET;
            return -1;
        }
        if (bgpsim_control_decoder_append(&client->decoder, buf, (size_t)nread) != 0) {
            errno = ENOMEM;
            return -1;
        }
        if ((size_t)nread < sizeof(buf)) {
            break;
        }
    }

    for (;;) {
        int rc = bgpsim_control_decoder_next(&client->decoder, &frame);
        if (rc == 0) {
            return 0;
        }
        if (rc < 0) {
            errno = EPROTO;
            return -1;
        }

        if (frame.type == BGPSIM_CTRL_EVENT) {
            if (event_cb) {
                event_cb(opaque, (const char *)frame.payload, frame.payload_len);
            }
        } else {
            bgpsim_control_frame_reset(&frame);
            errno = EPROTO;
            return -1;
        }

        bgpsim_control_frame_reset(&frame);
    }
}

int bgpsim_control_execute(int fd, const char *command, char **output) {
    bgpsim_control_client_t  client;
    bgpsim_control_capture_t capture;
    cli_mode_t               mode = CLI_MODE_EXEC;
    cli_session_t            session;
    int                      status = 0;

    if (!command || !output) {
        errno = EINVAL;
        return -1;
    }

    memset(&client, 0, sizeof(client));
    client.fd = fd;
    bgpsim_control_decoder_init(&client.decoder);
    output_buffer_init(&capture.buffer);
    cli_session_init(&session);

    if (control_send_frame_raw(fd, BGPSIM_CTRL_SYN, NULL, 0) != 0) {
        output_buffer_free(&capture.buffer);
        bgpsim_control_decoder_free(&client.decoder);
        return -1;
    }

    {
        bgpsim_control_frame_t frame = {0};
        int                    rc = control_recv_frame(fd, &client.decoder, &frame);
        if (rc <= 0 || frame.type != BGPSIM_CTRL_ACK) {
            bgpsim_control_frame_reset(&frame);
            output_buffer_free(&capture.buffer);
            bgpsim_control_decoder_free(&client.decoder);
            errno = EPROTO;
            return -1;
        }
        bgpsim_control_frame_reset(&frame);
    }

    if (bgpsim_control_client_execute(&client, command, &mode, &session, control_capture_chunk, control_ignore_event,
                                      &capture, &status) != 0) {
        output_buffer_free(&capture.buffer);
        bgpsim_control_decoder_free(&client.decoder);
        return -1;
    }

    *output = capture.buffer.data ? capture.buffer.data : strdup("");
    bgpsim_control_decoder_free(&client.decoder);
    return status;
}

int check_socket_active(const char *socket_path) {
    int fd = bgpsim_control_connect(socket_path);

    if (fd < 0) {
        return 0;
    }

    close(fd);
    return 1;
}

int bgpsim_control_init(bgp_sim_t *sim, const char *socket_path) {
    if (!sim || !socket_path) {
        errno = EINVAL;
        return -1;
    }

    if (sim->runtime) {
        g_control_runtime = sim->runtime;
        return 0;
    }

    if (bgpsim_runtime_start(&sim->runtime, sim, socket_path) != 0) {
        return -1;
    }

    g_control_runtime = sim->runtime;
    return 0;
}

void bgpsim_control_shutdown(void) {
    bgpsim_runtime_t *runtime = g_control_runtime;

    if (!g_control_runtime) {
        return;
    }

    g_control_runtime = NULL;
    /*
     * Loop callbacks read sim->runtime until the loop thread ends (an accept or a reconnect can still run): stop and
     * join it first. bgpsim_runtime_destroy() then clears the pointer.
     */
    bgpsim_runtime_request_shutdown(runtime);
    bgpsim_runtime_join(runtime);
    bgpsim_runtime_destroy(runtime);
}
