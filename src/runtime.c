#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <unistd.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "bgp.h"
#include "log.h"
#include "util.h"
#include "control.h"
#include "runtime.h"
#include "tx_exec.h"
#include "commands.h"
#include "bgp_peer_tx.h"
#include "script_exec.h"

#define BGPSIM_CONTROL_BACKLOG         64
#define BGPSIM_CONNECT_TIMEOUT_MS      2000
#define BGPSIM_OPEN_TIMEOUT_MS         5000
#define BGPSIM_NOTIFICATION_TIMEOUT_MS 5000
#define BGPSIM_MONITOR_QUEUE_LIMIT     128
#define BGPSIM_LISTEN_RETRY_MIN_MS     100   /* First retry of a passive listener that did not open */
#define BGPSIM_LISTEN_RETRY_MAX_MS     5000  /* Retries back off to this interval                   */

typedef struct bgpsim_control_write {
    uv_write_t                   req;
    struct bgpsim_control_write *next;
    bgpsim_control_session_t    *session;
    uint8_t                     *data;
    size_t                       len;
    int                          is_monitor_event;
} bgpsim_control_write_t;

typedef struct bgpsim_exec_output {
    output_t                  output;
    bgpsim_control_session_t *session;
} bgpsim_exec_output_t;

typedef struct bgpsim_peer_write {
    uv_write_t                req;
    struct bgpsim_peer_write *next;
    bgp_neighbor_t           *neighbor;
    uint8_t                  *data;
    size_t                    len;
    uint8_t                   msg_type;
    uint64_t                  session_epoch;
} bgpsim_peer_write_t;

struct bgpsim_control_session {
    bgpsim_runtime_t              *runtime;
    uv_pipe_t                      handle;
    bgpsim_control_decoder_t       decoder;
    cli_mode_t                     mode;
    cli_session_t                  session;
    bgpsim_control_write_t        *write_head;
    bgpsim_control_write_t        *write_tail;
    bgpsim_control_write_t        *write_active;
    size_t                         queued_writes;
    int                            write_in_flight;
    int                            closing;
    int                            handshake_complete;
    struct bgpsim_control_session *next;
};

typedef enum {
    RUNTIME_PEER_MSG_PROTOCOL_ERROR = -1,
    RUNTIME_PEER_MSG_OK             = 0,
    RUNTIME_PEER_MSG_RESET          = 1
} runtime_peer_msg_result_t;

static void runtime_reconcile_internal(bgpsim_runtime_t *runtime);
static void runtime_try_finalize_router(bgp_router_t *router);
static void runtime_try_finalize_neighbor(bgp_neighbor_t *neighbor);
static void runtime_peer_reconnect_timer_cb(uv_timer_t *timer);
static void runtime_peer_connect_timer_cb(uv_timer_t *timer);
static void runtime_peer_open_timer_cb(uv_timer_t *timer);
static void runtime_peer_hold_timer_cb(uv_timer_t *timer);
static void runtime_peer_keepalive_timer_cb(uv_timer_t *timer);
static void runtime_peer_notification_timer_cb(uv_timer_t *timer);
static void runtime_listener_on_connection(uv_stream_t *server, int status);
static void runtime_listener_stop(bgp_router_t *router);
static void runtime_control_on_close(uv_handle_t *handle);

static time_t runtime_retry_interval_seconds(int retry_count) {
    if (retry_count <= 0) {
        return BGP_MIN_RETRY_INTERVAL;
    }

    time_t interval = BGP_MIN_RETRY_INTERVAL * (retry_count + 1);
    return interval > BGP_MAX_RETRY_INTERVAL ? BGP_MAX_RETRY_INTERVAL : interval;
}

static int runtime_neighbor_is_local_test_address(const char *ip) {
    struct in_addr  addr4;
    struct in6_addr addr6;
    uint32_t        addr4_host;
    static const uint8_t ipv6_test_prefix[] = {0xfd, 0x00, 0x7f, 0x00};

    if (!ip) {
        return 0;
    }

    if (strcmp(ip, "localhost") == 0) {
        return 1;
    }

    if (inet_pton(AF_INET, ip, &addr4) == 1) {
        addr4_host = ntohl(addr4.s_addr);
        return (addr4_host >> 24) == 127;
    }

    if (inet_pton(AF_INET6, ip, &addr6) == 1) {
        return IN6_IS_ADDR_LOOPBACK(&addr6) ||
               memcmp(addr6.s6_addr, ipv6_test_prefix, sizeof(ipv6_test_prefix)) == 0;
    }

    return 0;
}

static int runtime_neighbor_passive_only(const bgp_router_t *router, const bgp_neighbor_t *neighbor) {
    if (!router || !router->sim || !router->sim->passive_mode) {
        return 0;
    }

    return runtime_neighbor_is_local_test_address(neighbor->ip);
}

static void runtime_control_session_remove(bgpsim_runtime_t *runtime, bgpsim_control_session_t *session) {
    bgpsim_control_session_t **current = &runtime->sessions;

    while (*current) {
        if (*current == session) {
            *current = session->next;
            session->next = NULL;
            return;
        }
        current = &(*current)->next;
    }
}

static void runtime_control_write_free(bgpsim_control_write_t *write) {
    if (!write) {
        return;
    }

    free(write->data);
    free(write);
}

static void runtime_control_session_start_next_write(bgpsim_control_session_t *session);

static void runtime_control_on_write(uv_write_t *req, int status) {
    bgpsim_control_write_t   *write = req ? req->data : NULL;
    bgpsim_control_session_t *session = write ? write->session : NULL;

    if (!write || !session) {
        return;
    }

    session->write_in_flight = 0;
    session->write_active = NULL;
    if (session->queued_writes > 0) {
        session->queued_writes--;
    }

    if (status < 0 && !session->closing) {
        session->closing = 1;
        uv_read_stop((uv_stream_t *)&session->handle);
        uv_close((uv_handle_t *)&session->handle, runtime_control_on_close);
    }

    runtime_control_write_free(write);
    runtime_control_session_start_next_write(session);
}

static void runtime_control_session_start_next_write(bgpsim_control_session_t *session) {
    bgpsim_control_write_t *write;
    uv_buf_t                buf;
    int                     rc;

    if (!session || session->write_in_flight || session->closing) {
        return;
    }

    write = session->write_head;
    if (!write) {
        return;
    }

    session->write_head = write->next;
    if (!session->write_head) {
        session->write_tail = NULL;
    }
    write->next = NULL;
    session->write_active = write;
    session->write_in_flight = 1;

    buf = uv_buf_init((char *)write->data, (unsigned int)write->len);
    write->req.data = write;
    rc = uv_write(&write->req, (uv_stream_t *)&session->handle, &buf, 1, runtime_control_on_write);
    if (rc < 0) {
        session->write_in_flight = 0;
        session->write_active = NULL;
        runtime_control_write_free(write);
        if (!session->closing) {
            session->closing = 1;
            uv_read_stop((uv_stream_t *)&session->handle);
            uv_close((uv_handle_t *)&session->handle, runtime_control_on_close);
        }
    }
}

static int runtime_control_session_queue_frame(bgpsim_control_session_t *session, uint16_t type,
                                               const void *payload, uint32_t payload_len, int is_monitor_event) {
    bgpsim_control_write_t *write;

    if (!session || session->closing) {
        return -1;
    }

    if (is_monitor_event && session->queued_writes >= BGPSIM_MONITOR_QUEUE_LIMIT) {
        return -1;
    }

    write = calloc(1, sizeof(*write));
    if (!write) {
        return -1;
    }

    if (bgpsim_control_build_frame(type, payload, payload_len, &write->data, &write->len) != 0) {
        free(write);
        return -1;
    }

    write->session = session;
    write->is_monitor_event = is_monitor_event;

    if (session->write_tail) {
        session->write_tail->next = write;
    } else {
        session->write_head = write;
    }
    session->write_tail = write;
    session->queued_writes++;
    runtime_control_session_start_next_write(session);
    return 0;
}

static void runtime_control_session_send_error(bgpsim_control_session_t *session, const char *message) {
    runtime_control_session_queue_frame(session, BGPSIM_CTRL_ERROR, message,
                                        message ? (uint32_t)strlen(message) : 0, 0);
}

static void runtime_control_output_write(void *opaque, output_stream_t stream, const char *data, size_t len) {
    bgpsim_exec_output_t *exec_output = opaque;
    uint16_t              type = stream == OUTPUT_STREAM_STDERR ? BGPSIM_CTRL_STDERR_CHUNK : BGPSIM_CTRL_STDOUT_CHUNK;

    if (!exec_output || !data || len == 0) {
        return;
    }

    runtime_control_session_queue_frame(exec_output->session, type, data, (uint32_t)len, 0);
}

static void runtime_control_session_send_exec_done(bgpsim_control_session_t *session, int status) {
    bgpsim_exec_done_t done;
    uint8_t            payload[sizeof(bgpsim_exec_done_t)];

    memset(&done, 0, sizeof(done));
    done.status = status;
    done.mode = session->mode;
    done.session = session->session;

    if (bgpsim_control_encode_exec_done(payload, sizeof(payload), &done) == 0) {
        runtime_control_session_queue_frame(session, BGPSIM_CTRL_EXEC_DONE, payload,
                                            (uint32_t)bgpsim_control_exec_done_payload_len(), 0);
    }
}

static void runtime_control_handle_exec(bgpsim_control_session_t *session, const bgpsim_control_frame_t *frame) {
    char                *command;
    bgpsim_exec_output_t exec_output;
    int                  status;

    if (!session || !frame) {
        return;
    }

    if (!session->handshake_complete) {
        runtime_control_session_send_error(session, "SYN required before EXEC");
        return;
    }

    if (!command_input_valid((const char *)frame->payload, frame->payload_len)) {
        const char *error = "Error: invalid command input or command too long\n";
        runtime_control_session_queue_frame(session, BGPSIM_CTRL_STDERR_CHUNK, error, (uint32_t)strlen(error), 0);
        runtime_control_session_send_exec_done(session, -1);
        return;
    }

    command = calloc((size_t)frame->payload_len + 1, 1);
    if (!command) {
        runtime_control_session_send_error(session, "Out of memory");
        return;
    }

    if (frame->payload_len) memcpy(command, frame->payload, frame->payload_len);
    exec_output.session = session;
    exec_output.output.write = runtime_control_output_write;
    exec_output.output.opaque = &exec_output;

    status = cli_process_command_with_output(&session->session, session->runtime->sim, &session->mode, command,
                                             &exec_output.output);
    runtime_control_session_send_exec_done(session, status);
    free(command);

    if (session->runtime->sim->shutdown) {
        bgpsim_runtime_request_shutdown(session->runtime);
    }
}

static void runtime_control_handle_syn(bgpsim_control_session_t *session, const bgpsim_control_frame_t *frame) {
    (void)frame;

    runtime_control_session_queue_frame(session, BGPSIM_CTRL_ACK, BGPSIM_CONTROL_VERSION,
                                        (uint32_t)strlen(BGPSIM_CONTROL_VERSION), 0);
    session->handshake_complete = 1;
}

static void runtime_control_handle_frame(bgpsim_control_session_t *session, const bgpsim_control_frame_t *frame) {
    if (!session || !frame) {
        return;
    }

    switch (frame->type) {
        case BGPSIM_CTRL_SYN:
            runtime_control_handle_syn(session, frame);
            break;
        case BGPSIM_CTRL_EXEC_REQ:
            runtime_control_handle_exec(session, frame);
            break;
        default:
            runtime_control_session_send_error(session, "Unsupported control message");
            break;
    }
}

static void runtime_control_on_close(uv_handle_t *handle) {
    bgpsim_control_session_t *session = handle ? handle->data : NULL;
    bgpsim_control_write_t   *write;

    if (!session) {
        return;
    }

    runtime_control_session_remove(session->runtime, session);
    bgpsim_control_decoder_free(&session->decoder);

    if (session->write_active) {
        runtime_control_write_free(session->write_active);
    }

    write = session->write_head;
    while (write) {
        bgpsim_control_write_t *next = write->next;
        runtime_control_write_free(write);
        write = next;
    }

    free(session);
}

static void runtime_control_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    (void)handle;
    buf->base = malloc(suggested_size > 0 ? suggested_size : 1024);
    buf->len = buf->base ? suggested_size : 0;
}

static void runtime_control_on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    bgpsim_control_session_t *session = stream ? stream->data : NULL;
    bgpsim_control_frame_t    frame = {0};

    if (!session) {
        free(buf->base);
        return;
    }

    if (nread < 0) {
        free(buf->base);
        if (!session->closing) {
            session->closing = 1;
            uv_read_stop(stream);
            uv_close((uv_handle_t *)&session->handle, runtime_control_on_close);
        }
        return;
    }

    if (nread == 0) {
        free(buf->base);
        return;
    }

    if (bgpsim_control_decoder_append(&session->decoder, buf->base, (size_t)nread) != 0) {
        free(buf->base);
        runtime_control_session_send_error(session, "Failed to buffer input");
        if (!session->closing) {
            session->closing = 1;
            uv_read_stop(stream);
            uv_close((uv_handle_t *)&session->handle, runtime_control_on_close);
        }
        return;
    }

    free(buf->base);

    for (;;) {
        int rc = bgpsim_control_decoder_next(&session->decoder, &frame);
        if (rc <= 0) {
            if (rc < 0) {
                runtime_control_session_send_error(session, "Invalid control frame");
                if (!session->closing) {
                    session->closing = 1;
                    uv_read_stop(stream);
                    uv_close((uv_handle_t *)&session->handle, runtime_control_on_close);
                }
            }
            break;
        }

        runtime_control_handle_frame(session, &frame);
        bgpsim_control_frame_reset(&frame);
    }
}

static void runtime_control_on_connection(uv_stream_t *server, int status) {
    bgpsim_runtime_t         *runtime = server ? server->data : NULL;
    bgpsim_control_session_t *session;
    int                       rc;

    if (!runtime || status < 0) {
        return;
    }

    session = calloc(1, sizeof(*session));
    if (!session) {
        return;
    }

    session->runtime = runtime;
    session->mode = CLI_MODE_EXEC;
    cli_session_init(&session->session);
    bgpsim_control_decoder_init(&session->decoder);

    rc = uv_pipe_init(&runtime->loop, &session->handle, 0);
    if (rc < 0) {
        bgpsim_control_decoder_free(&session->decoder);
        free(session);
        return;
    }

    session->handle.data = session;
    rc = uv_accept(server, (uv_stream_t *)&session->handle);
    if (rc < 0) {
        uv_close((uv_handle_t *)&session->handle, runtime_control_on_close);
        return;
    }

    session->next = runtime->sessions;
    runtime->sessions = session;
    uv_read_start((uv_stream_t *)&session->handle, runtime_control_alloc, runtime_control_on_read);
}

static int runtime_control_server_start(bgpsim_runtime_t *runtime) {
    int rc;

    unlink(runtime->socket_path);

    rc = uv_pipe_init(&runtime->loop, &runtime->control_server, 0);
    if (rc < 0) {
        return rc;
    }

    runtime->control_server_initialized = 1;
    runtime->control_server.data = runtime;

    rc = uv_pipe_bind(&runtime->control_server, runtime->socket_path);
    if (rc < 0) {
        return rc;
    }

    rc = uv_listen((uv_stream_t *)&runtime->control_server, BGPSIM_CONTROL_BACKLOG, runtime_control_on_connection);
    if (rc < 0) {
        return rc;
    }

    runtime->control_server_listening = 1;
    return 0;
}

static void runtime_peer_free_rx(bgp_neighbor_t *neighbor) {
    free(neighbor->rx_data);
    neighbor->rx_data = NULL;
    neighbor->rx_len = 0;
    neighbor->rx_cap = 0;
}

static void runtime_peer_free_pending_writes(bgp_neighbor_t *neighbor) {
    bgpsim_peer_write_t *write = neighbor->tx_head;

    while (write) {
        bgpsim_peer_write_t *next = write->next;
        free(write->data);
        free(write);
        write = next;
    }

    neighbor->tx_head = NULL;
    neighbor->tx_tail = NULL;
}

static void runtime_peer_write_free(bgpsim_peer_write_t *write) {
    if (!write) {
        return;
    }

    free(write->data);
    free(write);
}

static void runtime_peer_schedule_reconnect(bgp_neighbor_t *neighbor, uint64_t delay_ms);
static void runtime_peer_reset(bgp_neighbor_t *neighbor, int record_reset, int schedule_reconnect, const char *reason);

static void runtime_peer_emit_adjchange(bgp_neighbor_t *neighbor, const char *text) {
    bgpsim_runtime_t *runtime;

    if (!neighbor || !neighbor->router || !neighbor->router->sim) {
        return;
    }

    runtime = neighbor->router->sim->runtime;
    if (!runtime) {
        return;
    }

    bgpsim_runtime_emit_event_line(runtime, neighbor->router->local_as, neighbor->ip, text);
}

/*
 * Report a NOTIFICATION received or sent: a "%BGP-3-NOTIFICATION" event line for the log and terminal monitors.
 */
static void runtime_peer_emit_notification(bgp_neighbor_t *neighbor, const char *direction,
                                           const bgp_notification_record_t *record) {
    char reason[400];
    char text[512];

    if (!neighbor->router || !neighbor->router->sim || !neighbor->router->sim->runtime) {
        return;
    }
    bgp_notification_describe(record, reason, sizeof(reason));
    snprintf(text, sizeof(text), "%%BGP-3-NOTIFICATION: %s neighbor %s %s", direction, neighbor->ip, reason);
    bgpsim_runtime_emit_event_line(neighbor->router->sim->runtime, neighbor->router->local_as, NULL, text);
}

/*
 * Count a received NOTIFICATION and keep its code, subcode and Shutdown Communication.
 */
static void runtime_peer_note_rx_notification(bgp_neighbor_t *neighbor, const uint8_t *msg, size_t msg_len) {
    neighbor->rx_notification++;
    bgp_notification_record(&neighbor->last_notification_rx, msg + BGP_HEADER_SIZE, msg_len - BGP_HEADER_SIZE);
}

static void runtime_peer_handle_notification_reset(bgp_neighbor_t *neighbor) {
    bgp_state_t state;
    uint64_t    reset_count;
    time_t      uptime_seconds = 0;
    char        reason[400];

    if (!neighbor) {
        return;
    }

    runtime_peer_emit_notification(neighbor, "received from", &neighbor->last_notification_rx);
    bgp_notification_describe(&neighbor->last_notification_rx, reason, sizeof(reason));
    state = neighbor->state;
    reset_count = neighbor->session_resets + 1;
    if (state == BGP_STATE_ESTABLISHED && neighbor->uptime > 0) {
        uptime_seconds = time(NULL) - neighbor->uptime;
    }

    runtime_peer_reset(neighbor, 1, 1, state == BGP_STATE_ESTABLISHED ? "Down - received NOTIFICATION" : NULL);

    LOG_INFO("BGP session reset: Received NOTIFICATION %s from %s in %s state (reset #%" PRIu64 ")", reason,
             neighbor->ip, bgp_state_to_string(state), reset_count);
    if (uptime_seconds > 0) {
        LOG_INFO("Session was up for %ld seconds before reset", (long)uptime_seconds);
    }
    LOG_INFO("Session statistics preserved - Total messages: RX(OPEN:%" PRIu64 " UPDATE:%" PRIu64
             " KEEPALIVE:%" PRIu64 " NOTIFY:%" PRIu64 ") TX(OPEN:%" PRIu64 " UPDATE:%" PRIu64
             " KEEPALIVE:%" PRIu64 " NOTIFY:%" PRIu64 ")",
             neighbor->rx_open, neighbor->rx_update, neighbor->rx_keepalive, neighbor->rx_notification,
             neighbor->tx_open, neighbor->tx_update, neighbor->tx_keepalive, neighbor->tx_notification);
}

static void runtime_peer_update_socket_fd(bgp_neighbor_t *neighbor) {
    uv_os_fd_t fd = -1;

    if (!neighbor->stream_open) {
        neighbor->sock_fd = -1;
        return;
    }

    if (uv_fileno((const uv_handle_t *)&neighbor->stream, &fd) == 0) {
        neighbor->sock_fd = (int)fd;
    } else {
        neighbor->sock_fd = -1;
    }
}

static int runtime_peer_ensure_base(bgpsim_runtime_t *runtime, bgp_neighbor_t *neighbor) {
    int rc;

    if (neighbor->runtime_initialized) {
        return 0;
    }

    if (!neighbor->tx) {
        neighbor->tx = bgp_peer_tx_create();
        if (!neighbor->tx) {
            return UV_ENOMEM;
        }
        neighbor->tx->batch.req.data = neighbor;
    }

    rc = uv_timer_init(&runtime->loop, &neighbor->reconnect_timer);
    if (rc < 0) {
        return rc;
    }
    rc = uv_timer_init(&runtime->loop, &neighbor->connect_timer);
    if (rc < 0) {
        return rc;
    }
    rc = uv_timer_init(&runtime->loop, &neighbor->open_timer);
    if (rc < 0) {
        return rc;
    }
    rc = uv_timer_init(&runtime->loop, &neighbor->hold_timer);
    if (rc < 0) {
        return rc;
    }
    rc = uv_timer_init(&runtime->loop, &neighbor->keepalive_timer);
    if (rc < 0) {
        return rc;
    }

    neighbor->reconnect_timer.data = neighbor;
    neighbor->connect_timer.data = neighbor;
    neighbor->open_timer.data = neighbor;
    neighbor->hold_timer.data = neighbor;
    neighbor->keepalive_timer.data = neighbor;
    neighbor->runtime_initialized = 1;
    neighbor->stream_initialized = 0;
    neighbor->stream_open = 0;
    neighbor->read_started = 0;
    neighbor->connect_pending = 0;
    neighbor->closing = 0;
    neighbor->destroy_pending = 0;
    neighbor->close_refs = 0;
    neighbor->pending_reconnect = 0;
    neighbor->write_in_flight = 0;
    neighbor->notification_pending = 0;
    neighbor->state = BGP_STATE_IDLE;
    neighbor->sock_fd = -1;
    return 0;
}

static int runtime_peer_init_stream(bgpsim_runtime_t *runtime, bgp_neighbor_t *neighbor) {
    int rc;

    if (neighbor->stream_initialized) {
        return 0;
    }

    rc = uv_tcp_init(&runtime->loop, &neighbor->stream);
    if (rc < 0) {
        return rc;
    }

    neighbor->stream.data = neighbor;
    neighbor->stream_initialized = 1;
    return 0;
}

static void runtime_peer_pump(bgp_neighbor_t *neighbor);
static void runtime_peer_reset(bgp_neighbor_t *neighbor, int record_reset, int schedule_reconnect, const char *reason);

static void runtime_peer_on_write(uv_write_t *req, int status) {
    bgpsim_peer_write_t *write = req ? req->data : NULL;
    bgp_neighbor_t      *neighbor = write ? write->neighbor : NULL;
    int                  notification_complete;

    if (!write || !neighbor) {
        return;
    }

    neighbor->write_in_flight = 0;
    neighbor->tx_active = NULL;
    notification_complete = status == 0 && write->session_epoch == neighbor->session_epoch &&
                            write->msg_type == BGP_MSG_NOTIFICATION && neighbor->notification_pending;

    if (status == 0 && write->session_epoch == neighbor->session_epoch) {
        switch (write->msg_type) {
            case BGP_MSG_OPEN:
                neighbor->tx_open++;
                break;
            case BGP_MSG_KEEPALIVE:
                neighbor->tx_keepalive++;
                neighbor->last_keepalive_sent = time(NULL);
                break;
            case BGP_MSG_NOTIFICATION:
                neighbor->tx_notification++;
                bgp_notification_record(&neighbor->last_notification_tx, write->data + BGP_HEADER_SIZE,
                                        write->len - BGP_HEADER_SIZE);
                runtime_peer_emit_notification(neighbor, "sent to", &neighbor->last_notification_tx);
                break;
            case BGP_MSG_UPDATE:
                neighbor->tx_update++;
                break;
        }
    } else if (status < 0 && write->session_epoch == neighbor->session_epoch) {
        runtime_peer_reset(neighbor, 1, 1, "Down - write failed");
    }

    runtime_peer_write_free(write);
    if (notification_complete) {
        runtime_peer_reset(neighbor, 1, 1, "Down - sent NOTIFICATION");
    } else {
        runtime_peer_pump(neighbor);
    }
}

static int runtime_peer_queue_message(bgp_neighbor_t *neighbor, const uint8_t *data, size_t len, uint8_t msg_type) {
    bgpsim_peer_write_t *write;

    // A reset closes the stream at once but stream_open stays set until the close callback.
    if (!neighbor || !neighbor->stream_open || neighbor->closing || !data || len == 0) {
        return -1;
    }

    write = calloc(1, sizeof(*write));
    if (!write) {
        return -1;
    }

    write->data = malloc(len);
    if (!write->data) {
        free(write);
        return -1;
    }

    memcpy(write->data, data, len);
    write->len = len;
    write->msg_type = msg_type;
    write->neighbor = neighbor;
    write->session_epoch = neighbor->session_epoch;
    write->req.data = write;

    if (neighbor->tx_tail) {
        neighbor->tx_tail->next = write;
    } else {
        neighbor->tx_head = write;
    }
    neighbor->tx_tail = write;
    runtime_peer_pump(neighbor);
    return 0;
}

static void runtime_peer_reset(bgp_neighbor_t *neighbor, int record_reset, int schedule_reconnect, const char *reason);

/*
 * A batch of UPDATEs was written (status 0), failed, or was cancelled by a close. Only a write of the current session
 * advances its job; a failure on the current session resets it.
 */
static void runtime_peer_on_batch_write(uv_write_t *req, int status) {
    bgp_neighbor_t       *neighbor = req ? req->data : NULL;
    bgp_tx_batch_result_t result;
    uint64_t              batch_epoch;

    if (!neighbor || !neighbor->tx) {
        return;
    }
    batch_epoch = neighbor->tx->batch.epoch;
    neighbor->write_in_flight = 0;
    bgp_peer_tx_batch_done(neighbor->tx, neighbor->session_epoch, status == 0, &result);
    if (neighbor->destroy_pending) {
        return;
    }
    if (status < 0) {
        if (batch_epoch == neighbor->session_epoch) {
            runtime_peer_reset(neighbor, 1, 1, "Down - write failed");
        }
        return;
    }
    if (!result.stale) {
        neighbor->tx_update += result.msgs;
        if (result.observer.run_id != 0) {
            script_exec_progress(neighbor->router->sim, &result);
        }
    }
    runtime_peer_pump(neighbor);
}

/*
 * Write the next batch of queued UPDATEs: only on an established session with no fatal NOTIFICATION pending.
 */
static void runtime_peer_pump_updates(bgp_neighbor_t *neighbor) {
    bgp_peer_tx_t        *tx = neighbor->tx;
    bgp_tx_batch_result_t result;
    int                   rc;

    if (!tx || neighbor->state != BGP_STATE_ESTABLISHED || neighbor->notification_pending ||
        bgp_peer_tx_fill_batch(tx, neighbor->session_epoch, BGP_TX_BATCH_BYTES) == 0) {
        return;
    }
    neighbor->write_in_flight = 1;
    rc = uv_write(&tx->batch.req, (uv_stream_t *)&neighbor->stream, tx->batch.bufs, tx->batch.nbufs,
                  runtime_peer_on_batch_write);
    if (rc < 0) {
        // No callback follows a write that fails at once: release the batch here.
        neighbor->write_in_flight = 0;
        bgp_peer_tx_batch_done(tx, neighbor->session_epoch, 0, &result);
        runtime_peer_reset(neighbor, 1, 1, "Down - write failed");
    }
}

/*
 * Start the next write when none is in flight: queued control messages first. Nothing starts while the read
 * callback parses messages (a write that fails at once resets the session and frees the receive buffer under the
 * parser), or once a reset has begun closing the stream.
 */
static void runtime_peer_pump(bgp_neighbor_t *neighbor) {
    bgpsim_peer_write_t *write;
    uv_buf_t             buf;
    int                  rc;

    if (!neighbor || neighbor->write_in_flight || !neighbor->stream_open || neighbor->closing ||
        neighbor->reading) {
        return;
    }

    write = neighbor->tx_head;
    if (!write) {
        runtime_peer_pump_updates(neighbor);
        return;
    }

    neighbor->tx_head = write->next;
    if (!neighbor->tx_head) {
        neighbor->tx_tail = NULL;
    }
    write->next = NULL;
    neighbor->tx_active = write;
    neighbor->write_in_flight = 1;

    buf = uv_buf_init((char *)write->data, (unsigned int)write->len);
    rc = uv_write(&write->req, (uv_stream_t *)&neighbor->stream, &buf, 1, runtime_peer_on_write);
    if (rc < 0) {
        neighbor->write_in_flight = 0;
        neighbor->tx_active = NULL;
        runtime_peer_write_free(write);
        runtime_peer_reset(neighbor, 1, 1, "Down - write failed");
    }
}

/*
 * Build our OPEN with the neighbor capabilities and queue it for sending.
 */
static int runtime_peer_queue_open(bgp_neighbor_t *neighbor) {
    /*
     * Mirror bgp_send_open(): extended OPEN optional parameters can push the
     * message well past the old 255-byte capability boundary.
     */
    uint8_t buffer[BGP_MAX_MESSAGE_SIZE];
    int     len;

    len = bgp_build_open_with_capabilities(buffer, sizeof(buffer), neighbor->router->local_as,
                                           neighbor->router->router_id, &neighbor->capabilities);
    if (len < 0) {
        return -1;
    }

    return runtime_peer_queue_message(neighbor, buffer, (size_t)len, BGP_MSG_OPEN);
}

static int runtime_peer_queue_keepalive(bgp_neighbor_t *neighbor) {
    uint8_t buffer[BGP_HEADER_SIZE];
    int     len = bgp_build_keepalive(buffer, sizeof(buffer));

    if (len < 0) {
        return -1;
    }

    return runtime_peer_queue_message(neighbor, buffer, (size_t)len, BGP_MSG_KEEPALIVE);
}

static int runtime_peer_queue_notification_data(bgp_neighbor_t *neighbor, uint8_t error_code, uint8_t error_subcode,
                                                const void *data, size_t data_len) {
    uint8_t buffer[BGP_MAX_MESSAGE_SIZE];
    int     len = bgp_build_notification(buffer, sizeof(buffer), error_code, error_subcode);
    int     rc;

    if (!neighbor || !neighbor->stream_open) {
        return -1;
    }

    if (len < 0 || data_len > sizeof(buffer) - (size_t)len || (data_len > 0 && !data)) {
        return -1;
    }
    if (data_len > 0) {
        memcpy(buffer + len, data, data_len);
        len += (int)data_len;
        ((bgp_header_t *)buffer)->length = htons((uint16_t)len);
    }

    /*
     * Drain the fatal notification before closing the stream. Stop input and
     * timers while the async write completes, with a bounded drain timeout.
     */
    if (neighbor->read_started) {
        uv_read_stop((uv_stream_t *)&neighbor->stream);
        neighbor->read_started = 0;
    }
    uv_timer_stop(&neighbor->reconnect_timer);
    uv_timer_stop(&neighbor->connect_timer);
    uv_timer_stop(&neighbor->open_timer);
    uv_timer_stop(&neighbor->hold_timer);
    uv_timer_stop(&neighbor->keepalive_timer);
    runtime_peer_free_pending_writes(neighbor);
    neighbor->notification_pending = 1;
    uv_timer_start(&neighbor->open_timer, runtime_peer_notification_timer_cb, BGPSIM_NOTIFICATION_TIMEOUT_MS, 0);

    rc = runtime_peer_queue_message(neighbor, buffer, (size_t)len, BGP_MSG_NOTIFICATION);
    if (rc != 0) {
        neighbor->notification_pending = 0;
        uv_timer_stop(&neighbor->open_timer);
    }
    return rc;
}

static int runtime_peer_queue_notification(bgp_neighbor_t *neighbor, uint8_t error_code, uint8_t error_subcode) {
    return runtime_peer_queue_notification_data(neighbor, error_code, error_subcode, NULL, 0);
}

static void runtime_peer_arm_established_timers(bgp_neighbor_t *neighbor);

/*
 * libuv close callback for the peer stream and timers. When the stream closes, mark the peer as not connected; a peer
 * waiting to be destroyed is finalized when its last handle closes.
 */
static void runtime_peer_on_handle_closed(uv_handle_t *handle) {
    bgp_neighbor_t *neighbor = handle ? handle->data : NULL;

    if (!neighbor) {
        return;
    }

    if (handle == (uv_handle_t *)&neighbor->stream) {
        neighbor->stream_initialized = 0;
        neighbor->stream_open = 0;
        neighbor->read_started = 0;
        neighbor->connect_pending = 0;
        neighbor->closing = 0;
        neighbor->sock_fd = -1;
    }

    if (neighbor->destroy_pending) {
        if (neighbor->close_refs > 0) {
            neighbor->close_refs--;
        }
        runtime_try_finalize_neighbor(neighbor);
        return;
    }

    if (neighbor->active && neighbor->router && neighbor->router->active && neighbor->router->sim &&
        !neighbor->router->sim->shutdown && !runtime_neighbor_passive_only(neighbor->router, neighbor) &&
        !neighbor->pending_reconnect && neighbor->state == BGP_STATE_IDLE) {
        runtime_peer_schedule_reconnect(neighbor,
                                        (uint64_t)runtime_retry_interval_seconds(neighbor->retry_count) * 1000u);
    }
}

static void runtime_peer_on_read_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    (void)handle;
    buf->base = malloc(suggested_size > 0 ? suggested_size : 1024);
    buf->len = buf->base ? suggested_size : 0;
}

static int runtime_peer_handle_open_message(bgp_neighbor_t *neighbor, const uint8_t *msg, size_t msg_len) {
    bgp_open_info_t open_info;

    if (bgp_accept_open(neighbor->router, neighbor, msg, msg_len, &open_info) != 0) {
        runtime_peer_queue_notification(neighbor, BGP_ERR_OPEN_MESSAGE, open_info.error_subcode);
        return -1;
    }

    return 0;
}

/*
 * Run one complete BGP message through the FSM for the current state (OPEN, KEEPALIVE, UPDATE, NOTIFICATION) and
 * return what the caller must do next.
 */
static runtime_peer_msg_result_t runtime_peer_handle_message(bgp_neighbor_t *neighbor, const uint8_t *msg,
                                                             size_t msg_len) {
    const bgp_header_t *hdr = (const bgp_header_t *)msg;
    uint8_t             msg_type = hdr->type;
    time_t              now = time(NULL);

    switch (neighbor->state) {
        case BGP_STATE_OPENSENT:
            if (msg_type == BGP_MSG_OPEN) {
                neighbor->rx_open++;
                if (runtime_peer_handle_open_message(neighbor, msg, msg_len) != 0) {
                    return RUNTIME_PEER_MSG_PROTOCOL_ERROR;
                }
                if (runtime_peer_queue_keepalive(neighbor) != 0) {
                    return RUNTIME_PEER_MSG_PROTOCOL_ERROR;
                }
                neighbor->state = BGP_STATE_OPENCONFIRM;
                return RUNTIME_PEER_MSG_OK;
            }
            if (msg_type == BGP_MSG_NOTIFICATION) {
                runtime_peer_note_rx_notification(neighbor, msg, msg_len);
                return RUNTIME_PEER_MSG_RESET;
            }
            return RUNTIME_PEER_MSG_PROTOCOL_ERROR;

        case BGP_STATE_OPENCONFIRM:
            if (msg_type == BGP_MSG_KEEPALIVE) {
                neighbor->rx_keepalive++;
                neighbor->state = BGP_STATE_ESTABLISHED;
                neighbor->uptime = now;
                neighbor->last_msg_time = now;
                uv_timer_stop(&neighbor->open_timer);
                runtime_peer_arm_established_timers(neighbor);
                runtime_peer_emit_adjchange(neighbor, "Up");
                // Only queues: the read callback starts the writes after the messages are consumed.
                tx_session_up(neighbor);
                return RUNTIME_PEER_MSG_OK;
            }
            if (msg_type == BGP_MSG_NOTIFICATION) {
                runtime_peer_note_rx_notification(neighbor, msg, msg_len);
                return RUNTIME_PEER_MSG_RESET;
            }
            return RUNTIME_PEER_MSG_PROTOCOL_ERROR;

        case BGP_STATE_ESTABLISHED:
            if (msg_type == BGP_MSG_ROUTE_REFRESH && neighbor->capabilities.route_refresh) {
                /*
                 * RFC 2918: refresh does not reset the session or Hold Timer. The body is AFI (2), subtype (1,
                 * RFC 7313) and SAFI (1); the replays are queued and written after the read.
                 */
                const uint8_t *body = msg + BGP_HEADER_SIZE;

                tx_route_refresh(neighbor, (uint16_t)((body[0] << 8) | body[1]), body[2], body[3]);
                return RUNTIME_PEER_MSG_OK;
            }
            neighbor->last_msg_time = now;
            if (msg_type == BGP_MSG_KEEPALIVE) {
                neighbor->rx_keepalive++;
            } else if (msg_type == BGP_MSG_UPDATE) {
                neighbor->rx_update++;
            } else if (msg_type == BGP_MSG_NOTIFICATION) {
                runtime_peer_note_rx_notification(neighbor, msg, msg_len);
                return RUNTIME_PEER_MSG_RESET;
            } else {
                return RUNTIME_PEER_MSG_PROTOCOL_ERROR;
            }

            if (neighbor->hold_time > 0) {
                uv_timer_stop(&neighbor->hold_timer);
                uv_timer_start(&neighbor->hold_timer, runtime_peer_hold_timer_cb,
                               (uint64_t)neighbor->hold_time * 1000u, 0);
            }
            return RUNTIME_PEER_MSG_OK;

        default:
            return RUNTIME_PEER_MSG_OK;
    }
}

static void runtime_peer_arm_established_timers(bgp_neighbor_t *neighbor) {
    uint64_t hold_ms;
    uint64_t keepalive_ms;

    uv_timer_stop(&neighbor->hold_timer);
    uv_timer_stop(&neighbor->keepalive_timer);

    if (neighbor->hold_time > 0) {
        hold_ms = (uint64_t)neighbor->hold_time * 1000u;
        uv_timer_start(&neighbor->hold_timer, runtime_peer_hold_timer_cb, hold_ms, 0);
        keepalive_ms = (uint64_t)(neighbor->hold_time / 3);
        if (keepalive_ms == 0) {
            keepalive_ms = 1;
        }
        keepalive_ms *= 1000u;
    } else {
        // RFC 4271 section 4.4: neither periodic timer runs with Hold Time 0.
        return;
    }

    uv_timer_start(&neighbor->keepalive_timer, runtime_peer_keepalive_timer_cb, keepalive_ms, keepalive_ms);
}

/*
 * RFC 4271 section 6.1: validate framing before waiting for the body. Return
 * the Message Header Error subcode, or zero when the header is valid.
 */
static uint8_t runtime_peer_header_error(const bgp_header_t *hdr) {
    uint16_t len = ntohs(hdr->length);

    for (int i = 0; i < BGP_MARKER_SIZE; i++) {
        if (hdr->marker[i] != 0xFF) return 1;
    }
    if (len < BGP_HEADER_SIZE || len > BGP_MAX_MESSAGE_SIZE) return 2;

    switch (hdr->type) {
        case BGP_MSG_OPEN:
            return len < BGP_HEADER_SIZE + sizeof(bgp_open_t) ? 2 : 0;
        case BGP_MSG_UPDATE:
            return len < BGP_HEADER_SIZE + 4 ? 2 : 0;
        case BGP_MSG_NOTIFICATION:
            return len < BGP_HEADER_SIZE + sizeof(bgp_notification_t) ? 2 : 0;
        case BGP_MSG_KEEPALIVE:
            return len != BGP_HEADER_SIZE ? 2 : 0;
        case BGP_MSG_ROUTE_REFRESH:
            return len != BGP_HEADER_SIZE + 4 ? 2 : 0;
        default:
            return 3;
    }
}

static runtime_peer_msg_result_t runtime_peer_consume_rx(bgp_neighbor_t *neighbor) {
    runtime_peer_msg_result_t rc;

    while (neighbor->rx_len >= BGP_HEADER_SIZE) {
        const bgp_header_t *hdr = (const bgp_header_t *)neighbor->rx_data;
        uint16_t            msg_len = ntohs(hdr->length);
        uint8_t             header_error = runtime_peer_header_error(hdr);

        if (header_error != 0) {
            const void *data = header_error == 2 ? (const void *)&hdr->length :
                               header_error == 3 ? (const void *)&hdr->type : NULL;
            size_t data_len = header_error == 2 ? sizeof(hdr->length) : header_error == 3 ? sizeof(hdr->type) : 0;

            runtime_peer_queue_notification_data(neighbor, BGP_ERR_MESSAGE_HEADER, header_error, data, data_len);
            return RUNTIME_PEER_MSG_PROTOCOL_ERROR;
        }
        if (neighbor->rx_len < msg_len) {
            return RUNTIME_PEER_MSG_OK;
        }

        rc = runtime_peer_handle_message(neighbor, neighbor->rx_data, msg_len);
        if (rc == RUNTIME_PEER_MSG_RESET) {
            runtime_peer_handle_notification_reset(neighbor);
            return RUNTIME_PEER_MSG_RESET;
        }
        if (rc != RUNTIME_PEER_MSG_OK) {
            if (!neighbor->notification_pending) {
                runtime_peer_queue_notification(neighbor, BGP_ERR_FSM, 0);
            }
            return RUNTIME_PEER_MSG_PROTOCOL_ERROR;
        }

        memmove(neighbor->rx_data, neighbor->rx_data + msg_len, neighbor->rx_len - msg_len);
        neighbor->rx_len -= msg_len;
    }

    return RUNTIME_PEER_MSG_OK;
}

static void runtime_peer_on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    bgp_neighbor_t           *neighbor = stream ? stream->data : NULL;
    size_t                    needed;
    size_t                    new_cap;
    uint8_t                  *new_data;
    runtime_peer_msg_result_t rc;

    if (!neighbor) {
        free(buf->base);
        return;
    }

    if (neighbor->notification_pending) {
        free(buf->base);
        return;
    }

    if (nread < 0) {
        free(buf->base);
        runtime_peer_reset(neighbor, 1, 1, "Down - connection lost");
        return;
    }

    if (nread == 0) {
        free(buf->base);
        return;
    }

    needed = neighbor->rx_len + (size_t)nread;
    if (needed > neighbor->rx_cap) {
        new_cap = neighbor->rx_cap ? neighbor->rx_cap : 4096;
        while (new_cap < needed) {
            new_cap *= 2;
        }

        new_data = realloc(neighbor->rx_data, new_cap);
        if (!new_data) {
            free(buf->base);
            runtime_peer_reset(neighbor, 1, 1, "Down - receive buffer allocation failed");
            return;
        }

        neighbor->rx_data = new_data;
        neighbor->rx_cap = new_cap;
    }

    memcpy(neighbor->rx_data + neighbor->rx_len, buf->base, (size_t)nread);
    neighbor->rx_len += (size_t)nread;
    free(buf->base);

    neighbor->reading = 1;
    rc = runtime_peer_consume_rx(neighbor);
    neighbor->reading = 0;
    if (rc == RUNTIME_PEER_MSG_PROTOCOL_ERROR && !neighbor->notification_pending) {
        runtime_peer_reset(neighbor, 1, 1, "Down - protocol error");
        return;
    }
    // Send what the messages queued: a reply, a NOTIFICATION, or UPDATEs.
    runtime_peer_pump(neighbor);
}

/*
 * libuv connect callback. A stale attempt (older epoch, or a neighbor removed or stopped) closes the stream; a failed
 * one resets the peer and schedules a retry; a good one starts reading and sends OPEN.
 */
static void runtime_peer_on_connect(uv_connect_t *req, int status) {
    bgp_neighbor_t *neighbor = req ? req->handle->data : NULL;
    uint64_t        request_epoch = req ? (uint64_t)(uintptr_t)req->data : 0;

    if (!neighbor) {
        return;
    }

    uv_timer_stop(&neighbor->connect_timer);
    neighbor->connect_pending = 0;

    if (request_epoch != neighbor->connect_epoch || neighbor->destroy_pending || !neighbor->active ||
        !neighbor->router || !neighbor->router->active) {
        if (!neighbor->closing && neighbor->stream_initialized) {
            neighbor->closing = 1;
            uv_close((uv_handle_t *)&neighbor->stream, runtime_peer_on_handle_closed);
        }
        return;
    }

    if (status < 0) {
        runtime_peer_reset(neighbor, 1, 1, NULL);
        return;
    }

    neighbor->stream_open = 1;
    runtime_peer_update_socket_fd(neighbor);
    uv_read_start((uv_stream_t *)&neighbor->stream, runtime_peer_on_read_alloc, runtime_peer_on_read);
    neighbor->read_started = 1;
    neighbor->retry_count = 0;
    neighbor->is_passive = 0;
    neighbor->state = BGP_STATE_OPENSENT;
    neighbor->last_msg_time = time(NULL);

    if (runtime_peer_queue_open(neighbor) != 0) {
        runtime_peer_reset(neighbor, 1, 1, "Down - failed to queue OPEN");
        return;
    }

    uv_timer_start(&neighbor->open_timer, runtime_peer_open_timer_cb, BGPSIM_OPEN_TIMEOUT_MS, 0);
}

static int runtime_peer_bind_source_ip(bgp_neighbor_t *neighbor) {
    const char *source_ip = NULL;
    int         rc;

    if (neighbor->source_ip[0] != '\0') {
        source_ip = neighbor->source_ip;
    } else if (neighbor->router->source_ip[0] != '\0') {
        source_ip = neighbor->router->source_ip;
    }

    if (!source_ip) {
        return 0;
    }

    if (neighbor->af == AF_INET) {
        struct sockaddr_in addr4;

        rc = uv_ip4_addr(source_ip, 0, &addr4);
        if (rc < 0) {
            return rc;
        }
        return uv_tcp_bind(&neighbor->stream, (const struct sockaddr *)&addr4, 0);
    }

    if (neighbor->af == AF_INET6) {
        struct sockaddr_in6 addr6;

        rc = uv_ip6_addr(source_ip, 0, &addr6);
        if (rc < 0) {
            return rc;
        }
        return uv_tcp_bind(&neighbor->stream, (const struct sockaddr *)&addr6, 0);
    }

    return UV_EINVAL;
}

/*
 * Start an active TCP connection to the neighbor, unless one is open or pending or the neighbor is passive-only. Local
 * test addresses connect to the router listen port, others to port 179.
 */
static void runtime_peer_start_connect(bgp_neighbor_t *neighbor) {
    struct sockaddr_storage remote_addr;
    uint16_t remote_port = runtime_neighbor_is_local_test_address(neighbor->ip) ? neighbor->router->listen_port
                                                                                : BGP_PORT;
    int rc;

    if (!neighbor->active || !neighbor->router || !neighbor->router->active || neighbor->destroy_pending ||
        neighbor->closing || neighbor->connect_pending || neighbor->stream_open ||
        runtime_neighbor_passive_only(neighbor->router, neighbor)) {
        return;
    }

    if (runtime_peer_ensure_base(neighbor->router->sim->runtime, neighbor) != 0 ||
        runtime_peer_init_stream(neighbor->router->sim->runtime, neighbor) != 0) {
        return;
    }

    if (runtime_peer_bind_source_ip(neighbor) != 0) {
        runtime_peer_reset(neighbor, 1, 1, "Down - invalid source bind");
        return;
    }

    memset(&remote_addr, 0, sizeof(remote_addr));
    if (neighbor->af == AF_INET) {
        struct sockaddr_in addr4;

        if (uv_ip4_addr(neighbor->ip, remote_port, &addr4) != 0) {
            runtime_peer_reset(neighbor, 1, 1, "Down - invalid neighbor address");
            return;
        }
        memcpy(&remote_addr, &addr4, sizeof(addr4));
    } else {
        struct sockaddr_in6 addr6;

        if (uv_ip6_addr(neighbor->ip, remote_port, &addr6) != 0) {
            runtime_peer_reset(neighbor, 1, 1, "Down - invalid neighbor address");
            return;
        }
        memcpy(&remote_addr, &addr6, sizeof(addr6));
    }

    neighbor->last_connect_attempt = time(NULL);
    neighbor->retry_count++;
    neighbor->connect_epoch++;
    neighbor->connect_pending = 1;
    neighbor->pending_reconnect = 0;
    neighbor->state = BGP_STATE_CONNECT;
    neighbor->connect_req.data = (void *)(uintptr_t)neighbor->connect_epoch;

    log_write("Attempting connection to %s (retry %d, next in %ld sec)...",
              neighbor->ip, neighbor->retry_count, runtime_retry_interval_seconds(neighbor->retry_count));

    rc = uv_tcp_connect(&neighbor->connect_req, &neighbor->stream, (const struct sockaddr *)&remote_addr,
                        runtime_peer_on_connect);
    if (rc < 0) {
        neighbor->connect_pending = 0;
        runtime_peer_reset(neighbor, 1, 1, "Down - connect failed");
        return;
    }

    uv_timer_start(&neighbor->connect_timer, runtime_peer_connect_timer_cb, BGPSIM_CONNECT_TIMEOUT_MS, 0);
}

/*
 * Arm the reconnect timer once (pending_reconnect blocks a second arm). Nothing happens during shutdown or for a
 * passive-only neighbor.
 */
static void runtime_peer_schedule_reconnect(bgp_neighbor_t *neighbor, uint64_t delay_ms) {
    if (!neighbor || !neighbor->runtime_initialized || !neighbor->active || !neighbor->router ||
        !neighbor->router->active || !neighbor->router->sim || neighbor->router->sim->shutdown ||
        neighbor->pending_reconnect ||
        runtime_neighbor_passive_only(neighbor->router, neighbor)) {
        return;
    }

    neighbor->pending_reconnect = 1;
    uv_timer_stop(&neighbor->reconnect_timer);
    uv_timer_start(&neighbor->reconnect_timer, runtime_peer_reconnect_timer_cb, delay_ms, 0);
}

/*
 * Drop the session: stop all timers, free queued and received data, go to Idle, clear the peer capabilities and close
 * the stream. record_reset counts the reset; reason (when set and the session was Established) is logged as an
 * ADJCHANGE event; schedule_reconnect arms a retry with backoff.
 */
static void runtime_peer_reset(bgp_neighbor_t *neighbor, int record_reset, int schedule_reconnect, const char *reason) {
    int was_established;

    if (!neighbor) {
        return;
    }

    was_established = (neighbor->state == BGP_STATE_ESTABLISHED);

    if (record_reset) {
        neighbor->session_resets++;
        neighbor->last_reset_time = time(NULL);
    }

    uv_timer_stop(&neighbor->reconnect_timer);
    uv_timer_stop(&neighbor->connect_timer);
    uv_timer_stop(&neighbor->open_timer);
    uv_timer_stop(&neighbor->hold_timer);
    uv_timer_stop(&neighbor->keepalive_timer);

    runtime_peer_free_pending_writes(neighbor);
    runtime_peer_free_rx(neighbor);
    if (neighbor->tx) {
        /*
         * The receiver drops the session's routes; a batch in flight completes stale. A script step waiting for
         * the dropped jobs fails.
         */
        bgp_peer_tx_reset(neighbor->tx, script_exec_abort, neighbor->router ? neighbor->router->sim : NULL);
    }

    neighbor->state = BGP_STATE_IDLE;
    neighbor->uptime = 0;
    neighbor->last_msg_time = 0;
    neighbor->last_keepalive_sent = 0;
    neighbor->remote_id = 0;
    neighbor->hold_time = 0;
    neighbor->peer_capabilities_received = 0;
    neighbor->peer_mp_capability_received = 0;
    memset(&neighbor->peer_capabilities, 0, sizeof(neighbor->peer_capabilities));
    neighbor->is_passive = 0;
    neighbor->pending_reconnect = 0;
    neighbor->notification_pending = 0;
    neighbor->connect_pending = 0;
    neighbor->session_epoch++;

    if (neighbor->read_started && neighbor->stream_initialized) {
        uv_read_stop((uv_stream_t *)&neighbor->stream);
        neighbor->read_started = 0;
    }

    if (neighbor->stream_initialized && !neighbor->closing) {
        neighbor->closing = 1;
        uv_close((uv_handle_t *)&neighbor->stream, runtime_peer_on_handle_closed);
    }

    if (was_established && reason) {
        runtime_peer_emit_adjchange(neighbor, reason);
    }

    if (!neighbor->stream_initialized && schedule_reconnect) {
        runtime_peer_schedule_reconnect(neighbor,
                                        (uint64_t)runtime_retry_interval_seconds(neighbor->retry_count) * 1000u);
    }
}

static void runtime_peer_reconnect_timer_cb(uv_timer_t *timer) {
    bgp_neighbor_t *neighbor = timer ? timer->data : NULL;

    if (!neighbor) {
        return;
    }

    neighbor->pending_reconnect = 0;
    runtime_peer_start_connect(neighbor);
}

static void runtime_peer_connect_timer_cb(uv_timer_t *timer) {
    bgp_neighbor_t *neighbor = timer ? timer->data : NULL;

    if (!neighbor) {
        return;
    }

    runtime_peer_reset(neighbor, 1, 1, "Down - connect timeout");
}

static void runtime_peer_open_timer_cb(uv_timer_t *timer) {
    bgp_neighbor_t *neighbor = timer ? timer->data : NULL;

    if (!neighbor) {
        return;
    }

    if (runtime_peer_queue_notification(neighbor, BGP_ERR_FSM, 0) != 0) {
        runtime_peer_reset(neighbor, 1, 1, "Down - open timeout");
    }
}

static void runtime_peer_hold_timer_cb(uv_timer_t *timer) {
    bgp_neighbor_t *neighbor = timer ? timer->data : NULL;

    if (!neighbor) {
        return;
    }

    if (runtime_peer_queue_notification(neighbor, BGP_ERR_HOLD_TIMER_EXPIRED, 0) != 0) {
        runtime_peer_reset(neighbor, 1, 1, "Down - hold timer expired");
    }
}

static void runtime_peer_notification_timer_cb(uv_timer_t *timer) {
    bgp_neighbor_t *neighbor = timer ? timer->data : NULL;

    if (neighbor && neighbor->notification_pending) {
        runtime_peer_reset(neighbor, 1, 1, "Down - notification send timeout");
    }
}

static void runtime_peer_keepalive_timer_cb(uv_timer_t *timer) {
    bgp_neighbor_t *neighbor = timer ? timer->data : NULL;

    if (!neighbor) {
        return;
    }

    if (runtime_peer_queue_keepalive(neighbor) != 0) {
        runtime_peer_reset(neighbor, 1, 1, "Down - keepalive send failed");
    }
}

static void runtime_peer_begin_destroy(bgp_neighbor_t *neighbor) {
    if (!neighbor || !neighbor->runtime_initialized || neighbor->destroy_pending) {
        return;
    }

    neighbor->destroy_pending = 1;
    neighbor->pending_reconnect = 0;
    uv_timer_stop(&neighbor->reconnect_timer);
    uv_timer_stop(&neighbor->connect_timer);
    uv_timer_stop(&neighbor->open_timer);
    uv_timer_stop(&neighbor->hold_timer);
    uv_timer_stop(&neighbor->keepalive_timer);

    runtime_peer_free_pending_writes(neighbor);
    runtime_peer_free_rx(neighbor);
    if (neighbor->tx) {
        bgp_peer_tx_reset(neighbor->tx, script_exec_abort, neighbor->router ? neighbor->router->sim : NULL);
    }

    neighbor->close_refs = 0;

    /*
     * A peer can already have an in-flight close from a reset path when global
     * shutdown starts. Those callbacks still need to complete before the
     * neighbor storage is zeroed, so count already-closing handles too.
     */
    if (neighbor->stream_initialized) {
        neighbor->close_refs++;
        if (!uv_is_closing((const uv_handle_t *)&neighbor->stream)) {
            neighbor->closing = 1;
            uv_close((uv_handle_t *)&neighbor->stream, runtime_peer_on_handle_closed);
        }
    }
    if (uv_is_closing((const uv_handle_t *)&neighbor->reconnect_timer)) {
        neighbor->close_refs++;
    } else {
        neighbor->close_refs++;
        uv_close((uv_handle_t *)&neighbor->reconnect_timer, runtime_peer_on_handle_closed);
    }
    if (uv_is_closing((const uv_handle_t *)&neighbor->connect_timer)) {
        neighbor->close_refs++;
    } else {
        neighbor->close_refs++;
        uv_close((uv_handle_t *)&neighbor->connect_timer, runtime_peer_on_handle_closed);
    }
    if (uv_is_closing((const uv_handle_t *)&neighbor->open_timer)) {
        neighbor->close_refs++;
    } else {
        neighbor->close_refs++;
        uv_close((uv_handle_t *)&neighbor->open_timer, runtime_peer_on_handle_closed);
    }
    if (uv_is_closing((const uv_handle_t *)&neighbor->hold_timer)) {
        neighbor->close_refs++;
    } else {
        neighbor->close_refs++;
        uv_close((uv_handle_t *)&neighbor->hold_timer, runtime_peer_on_handle_closed);
    }
    if (uv_is_closing((const uv_handle_t *)&neighbor->keepalive_timer)) {
        neighbor->close_refs++;
    } else {
        neighbor->close_refs++;
        uv_close((uv_handle_t *)&neighbor->keepalive_timer, runtime_peer_on_handle_closed);
    }

    runtime_try_finalize_neighbor(neighbor);
}

static void runtime_try_finalize_neighbor(bgp_neighbor_t *neighbor) {
    bgp_router_t *router;

    if (!neighbor || !neighbor->destroy_pending || neighbor->close_refs != 0) {
        return;
    }

    router = neighbor->router;
    // Every write callback has run before the last close callback, so no batch is in flight.
    bgp_neighbor_reset(neighbor);

    if (router) {
        while (router->neighbor_count > 0) {
            bgp_neighbor_t *tail = router->neighbors[router->neighbor_count - 1];
            if (tail->active || tail->runtime_initialized || tail->stream_initialized || tail->destroy_pending) {
                break;
            }
            router->neighbor_count--;
        }
        runtime_try_finalize_router(router);
    }
}

static void runtime_listener_on_close(uv_handle_t *handle) {
    bgp_router_t *router = handle ? handle->data : NULL;

    if (!router) {
        return;
    }

    router->listener_initialized = 0;
    router->listener_open = 0;
    router->listener_closing = 0;
    runtime_try_finalize_router(router);
}

/*
 * Free the slot of a removed router once its listener and all its neighbors are closed, and shrink the router count
 * past empty slots at the end.
 */
static void runtime_try_finalize_router(bgp_router_t *router) {
    bgp_sim_t *sim;

    if (!router || router->active || router->listener_initialized || router->listener_open ||
        router->listener_closing) {
        return;
    }

    for (int i = 0; i < router->neighbor_count; i++) {
        bgp_neighbor_t *neighbor = router->neighbors[i];
        if (neighbor->active || neighbor->runtime_initialized || neighbor->stream_initialized ||
            neighbor->destroy_pending) {
            return;
        }
    }

    sim = router->sim;
    bgp_router_reset(router);

    if (sim) {
        while (sim->router_count > 0) {
            bgp_router_t *tail = sim->routers[sim->router_count - 1];
            if (tail->sim) {
                break;
            }
            sim->router_count--;
        }
    }
}

/*
 * Open the passive listener of a router. Returns 0 when it listens, 1 while a failed handle is still closing (try
 * again later), or a negative libuv error; a failed handle is closed, so the next try starts with a new socket.
 */
static int runtime_listener_start(bgpsim_runtime_t *runtime, bgp_router_t *router) {
    int                 rc;
    struct sockaddr_in6 addr6;

    if (router->listener_open) {
        return 0;
    }
    if (router->listener_closing) {
        return 1;
    }

    if (!router->listener_initialized) {
        rc = uv_tcp_init(&runtime->loop, &router->listener);
        if (rc < 0) {
            return rc;
        }
        router->listener.data = router;
        router->listener_initialized = 1;
    }

    memset(&addr6, 0, sizeof(addr6));
    rc = uv_ip6_addr("::", router->listen_port, &addr6);
    if (rc == 0) {
        rc = uv_tcp_bind(&router->listener, (const struct sockaddr *)&addr6, 0);
    }
    if (rc == 0) {
        // libuv reports a bind() EADDRINUSE here, from uv_listen().
        rc = uv_listen((uv_stream_t *)&router->listener, BGP_LISTEN_BACKLOG, runtime_listener_on_connection);
    }
    if (rc < 0) {
        runtime_listener_stop(router);
        return rc;
    }

    router->listener_open = 1;
    router->listener_error = 0;
    runtime->listener_retry_ms = BGPSIM_LISTEN_RETRY_MIN_MS;
    log_write("BGP router %u listening on port %u", router->local_as, router->listen_port);
    return 0;
}

static void runtime_listener_retry_cb(uv_timer_t *timer) {
    runtime_reconcile_internal(timer->data);
}

/*
 * A passive listener did not open: the port may be taken for a while (another process, or a connection that got it
 * as its local port). Log each new error once and try again, backing off; the router keeps no listener until then.
 */
static void runtime_listener_failed(bgpsim_runtime_t *runtime, bgp_router_t *router, int rc) {
    if (rc < 0 && rc != router->listener_error) {
        log_write("BGP router %u cannot listen on port %u: %s; retrying", router->local_as, router->listen_port,
                  uv_strerror(rc));
        router->listener_error = rc;
    }
    if (!runtime->listener_retry_initialized || uv_is_active((const uv_handle_t *)&runtime->listener_retry_timer)) {
        return;
    }
    uv_timer_start(&runtime->listener_retry_timer, runtime_listener_retry_cb, runtime->listener_retry_ms, 0);
    runtime->listener_retry_ms = runtime->listener_retry_ms * 2 > BGPSIM_LISTEN_RETRY_MAX_MS ?
                                 BGPSIM_LISTEN_RETRY_MAX_MS : runtime->listener_retry_ms * 2;
}

static int runtime_format_peer_ip(const struct sockaddr *addr, char *buf, size_t buf_len) {
    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *addr4 = (const struct sockaddr_in *)addr;
        return inet_ntop(AF_INET, &addr4->sin_addr, buf, buf_len) ? 0 : -1;
    }

    if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *addr6 = (const struct sockaddr_in6 *)addr;
        if (IN6_IS_ADDR_V4MAPPED(&addr6->sin6_addr)) {
            struct in_addr addr4;
            memcpy(&addr4, &addr6->sin6_addr.s6_addr[12], sizeof(addr4));
            return inet_ntop(AF_INET, &addr4, buf, buf_len) ? 0 : -1;
        }
        return inet_ntop(AF_INET6, &addr6->sin6_addr, buf, buf_len) ? 0 : -1;
    }

    return -1;
}

/*
 * Passive mode: accept a TCP connection and attach it to the configured neighbor with the peer address; a connection
 * from an unknown or busy neighbor is closed.
 */
static void runtime_listener_on_connection(uv_stream_t *server, int status) {
    bgp_router_t           *router = server ? server->data : NULL;
    bgp_neighbor_t         *neighbor;
    uv_tcp_t               *accepted = NULL;
    struct sockaddr_storage peer_addr;
    int                     peer_len = sizeof(peer_addr);
    char                    peer_ip[INET6_ADDRSTRLEN];
    uv_os_fd_t              accepted_fd = -1;
    int                     dup_fd = -1;

    if (!router || status < 0 || !router->sim || !router->sim->passive_mode) {
        return;
    }

    accepted = calloc(1, sizeof(*accepted));
    if (!accepted) {
        return;
    }

    if (uv_tcp_init(&router->sim->runtime->loop, accepted) != 0) {
        free(accepted);
        return;
    }

    if (uv_accept(server, (uv_stream_t *)accepted) != 0) {
        uv_close((uv_handle_t *)accepted, (uv_close_cb)free);
        return;
    }

    if (uv_tcp_getpeername(accepted, (struct sockaddr *)&peer_addr, &peer_len) != 0 ||
        runtime_format_peer_ip((const struct sockaddr *)&peer_addr, peer_ip, sizeof(peer_ip)) != 0) {
        uv_close((uv_handle_t *)accepted, (uv_close_cb)free);
        return;
    }

    log_write("Accepted connection from %s", peer_ip);

    neighbor = bgp_find_neighbor(router, peer_ip);
    if (!neighbor || neighbor->stream_open || neighbor->connect_pending || neighbor->destroy_pending ||
        neighbor->active == 0 || runtime_peer_ensure_base(router->sim->runtime, neighbor) != 0 ||
        runtime_peer_init_stream(router->sim->runtime, neighbor) != 0) {
        uv_close((uv_handle_t *)accepted, (uv_close_cb)free);
        return;
    }

    if (uv_fileno((const uv_handle_t *)accepted, &accepted_fd) != 0) {
        uv_close((uv_handle_t *)accepted, (uv_close_cb)free);
        return;
    }

    dup_fd = dup((int)accepted_fd);
    uv_close((uv_handle_t *)accepted, (uv_close_cb)free);
    if (dup_fd < 0) {
        return;
    }

    if (uv_tcp_open(&neighbor->stream, dup_fd) != 0) {
        close(dup_fd);
        return;
    }
    neighbor->stream.data = neighbor;

    neighbor->stream_open = 1;
    neighbor->is_passive = 1;
    neighbor->state = BGP_STATE_OPENSENT;
    runtime_peer_update_socket_fd(neighbor);
    uv_read_start((uv_stream_t *)&neighbor->stream, runtime_peer_on_read_alloc, runtime_peer_on_read);
    neighbor->read_started = 1;

    if (runtime_peer_queue_open(neighbor) != 0) {
        runtime_peer_reset(neighbor, 1, 0, "Down - failed to queue OPEN");
        return;
    }

    uv_timer_start(&neighbor->open_timer, runtime_peer_open_timer_cb, BGPSIM_OPEN_TIMEOUT_MS, 0);
}

static void runtime_listener_stop(bgp_router_t *router) {
    if (!router || !router->listener_initialized || router->listener_closing) {
        return;
    }

    router->listener_closing = 1;
    uv_close((uv_handle_t *)&router->listener, runtime_listener_on_close);
}

static void runtime_reconcile_neighbor(bgpsim_runtime_t *runtime, bgp_neighbor_t *neighbor) {
    if (!neighbor || !neighbor->router) {
        return;
    }

    if (!neighbor->active || !neighbor->router->active) {
        if (neighbor->runtime_initialized) {
            runtime_peer_begin_destroy(neighbor);
        }
        return;
    }

    if (runtime_peer_ensure_base(runtime, neighbor) != 0) {
        return;
    }

    neighbor->reconnect_timer.data = neighbor;
    neighbor->connect_timer.data = neighbor;
    neighbor->open_timer.data = neighbor;
    neighbor->hold_timer.data = neighbor;
    neighbor->keepalive_timer.data = neighbor;

    if (!neighbor->stream_open && !neighbor->connect_pending && !neighbor->pending_reconnect &&
        !runtime_neighbor_passive_only(neighbor->router, neighbor)) {
        runtime_peer_schedule_reconnect(neighbor, 0);
    }
}

static void runtime_reconcile_router(bgpsim_runtime_t *runtime, bgp_router_t *router) {
    if (!router) {
        return;
    }

    if (!router->active) {
        if (router->listener_initialized) {
            runtime_listener_stop(router);
        }
        for (int i = 0; i < router->neighbor_count; i++) {
            runtime_reconcile_neighbor(runtime, router->neighbors[i]);
        }
        runtime_try_finalize_router(router);
        return;
    }

    if (runtime->sim->passive_mode) {
        int rc = runtime_listener_start(runtime, router);

        if (rc != 0) {
            runtime_listener_failed(runtime, router, rc);
        }
    } else if (router->listener_initialized) {
        runtime_listener_stop(router);
    }

    for (int i = 0; i < router->neighbor_count; i++) {
        runtime_reconcile_neighbor(runtime, router->neighbors[i]);
    }
}

static void runtime_reconcile_internal(bgpsim_runtime_t *runtime) {
    if (!runtime || runtime->shutdown_started) {
        return;
    }

    for (int i = 0; i < runtime->sim->router_count; i++) {
        runtime_reconcile_router(runtime, runtime->sim->routers[i]);
    }
}

static void runtime_shutdown_close_all(bgpsim_runtime_t *runtime) {
    bgpsim_control_session_t *session = runtime->sessions;

    script_exec_shutdown(runtime->sim);

    while (session) {
        bgpsim_control_session_t *next = session->next;
        if (!session->closing) {
            session->closing = 1;
            uv_read_stop((uv_stream_t *)&session->handle);
            uv_close((uv_handle_t *)&session->handle, runtime_control_on_close);
        }
        session = next;
    }

    if (runtime->control_server_initialized && !uv_is_closing((const uv_handle_t *)&runtime->control_server)) {
        uv_close((uv_handle_t *)&runtime->control_server, NULL);
        runtime->control_server_listening = 0;
    }

    for (int i = 0; i < runtime->sim->router_count; i++) {
        bgp_router_t *router = runtime->sim->routers[i];
        if (router->listener_initialized) {
            runtime_listener_stop(router);
        }
        for (int j = 0; j < router->neighbor_count; j++) {
            runtime_peer_begin_destroy(router->neighbors[j]);
        }
    }

    if (!uv_is_closing((const uv_handle_t *)&runtime->shutdown_async)) {
        uv_close((uv_handle_t *)&runtime->shutdown_async, NULL);
    }
    if (!uv_is_closing((const uv_handle_t *)&runtime->reconcile_async)) {
        uv_close((uv_handle_t *)&runtime->reconcile_async, NULL);
    }
    if (runtime->listener_retry_initialized &&
        !uv_is_closing((const uv_handle_t *)&runtime->listener_retry_timer)) {
        uv_close((uv_handle_t *)&runtime->listener_retry_timer, NULL);
    }
}

static void runtime_on_shutdown_async(uv_async_t *handle) {
    bgpsim_runtime_t *runtime = handle ? handle->data : NULL;

    if (!runtime || runtime->shutdown_started) {
        return;
    }

    runtime->shutdown_started = 1;
    runtime->sim->shutdown = 1;
    runtime_shutdown_close_all(runtime);
}

static void runtime_on_reconcile_async(uv_async_t *handle) {
    bgpsim_runtime_t *runtime = handle ? handle->data : NULL;

    if (!runtime || runtime->shutdown_started) {
        return;
    }

    runtime->reconcile_requested = 0;
    runtime_reconcile_internal(runtime);
}

static void runtime_signal_ready(bgpsim_runtime_t *runtime, int status) {
    pthread_mutex_lock(&runtime->lifecycle_lock);
    runtime->ready = 1;
    runtime->ready_status = status;
    pthread_cond_broadcast(&runtime->lifecycle_cond);
    pthread_mutex_unlock(&runtime->lifecycle_lock);
}

static void runtime_thread_main(void *arg) {
    bgpsim_runtime_t *runtime = arg;
    int               rc;

    rc = uv_loop_init(&runtime->loop);
    if (rc < 0) {
        runtime_signal_ready(runtime, rc);
        return;
    }

    runtime->running = 1;

    rc = uv_async_init(&runtime->loop, &runtime->shutdown_async, runtime_on_shutdown_async);
    if (rc < 0) {
        runtime_signal_ready(runtime, rc);
        uv_loop_close(&runtime->loop);
        return;
    }
    runtime->shutdown_async.data = runtime;

    rc = uv_async_init(&runtime->loop, &runtime->reconcile_async, runtime_on_reconcile_async);
    if (rc < 0) {
        runtime_signal_ready(runtime, rc);
        uv_close((uv_handle_t *)&runtime->shutdown_async, NULL);
        uv_run(&runtime->loop, UV_RUN_DEFAULT);
        uv_loop_close(&runtime->loop);
        return;
    }
    runtime->reconcile_async.data = runtime;

    rc = uv_timer_init(&runtime->loop, &runtime->listener_retry_timer);
    if (rc == 0) {
        runtime->listener_retry_timer.data = runtime;
        runtime->listener_retry_initialized = 1;
        runtime->listener_retry_ms = BGPSIM_LISTEN_RETRY_MIN_MS;
        rc = runtime_control_server_start(runtime);
    }
    if (rc < 0) {
        runtime_signal_ready(runtime, rc);
        runtime_shutdown_close_all(runtime);
        uv_run(&runtime->loop, UV_RUN_DEFAULT);
        uv_loop_close(&runtime->loop);
        return;
    }

    runtime_reconcile_internal(runtime);
    runtime_signal_ready(runtime, 0);
    uv_run(&runtime->loop, UV_RUN_DEFAULT);
    unlink(runtime->socket_path);
    uv_loop_close(&runtime->loop);

    pthread_mutex_lock(&runtime->lifecycle_lock);
    runtime->running = 0;
    pthread_cond_broadcast(&runtime->lifecycle_cond);
    pthread_mutex_unlock(&runtime->lifecycle_lock);
}

int bgpsim_runtime_start(bgpsim_runtime_t **out_runtime, bgp_sim_t *sim, const char *socket_path) {
    bgpsim_runtime_t *runtime;
    int               status;

    if (!out_runtime || !sim || !socket_path || socket_path[0] == '\0') {
        return -1;
    }

    runtime = calloc(1, sizeof(*runtime));
    if (!runtime) {
        return -1;
    }

    runtime->sim = sim;
    strncpy(runtime->socket_path, socket_path, sizeof(runtime->socket_path) - 1);
    runtime->socket_path[sizeof(runtime->socket_path) - 1] = '\0';
    pthread_mutex_init(&runtime->lifecycle_lock, NULL);
    pthread_cond_init(&runtime->lifecycle_cond, NULL);
    sim->runtime = runtime;

    if (uv_thread_create(&runtime->thread, runtime_thread_main, runtime) != 0) {
        sim->runtime = NULL;
        pthread_cond_destroy(&runtime->lifecycle_cond);
        pthread_mutex_destroy(&runtime->lifecycle_lock);
        free(runtime);
        return -1;
    }

    pthread_mutex_lock(&runtime->lifecycle_lock);
    while (!runtime->ready) {
        pthread_cond_wait(&runtime->lifecycle_cond, &runtime->lifecycle_lock);
    }
    status = runtime->ready_status;
    pthread_mutex_unlock(&runtime->lifecycle_lock);

    if (status != 0) {
        bgpsim_runtime_request_shutdown(runtime);
        bgpsim_runtime_join(runtime);
        bgpsim_runtime_destroy(runtime);
        return status;
    }

    *out_runtime = runtime;
    return 0;
}

void bgpsim_runtime_request_shutdown(bgpsim_runtime_t *runtime) {
    if (!runtime) {
        return;
    }

    runtime->stop_requested = 1;
    if (bgpsim_runtime_is_loop_thread(runtime)) {
        runtime_on_shutdown_async(&runtime->shutdown_async);
    } else if (runtime->running) {
        uv_async_send(&runtime->shutdown_async);
    }
}

void bgpsim_runtime_join(bgpsim_runtime_t *runtime) {
    if (!runtime || !runtime->running) {
        return;
    }

    uv_thread_join(&runtime->thread);
}

void bgpsim_runtime_destroy(bgpsim_runtime_t *runtime) {
    if (!runtime) {
        return;
    }

    if (runtime->sim && runtime->sim->runtime == runtime) {
        runtime->sim->runtime = NULL;
    }
    pthread_cond_destroy(&runtime->lifecycle_cond);
    pthread_mutex_destroy(&runtime->lifecycle_lock);
    free(runtime);
}

int bgpsim_runtime_is_loop_thread(bgpsim_runtime_t *runtime) {
    uv_thread_t self;

    if (!runtime || !runtime->running) {
        return 0;
    }

    self = uv_thread_self();
    return uv_thread_equal(&runtime->thread, &self);
}

void bgpsim_runtime_reconcile(bgpsim_runtime_t *runtime) {
    if (!runtime) {
        return;
    }

    if (bgpsim_runtime_is_loop_thread(runtime)) {
        runtime_reconcile_internal(runtime);
    } else {
        bgpsim_runtime_request_reconcile(runtime);
    }
}

void bgpsim_runtime_request_reconcile(bgpsim_runtime_t *runtime) {
    if (!runtime || !runtime->running || runtime->shutdown_started) {
        return;
    }

    runtime->reconcile_requested = 1;
    uv_async_send(&runtime->reconcile_async);
}

/*
 * "clear bgp": reset the session (counted when record_reset is set) and reconnect. Runs on the loop thread only.
 */
void bgpsim_runtime_clear_neighbor(bgp_neighbor_t *neighbor, int record_reset) {
    bgpsim_runtime_t *runtime;

    if (!neighbor || !neighbor->router || !neighbor->router->sim) {
        return;
    }

    runtime = neighbor->router->sim->runtime;
    /*
     * The active runtime owns live peer state. Callers reaching this helper are
     * expected to already be on the libuv loop thread.
     */
    if (!runtime || !bgpsim_runtime_is_loop_thread(runtime)) {
        return;
    }

    runtime_peer_reset(neighbor, record_reset, 1,
                       neighbor->state == BGP_STATE_ESTABLISHED ? "Down - administratively cleared" : NULL);
}

void bgpsim_runtime_peer_kick(bgp_neighbor_t *neighbor) {
    if (neighbor && neighbor->router && neighbor->router->sim && neighbor->router->sim->runtime &&
        bgpsim_runtime_is_loop_thread(neighbor->router->sim->runtime)) {
        runtime_peer_pump(neighbor);
    }
}

/*
 * Log an event line and send it to every attached session with terminal monitor on. With neighbor_ip it is a
 * "%BGP-5-ADJCHANGE" line.
 */
void bgpsim_runtime_emit_event_line(bgpsim_runtime_t *runtime, uint32_t router_as, const char *neighbor_ip,
                                    const char *text) {
    char timestamp[32];
    char line[512];

    if (!runtime || !text) {
        return;
    }

    get_timestamp_str(timestamp, sizeof(timestamp));
    if (neighbor_ip && neighbor_ip[0] != '\0') {
        snprintf(line, sizeof(line), "%s: %%BGP-5-ADJCHANGE: neighbor %s %s\n", timestamp, neighbor_ip, text);
        log_write("BGP %u neighbor %s %s", router_as, neighbor_ip, text);
    } else {
        snprintf(line, sizeof(line), "%s: %s\n", timestamp, text);
        log_write("BGP %u %s", router_as, text);
    }

    for (bgpsim_control_session_t *session = runtime->sessions; session; session = session->next) {
        if (!session->session.terminal_monitor) {
            continue;
        }
        runtime_control_session_queue_frame(session, BGPSIM_CTRL_EVENT, line, (uint32_t)strlen(line), 1);
    }
}
