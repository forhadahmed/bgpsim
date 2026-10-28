/*
 * BGP Test Client
 *
 * This program acts as a simple external BGP peer for bgpsim integration
 * tests. It supports two modes:
 *   - active: connect out to a peer
 *   - passive: listen and accept one inbound peer
 *
 * The tamper model is intentionally centralized here instead of spread across
 * ad hoc environment checks in main(). Each tamper falls into one of three
 * buckets:
 *   - one-shot: connect/accept, send malformed or truncated data, then exit
 *   - delayed handshake: slow down a specific FSM phase but still establish
 *   - post-establishment: complete the session, then trigger a reset action
 */

#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

// BGP protocol constants
#define BGP_VERSION          4
#define BGP_HEADER_SIZE      19
#define BGP_MAX_MESSAGE_SIZE 4096
#define BGP_MARKER_SIZE      16
#define BGP_HOLD_TIME        180

// BGP message types
#define BGP_MSG_OPEN         1
#define BGP_MSG_UPDATE       2
#define BGP_MSG_NOTIFICATION 3
#define BGP_MSG_KEEPALIVE    4

#define DEFAULT_TAMPER_DELAY_SECONDS 3

typedef struct {
    uint8_t  marker[BGP_MARKER_SIZE];
    uint16_t length;
    uint8_t  type;
} __attribute__((packed)) bgp_header_t;

typedef struct {
    uint8_t  version;
    uint16_t my_as;
    uint16_t hold_time;
    uint32_t bgp_identifier;
    uint8_t  opt_param_len;
} __attribute__((packed)) bgp_open_t;

typedef enum {
    PEER_TAMPER_NONE = 0,
    PEER_TAMPER_SEND_NOTIFICATION,
    PEER_TAMPER_INVALID_HEADER,
    PEER_TAMPER_PARTIAL_OPEN,
    PEER_TAMPER_CLOSE_AFTER_ACCEPT,
    PEER_TAMPER_CLOSE_AFTER_OPEN,
    PEER_TAMPER_DELAY_OPEN,
    PEER_TAMPER_DELAY_KEEPALIVE,
    PEER_TAMPER_WRONG_OPEN_AS,
    PEER_TAMPER_BAD_OPEN_LENGTH
} peer_tamper_kind_t;

typedef struct {
    peer_tamper_kind_t kind;
    const char        *name;
    const char        *description;
    int                short_lived;
    int                await_close;  /* After sending: half-close, then wait until bgpsim closes (it has read the bytes) */
} peer_tamper_def_t;

static int wait_for_peer_close(int sock_fd, int timeout_ms);

typedef struct {
    const peer_tamper_def_t *def;
    int                      delay_seconds;
} peer_tamper_t;

typedef struct {
    uint8_t  marker_fill;
    uint8_t  version;
    uint32_t my_as;
    uint16_t hold_time;
    uint32_t router_id;
    uint16_t declared_length;
    size_t   bytes_to_send;
} bgp_open_send_options_t;

static const peer_tamper_def_t peer_tamper_defs[] = {
    {
        PEER_TAMPER_NONE,
        "none",
        "normal peer behavior",
        0,
        0
    },
    {
        PEER_TAMPER_SEND_NOTIFICATION,
        "send_notification",
        "establish the session, then send a NOTIFICATION",
        0,
        0
    },
    {
        PEER_TAMPER_INVALID_HEADER,
        "invalid_header",
        "send an OPEN header with invalid marker bytes, then close",
        1,
        1
    },
    {
        PEER_TAMPER_PARTIAL_OPEN,
        "partial_open",
        "send only part of an OPEN message, then close",
        1,
        1
    },
    {
        PEER_TAMPER_CLOSE_AFTER_ACCEPT,
        "close_after_accept",
        "accept the TCP connection and close before any BGP exchange",
        1,
        0
    },
    {
        PEER_TAMPER_CLOSE_AFTER_OPEN,
        "close_after_open",
        "send a valid OPEN and close before KEEPALIVE exchange completes",
        1,
        1
    },
    {
        PEER_TAMPER_DELAY_OPEN,
        "delay_open",
        "delay sending OPEN, then complete the handshake normally",
        0,
        0
    },
    {
        PEER_TAMPER_DELAY_KEEPALIVE,
        "delay_keepalive",
        "delay the final KEEPALIVE, keeping bgpsim in OpenConfirm longer",
        0,
        0
    },
    {
        PEER_TAMPER_WRONG_OPEN_AS,
        "wrong_open_as",
        "send an OPEN with the wrong AS number, then close",
        1,
        1
    },
    {
        PEER_TAMPER_BAD_OPEN_LENGTH,
        "bad_open_length",
        "send an OPEN with an invalid length field, then close",
        1,
        1
    }
};

static int send_all(int sock_fd, const uint8_t *data, size_t len) {
    size_t sent = 0;
    int    send_flags = 0;

#ifdef MSG_NOSIGNAL
    send_flags |= MSG_NOSIGNAL;
#endif

    while (sent < len) {
        ssize_t n = send(sock_fd, data + sent, len - sent, send_flags);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("send");
            return -1;
        }
        sent += (size_t)n;
    }

    return 0;
}

static int recv_all(int sock_fd, uint8_t *data, size_t len) {
    size_t received = 0;

    while (received < len) {
        ssize_t n = recv(sock_fd, data + received, len - received, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("recv");
            return -1;
        }
        if (n == 0) {
            fprintf(stderr, "Connection closed by peer\n");
            return -1;
        }
        received += (size_t)n;
    }

    return 0;
}

static void close_if_valid(int *sock_fd) {
    if (*sock_fd >= 0) {
        close(*sock_fd);
        *sock_fd = -1;
    }
}

static int parse_positive_int(const char *value, int default_value, int min_value, int max_value) {
    char *end = NULL;
    long  parsed;

    if (value == NULL || value[0] == '\0') {
        return default_value;
    }

    errno = 0;
    parsed = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        return default_value;
    }
    if (parsed < min_value || parsed > max_value) {
        return default_value;
    }

    return (int)parsed;
}

static uint32_t parse_uint32_default(const char *value,
                                     uint32_t default_value,
                                     uint32_t min_value,
                                     uint32_t max_value) {
    char *end = NULL;
    unsigned long parsed;

    if (value == NULL || value[0] == '\0') {
        return default_value;
    }

    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        return default_value;
    }
    if (parsed < min_value || parsed > max_value) {
        return default_value;
    }

    return (uint32_t)parsed;
}

static int parse_router_id_arg(const char *value, uint32_t *router_id) {
    struct in_addr addr4;

    if (value == NULL || router_id == NULL) {
        return -1;
    }

    if (inet_pton(AF_INET, value, &addr4) != 1) {
        return -1;
    }

    *router_id = ntohl(addr4.s_addr);
    return 0;
}

static int format_sockaddr_numeric(const struct sockaddr *addr,
                                   socklen_t addr_len,
                                   char *ip,
                                   size_t ip_len,
                                   uint16_t *port) {
    char service[NI_MAXSERV];
    unsigned long parsed_port;
    char *end = NULL;

    if (getnameinfo(addr, addr_len, ip, (socklen_t)ip_len,
                    service, sizeof(service),
                    NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
        return -1;
    }

    if (port == NULL) {
        return 0;
    }

    errno = 0;
    parsed_port = strtoul(service, &end, 10);
    if (errno != 0 || end == service || *end != '\0' || parsed_port > 65535) {
        return -1;
    }

    *port = (uint16_t)parsed_port;
    return 0;
}

static void configure_listener_socket(int sock_fd, int family) {
    int reuse = 1;

    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR,
                   &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt");
    }

#ifdef SO_REUSEPORT
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEPORT,
                   &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt");
    }
#endif

    if (family == AF_INET6) {
        int v6only = 1;

        if (setsockopt(sock_fd, IPPROTO_IPV6, IPV6_V6ONLY,
                       &v6only, sizeof(v6only)) < 0) {
            perror("setsockopt");
        }
    }
}

static void configure_connected_socket(int sock_fd) {
#ifdef SO_NOSIGPIPE
    int opt = 1;

    if (setsockopt(sock_fd, SOL_SOCKET, SO_NOSIGPIPE,
                   &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
    }
#else
    (void)sock_fd;
#endif
}

static void print_supported_tampers(void) {
    size_t i;

    printf("Peer tampers via BGP_TEST_TAMPER:\n");
    for (i = 1; i < ARRAY_SIZE(peer_tamper_defs); i++) {
        printf("  %-18s %s\n", peer_tamper_defs[i].name, peer_tamper_defs[i].description);
    }
}

static const peer_tamper_def_t *find_peer_tamper_def(const char *name) {
    size_t i;

    if (name == NULL || name[0] == '\0') {
        return &peer_tamper_defs[0];
    }

    for (i = 0; i < ARRAY_SIZE(peer_tamper_defs); i++) {
        if (strcmp(peer_tamper_defs[i].name, name) == 0) {
            return &peer_tamper_defs[i];
        }
    }

    return NULL;
}

static int load_peer_tamper(peer_tamper_t *tamper) {
    const char              *name = getenv("BGP_TEST_TAMPER");
    const peer_tamper_def_t *def = find_peer_tamper_def(name);

    if (def == NULL) {
        fprintf(stderr, "Unknown BGP_TEST_TAMPER value: %s\n", name != NULL ? name : "(null)");
        print_supported_tampers();
        return -1;
    }

    tamper->def = def;
    tamper->delay_seconds = parse_positive_int(getenv("BGP_TEST_TAMPER_DELAY"), DEFAULT_TAMPER_DELAY_SECONDS, 1, 60);
    return 0;
}

static void init_bgp_open_send_options(bgp_open_send_options_t *options, uint32_t my_as, uint32_t router_id) {
    memset(options, 0, sizeof(*options));
    options->marker_fill = 0xFF;
    options->version = BGP_VERSION;
    options->my_as = my_as;
    options->hold_time = BGP_HOLD_TIME;
    options->router_id = router_id;
    options->declared_length = (uint16_t)(BGP_HEADER_SIZE + sizeof(bgp_open_t));
    options->bytes_to_send = BGP_HEADER_SIZE + sizeof(bgp_open_t);
}

static uint32_t choose_wrong_as(uint32_t my_as) {
    if (my_as == 1) {
        return 2;
    }

    return my_as - 1;
}

static int send_bgp_open_with_options(int sock_fd, const bgp_open_send_options_t *options) {
    uint8_t buffer[BGP_HEADER_SIZE + sizeof(bgp_open_t)];
    bgp_header_t *hdr = (bgp_header_t *)buffer;
    bgp_open_t   *open = (bgp_open_t *)(buffer + BGP_HEADER_SIZE);
    size_t        actual_length = sizeof(buffer);

    if (options->bytes_to_send == 0 || options->bytes_to_send > actual_length) {
        fprintf(stderr, "Invalid OPEN send length: %zu\n", options->bytes_to_send);
        return -1;
    }

    memset(hdr->marker, options->marker_fill, BGP_MARKER_SIZE);
    hdr->length = htons(options->declared_length);
    hdr->type = BGP_MSG_OPEN;

    open->version = options->version;
    open->my_as = htons((uint16_t)options->my_as);
    open->hold_time = htons(options->hold_time);
    open->bgp_identifier = htonl(options->router_id);
    open->opt_param_len = 0;

    printf("Sending OPEN: AS=%u, ID=%u.%u.%u.%u, HoldTime=%u\n",
           options->my_as,
           (options->router_id >> 24) & 0xFF,
           (options->router_id >> 16) & 0xFF,
           (options->router_id >> 8) & 0xFF,
           options->router_id & 0xFF,
           options->hold_time);
    if (options->version != BGP_VERSION ||
        options->declared_length != actual_length ||
        options->bytes_to_send != actual_length ||
        options->marker_fill != 0xFF) {
        printf("OPEN tamper details: version=%u marker=0x%02x declared_length=%u bytes_sent=%zu\n",
               options->version,
               options->marker_fill,
               options->declared_length,
               options->bytes_to_send);
    }

    return send_all(sock_fd, buffer, options->bytes_to_send);
}

static int send_bgp_open(int sock_fd, uint32_t my_as, uint32_t router_id) {
    bgp_open_send_options_t options;

    init_bgp_open_send_options(&options, my_as, router_id);
    return send_bgp_open_with_options(sock_fd, &options);
}

static int send_bgp_keepalive(int sock_fd) {
    uint8_t       buffer[BGP_HEADER_SIZE];
    bgp_header_t *hdr = (bgp_header_t *)buffer;

    memset(hdr->marker, 0xFF, BGP_MARKER_SIZE);
    hdr->length = htons(BGP_HEADER_SIZE);
    hdr->type = BGP_MSG_KEEPALIVE;

    printf("Sending KEEPALIVE\n");
    return send_all(sock_fd, buffer, sizeof(buffer));
}

static int send_bgp_notification(int sock_fd, uint8_t error_code, uint8_t error_subcode) {
    uint8_t       buffer[BGP_HEADER_SIZE + 2];
    bgp_header_t *hdr = (bgp_header_t *)buffer;

    memset(hdr->marker, 0xFF, BGP_MARKER_SIZE);
    hdr->length = htons(BGP_HEADER_SIZE + 2);
    hdr->type = BGP_MSG_NOTIFICATION;
    buffer[BGP_HEADER_SIZE] = error_code;
    buffer[BGP_HEADER_SIZE + 1] = error_subcode;

    printf("Sending NOTIFICATION: error_code=%u, error_subcode=%u\n", error_code, error_subcode);
    return send_all(sock_fd, buffer, sizeof(buffer));
}

static int recv_bgp_message(int sock_fd, uint8_t *buffer, size_t buffer_size, uint8_t *msg_type) {
    bgp_header_t *hdr = (bgp_header_t *)buffer;
    uint16_t      msg_len;
    int           i;

    if (recv_all(sock_fd, buffer, BGP_HEADER_SIZE) < 0) {
        return -1;
    }

    for (i = 0; i < BGP_MARKER_SIZE; i++) {
        if (hdr->marker[i] != 0xFF) {
            fprintf(stderr, "Invalid BGP marker\n");
            return -1;
        }
    }

    msg_len = ntohs(hdr->length);
    *msg_type = hdr->type;

    if (msg_len < BGP_HEADER_SIZE || msg_len > buffer_size) {
        fprintf(stderr, "Invalid BGP message length: %u\n", msg_len);
        return -1;
    }

    if (msg_len > BGP_HEADER_SIZE) {
        if (recv_all(sock_fd, buffer + BGP_HEADER_SIZE, msg_len - BGP_HEADER_SIZE) < 0) {
            return -1;
        }
    }

    return (int)msg_len;
}

static int process_bgp_open(const uint8_t *msg, size_t msg_len) {
    const bgp_open_t *open = (const bgp_open_t *)(msg + BGP_HEADER_SIZE);
    uint16_t          remote_as;
    uint16_t          hold_time;
    uint32_t          remote_id;

    if (msg_len < BGP_HEADER_SIZE + sizeof(bgp_open_t)) {
        fprintf(stderr, "OPEN message too short\n");
        return -1;
    }

    remote_as = ntohs(open->my_as);
    hold_time = ntohs(open->hold_time);
    remote_id = ntohl(open->bgp_identifier);

    printf("Received OPEN: AS=%u, ID=%u.%u.%u.%u, HoldTime=%u\n",
           remote_as,
           (remote_id >> 24) & 0xFF,
           (remote_id >> 16) & 0xFF,
           (remote_id >> 8) & 0xFF,
           remote_id & 0xFF,
           hold_time);

    return 0;
}

static int connect_to_bgp_server(const char *server_ip, uint16_t port) {
    struct addrinfo  hints;
    struct addrinfo *results = NULL;
    struct addrinfo *current;
    char             port_str[16];
    int              sock_fd = -1;
    int              gai_error;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;

    snprintf(port_str, sizeof(port_str), "%u", port);

    gai_error = getaddrinfo(server_ip, port_str, &hints, &results);
    if (gai_error != 0) {
        fprintf(stderr, "Address resolution failed for %s:%u: %s\n", server_ip, port, gai_strerror(gai_error));
        return -1;
    }

    printf("Connecting to %s:%u...\n", server_ip, port);

    for (current = results; current != NULL; current = current->ai_next) {
        sock_fd = socket(current->ai_family, current->ai_socktype, current->ai_protocol);
        if (sock_fd < 0) {
            continue;
        }

        if (connect(sock_fd, current->ai_addr, current->ai_addrlen) == 0) {
            char     connected_ip[NI_MAXHOST];
            uint16_t connected_port = port;

            configure_connected_socket(sock_fd);

            if (format_sockaddr_numeric(current->ai_addr, current->ai_addrlen,
                                        connected_ip, sizeof(connected_ip),
                                        &connected_port) == 0) {
                printf("Connected successfully to %s:%u\n", connected_ip, connected_port);
            } else {
                printf("Connected successfully\n");
            }

            freeaddrinfo(results);
            return sock_fd;
        }

        perror("connect");
        close(sock_fd);
        sock_fd = -1;
    }

    freeaddrinfo(results);
    return -1;
}

static int setup_listen_socket(const char *listen_ip, uint16_t port) {
    struct addrinfo  hints;
    struct addrinfo *results = NULL;
    struct addrinfo *current;
    char             port_str[16];
    int              listen_sock = -1;
    int              gai_error;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;

    snprintf(port_str, sizeof(port_str), "%u", port);

    gai_error = getaddrinfo(listen_ip, port_str, &hints, &results);
    if (gai_error != 0) {
        fprintf(stderr, "Address resolution failed for %s:%u: %s\n", listen_ip, port, gai_strerror(gai_error));
        return -1;
    }

    for (current = results; current != NULL; current = current->ai_next) {
        char     bound_ip[NI_MAXHOST];
        uint16_t bound_port = port;

        listen_sock = socket(current->ai_family, current->ai_socktype, current->ai_protocol);
        if (listen_sock < 0) {
            continue;
        }

        configure_listener_socket(listen_sock, current->ai_family);

        if (bind(listen_sock, current->ai_addr, current->ai_addrlen) < 0) {
            perror("bind");
            close(listen_sock);
            listen_sock = -1;
            continue;
        }

        if (listen(listen_sock, 5) < 0) {
            perror("listen");
            close(listen_sock);
            listen_sock = -1;
            continue;
        }

        if (format_sockaddr_numeric(current->ai_addr, current->ai_addrlen,
                                    bound_ip, sizeof(bound_ip),
                                    &bound_port) == 0) {
            printf("Listening on %s:%u...\n", bound_ip, bound_port);
        } else {
            printf("Listening on %s:%u...\n", listen_ip, port);
        }

        freeaddrinfo(results);
        return listen_sock;
    }

    freeaddrinfo(results);
    return -1;
}

static int accept_connection(int listen_sock) {
    struct sockaddr_storage client_addr;
    socklen_t               client_len = sizeof(client_addr);
    int                     client_sock;
    char                    client_ip[NI_MAXHOST];
    uint16_t                client_port = 0;

    printf("Waiting for incoming connection...\n");

    client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &client_len);
    if (client_sock < 0) {
        perror("accept");
        return -1;
    }

    if (format_sockaddr_numeric((const struct sockaddr *)&client_addr, client_len,
                                client_ip, sizeof(client_ip),
                                &client_port) == 0) {
        printf("Accepted connection from %s:%u\n", client_ip, client_port);
    } else {
        printf("Accepted connection\n");
    }

    configure_connected_socket(client_sock);

    return client_sock;
}

static void apply_tamper_delay(const peer_tamper_t *tamper, peer_tamper_kind_t kind, const char *phase_name) {
    if (tamper->def->kind != kind) {
        return;
    }

    printf("Tamper %s: delaying %s by %d seconds\n", tamper->def->name, phase_name, tamper->delay_seconds);
    sleep((unsigned int)tamper->delay_seconds);
}

static int run_one_shot_tamper(int sock_fd, uint32_t my_as, uint32_t router_id, const peer_tamper_t *tamper) {
    bgp_open_send_options_t options;
    int                     rc = 0;

    init_bgp_open_send_options(&options, my_as, router_id);

    switch (tamper->def->kind) {
        case PEER_TAMPER_CLOSE_AFTER_ACCEPT:
            printf("Tamper %s: closing immediately after TCP setup\n", tamper->def->name);
            return 0;

        case PEER_TAMPER_INVALID_HEADER:
            printf("Tamper %s: sending invalid marker bytes\n", tamper->def->name);
            options.marker_fill = 0x00;
            options.declared_length = BGP_HEADER_SIZE;
            options.bytes_to_send = BGP_HEADER_SIZE;
            rc = send_bgp_open_with_options(sock_fd, &options);
            break;

        case PEER_TAMPER_PARTIAL_OPEN:
            printf("Tamper %s: sending only a partial OPEN body\n", tamper->def->name);
            options.bytes_to_send = BGP_HEADER_SIZE + (sizeof(bgp_open_t) / 2);
            rc = send_bgp_open_with_options(sock_fd, &options);
            break;

        case PEER_TAMPER_CLOSE_AFTER_OPEN:
            printf("Tamper %s: sending OPEN, then closing before KEEPALIVE exchange\n", tamper->def->name);
            rc = send_bgp_open_with_options(sock_fd, &options);
            break;

        case PEER_TAMPER_WRONG_OPEN_AS:
            printf("Tamper %s: sending OPEN with wrong AS\n", tamper->def->name);
            options.my_as = choose_wrong_as(my_as);
            rc = send_bgp_open_with_options(sock_fd, &options);
            break;

        case PEER_TAMPER_BAD_OPEN_LENGTH:
            printf("Tamper %s: sending OPEN with invalid length field\n", tamper->def->name);
            options.declared_length = (uint16_t)(BGP_MAX_MESSAGE_SIZE + 1);
            rc = send_bgp_open_with_options(sock_fd, &options);
            break;

        default:
            fprintf(stderr, "Tamper %s is not a one-shot tamper\n", tamper->def->name);
            return -1;
    }

    if (rc == 0 && tamper->def->await_close) {
        /*
         * The FIN follows the bytes, so bgpsim reads them and then sees the close; closing at once could reset the
         * connection (with bgpsim's OPEN unread here) before bgpsim reads them.
         */
        shutdown(sock_fd, SHUT_WR);
        if (!wait_for_peer_close(sock_fd, 10000)) {
            fprintf(stderr, "Tamper %s: bgpsim did not close the connection\n", tamper->def->name);
            rc = -1;
        }
    }

    return rc;
}

static int perform_bgp_handshake(int sock_fd, uint32_t my_as, uint32_t router_id, const peer_tamper_t *tamper) {
    uint8_t buffer[BGP_MAX_MESSAGE_SIZE];
    uint8_t msg_type;
    int     msg_len;

    printf("\n=== Starting BGP Handshake ===\n\n");

    apply_tamper_delay(tamper, PEER_TAMPER_DELAY_OPEN, "OPEN send");

    if (send_bgp_open(sock_fd, my_as, router_id) < 0) {
        fprintf(stderr, "Failed to send OPEN\n");
        return -1;
    }

    printf("Waiting for OPEN...\n");
    msg_len = recv_bgp_message(sock_fd, buffer, sizeof(buffer), &msg_type);
    if (msg_len < 0) {
        fprintf(stderr, "Failed to receive OPEN\n");
        return -1;
    }
    if (msg_type != BGP_MSG_OPEN) {
        fprintf(stderr, "Expected OPEN message, got type %u\n", msg_type);
        return -1;
    }
    if (process_bgp_open(buffer, (size_t)msg_len) < 0) {
        return -1;
    }

    printf("Waiting for KEEPALIVE...\n");
    msg_len = recv_bgp_message(sock_fd, buffer, sizeof(buffer), &msg_type);
    if (msg_len < 0) {
        fprintf(stderr, "Failed to receive KEEPALIVE\n");
        return -1;
    }
    if (msg_type != BGP_MSG_KEEPALIVE) {
        fprintf(stderr, "Expected KEEPALIVE message, got type %u\n", msg_type);
        return -1;
    }
    printf("Received KEEPALIVE\n");

    apply_tamper_delay(tamper, PEER_TAMPER_DELAY_KEEPALIVE, "KEEPALIVE send");

    if (send_bgp_keepalive(sock_fd) < 0) {
        fprintf(stderr, "Failed to send KEEPALIVE\n");
        return -1;
    }

    printf("\n=== BGP Session ESTABLISHED ===\n\n");
    return 0;
}

static void run_keepalive_loop(int sock_fd, int keep_alive_seconds) {
    uint8_t buffer[BGP_MAX_MESSAGE_SIZE];
    uint8_t msg_type;
    int     rx_keepalive = 1;
    int     tx_keepalive = 1;
    int     keepalive_interval = 5;
    time_t  start_time = time(NULL);
    time_t  last_keepalive = time(NULL);

    printf("Keeping session alive for %d seconds with keepalive exchange...\n", keep_alive_seconds);

    while (time(NULL) - start_time < keep_alive_seconds) {
        fd_set         read_fds;
        struct timeval timeout = {0, 100000};  /* Wake for a message at once, else check the timers every 100 ms */
        int            ready;

        FD_ZERO(&read_fds);
        FD_SET(sock_fd, &read_fds);

        ready = select(sock_fd + 1, &read_fds, NULL, NULL, &timeout);
        if (ready < 0) {
            perror("select");
            break;
        }

        if (ready > 0 && FD_ISSET(sock_fd, &read_fds)) {
            int msg_len = recv_bgp_message(sock_fd, buffer, sizeof(buffer), &msg_type);

            if (msg_len < 0) {
                printf("Connection closed while keeping session alive\n");
                break;
            }

            if (msg_type == BGP_MSG_KEEPALIVE) {
                rx_keepalive++;
                printf("Received KEEPALIVE (total RX: %d)\n", rx_keepalive);
            } else if (msg_type == BGP_MSG_NOTIFICATION) {
                printf("Received NOTIFICATION, closing session\n");
                break;
            }
        }

        if ((time(NULL) - last_keepalive) >= keepalive_interval) {
            if (send_bgp_keepalive(sock_fd) == 0) {
                tx_keepalive++;
                printf("Periodic KEEPALIVE sent (total TX: %d)\n", tx_keepalive);
                last_keepalive = time(NULL);
            }
        }
    }

    printf("\nKeepalive session summary:\n");
    printf("  Duration: %d seconds\n", keep_alive_seconds);
    printf("  Keepalives RX: %d\n", rx_keepalive);
    printf("  Keepalives TX: %d\n", tx_keepalive);
    printf("  Expected RX: ~%d (bgpsim sends every ~60 seconds)\n", keep_alive_seconds / 60 + 1);
    printf("  Expected TX: ~%d (client sends every %d seconds)\n",
           keep_alive_seconds / keepalive_interval + 1,
           keepalive_interval);

    if (rx_keepalive >= 1 && tx_keepalive >= keep_alive_seconds / keepalive_interval) {
        printf("\n*** KEEPALIVE TEST: PASSED ***\n");
    } else {
        printf("\n*** KEEPALIVE TEST: FAILED ***\n");
    }
}

/*
 * Read and drop what arrives until the peer closes the connection (EOF or reset), or until timeout_ms. Returns 1 when
 * it closed.
 */
static int wait_for_peer_close(int sock_fd, int timeout_ms) {
    struct timespec start;

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        struct timespec now;
        fd_set          read_fds;
        struct timeval  timeout;
        uint8_t         discard[4096];
        long            left_ms;
        ssize_t         n;

        clock_gettime(CLOCK_MONOTONIC, &now);
        left_ms = timeout_ms - ((now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000);
        if (left_ms <= 0) {
            return 0;
        }
        timeout.tv_sec = left_ms / 1000;
        timeout.tv_usec = (left_ms % 1000) * 1000;
        FD_ZERO(&read_fds);
        FD_SET(sock_fd, &read_fds);
        if (select(sock_fd + 1, &read_fds, NULL, NULL, &timeout) < 0 && errno != EINTR) {
            return 0;
        }
        n = recv(sock_fd, discard, sizeof(discard), MSG_DONTWAIT);
        if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
            return 1;
        }
    }
}

static int run_post_established_tamper(int sock_fd, const peer_tamper_t *tamper) {
    if (tamper->def->kind != PEER_TAMPER_SEND_NOTIFICATION) {
        return 0;
    }

    printf("\n=== Sending NOTIFICATION to trigger session reset ===\n");
    if (send_bgp_notification(sock_fd, 6, 0) < 0) {
        fprintf(stderr, "Failed to send NOTIFICATION\n");
        return -1;
    }
    printf("NOTIFICATION sent\n");
    /*
     * bgpsim resets the session when it reads the NOTIFICATION: wait for it to close the connection, so the client
     * does not exit (and reset the socket) before bgpsim has read it.
     */
    if (!wait_for_peer_close(sock_fd, 10000)) {
        fprintf(stderr, "bgpsim did not close the session after the NOTIFICATION\n");
        return -1;
    }
    printf("Session closed by bgpsim\n");
    return 0;
}

static void print_usage(const char *progname) {
    printf("Usage: %s [options] [ip] [port] [as] [router_id] [keepalive_sec]\n", progname);
    printf("Options:\n");
    printf("  --passive    Passive mode (listen for connections)\n");
    printf("  --active     Active mode (connect to server, default)\n");
    printf("  -h, --help   Show this help message\n");
    printf("\nDefaults:\n");
    printf("  ip: 127.0.0.1\n");
    printf("  port: 20000\n");
    printf("  as: 200\n");
    printf("  router_id: 2.2.2.2\n");
    printf("  keepalive_sec: 0 (no keepalive)\n");
    printf("  Transport accepts either IPv4 or IPv6 peer addresses.\n");
    printf("\n");
    print_supported_tampers();
    printf("Use BGP_TEST_TAMPER_DELAY to adjust delay_open/delay_keepalive.\n");
}

int main(int argc, char *argv[]) {
    const char   *ip = "127.0.0.1";
    uint16_t      port = 20000;
    uint32_t      my_as = 200;
    uint32_t      router_id = (2U << 24) | (2U << 16) | (2U << 8) | 2U;
    int           keep_alive_seconds = 0;
    int           passive_mode = 0;
    int           arg_index = 1;
    int           sock_fd = -1;
    int           listen_sock = -1;
    peer_tamper_t tamper;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    if (load_peer_tamper(&tamper) < 0) {
        return 1;
    }

    while (arg_index < argc) {
        if (strcmp(argv[arg_index], "--passive") == 0) {
            passive_mode = 1;
            arg_index++;
        } else if (strcmp(argv[arg_index], "--active") == 0) {
            passive_mode = 0;
            arg_index++;
        } else if (strcmp(argv[arg_index], "-h") == 0 || strcmp(argv[arg_index], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            break;
        }
    }

    if (arg_index < argc) {
        ip = argv[arg_index++];
    }
    if (arg_index < argc) {
        port = (uint16_t)parse_positive_int(argv[arg_index++], port, 1, 65535);
    }
    if (arg_index < argc) {
        my_as = parse_uint32_default(argv[arg_index++], my_as, 1, UINT32_MAX);
    }
    if (arg_index < argc) {
        if (parse_router_id_arg(argv[arg_index++], &router_id) != 0) {
            fprintf(stderr, "Invalid router ID (must be IPv4 dotted-decimal)\n");
            return 1;
        }
    }
    if (arg_index < argc) {
        keep_alive_seconds = parse_positive_int(argv[arg_index++], 0, 0, 86400);
    }

    printf("BGP Test Client\n");
    printf("===============\n");
    printf("Mode: %s\n", passive_mode ? "Passive (Listening)" : "Active (Connecting)");
    printf("%s: %s:%u\n", passive_mode ? "Listen" : "Server", ip, port);
    printf("My AS: %u\n", my_as);
    printf("My Router ID: %u.%u.%u.%u\n",
           (router_id >> 24) & 0xFF,
           (router_id >> 16) & 0xFF,
           (router_id >> 8) & 0xFF,
           router_id & 0xFF);
    printf("Peer Tamper: %s\n", tamper.def->name);
    if (tamper.def->kind == PEER_TAMPER_DELAY_OPEN ||
        tamper.def->kind == PEER_TAMPER_DELAY_KEEPALIVE) {
        printf("Tamper Delay: %d seconds\n", tamper.delay_seconds);
    }
    printf("\n");

    if (passive_mode) {
        listen_sock = setup_listen_socket(ip, port);
        if (listen_sock < 0) {
            return 1;
        }

        sock_fd = accept_connection(listen_sock);
        if (sock_fd < 0) {
            close_if_valid(&listen_sock);
            return 1;
        }

        /*
         * Passive mode only serves one peer session. Close the listener as soon
         * as the connection is accepted so reconnect tests cannot race against a
         * stale LISTEN socket from the previous passive client instance.
         */
        close_if_valid(&listen_sock);
    } else {
        sock_fd = connect_to_bgp_server(ip, port);
        if (sock_fd < 0) {
            return 1;
        }
    }

    if (tamper.def->short_lived) {
        int rc = run_one_shot_tamper(sock_fd, my_as, router_id, &tamper);

        close_if_valid(&sock_fd);
        close_if_valid(&listen_sock);
        return (rc == 0) ? 0 : 1;
    }

    if (perform_bgp_handshake(sock_fd, my_as, router_id, &tamper) < 0) {
        close_if_valid(&sock_fd);
        close_if_valid(&listen_sock);
        return 1;
    }

    if (keep_alive_seconds > 0) {
        run_keepalive_loop(sock_fd, keep_alive_seconds);
    }

    if (run_post_established_tamper(sock_fd, &tamper) < 0) {
        close_if_valid(&sock_fd);
        close_if_valid(&listen_sock);
        return 1;
    }

    close_if_valid(&sock_fd);
    close_if_valid(&listen_sock);
    printf("Connection closed\n");
    return 0;
}
