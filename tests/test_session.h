/*
 * Runtime session helpers for C tests: a simulator with a running runtime, and a raw loopback peer that a test drives
 * by hand. Shared by the OPEN tests and the UPDATE transmission tests.
 */
#ifndef BGPSIM_TEST_SESSION_H
#define BGPSIM_TEST_SESSION_H

#include <poll.h>
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "bgp.h"
#include "bgpsim.h"
#include "control.h"
#include "test_wait.h"
#include "bgp_router.h"
#include "bgp_neighbor.h"
#include "test_runtime.h"

#define SESSION_TIMEOUT_MS WAIT_TIMEOUT_MS

typedef struct {
    bgp_neighbor_t *neighbor;
} neighbor_wait_t;

static inline int neighbor_established(void *opaque) {
    neighbor_wait_t *wait = opaque;

    return wait != NULL && wait->neighbor != NULL && wait->neighbor->state == BGP_STATE_ESTABLISHED;
}

/*
 * Connect to 127.0.0.1:port, retrying with backoff until timeout_ms while nothing listens there yet.
 */
static inline int connect_ipv4_loopback_from_with_retry(const char *source, uint16_t port, int timeout_ms) {
    struct sockaddr_in remote_addr;
    struct sockaddr_in local_addr = {.sin_family = AF_INET};
    int64_t            deadline = wait_now_ms() + timeout_ms;
    useconds_t         delay = WAIT_FIRST_DELAY_US;

    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &remote_addr.sin_addr);
    if (source && inet_pton(AF_INET, source, &local_addr.sin_addr) != 1) return -1;

    do {
        int sock = socket(AF_INET, SOCK_STREAM, 0);

        if (sock >= 0) {
            if ((!source || bind(sock, (struct sockaddr *)&local_addr, sizeof(local_addr)) == 0) &&
                connect(sock, (struct sockaddr *)&remote_addr, sizeof(remote_addr)) == 0) {
                return sock;
            }
            close(sock);
        }
    } while (wait_backoff(deadline, &delay));

    return -1;
}

static inline int connect_ipv4_loopback_with_retry(uint16_t port, int timeout_ms) {
    return connect_ipv4_loopback_from_with_retry(NULL, port, timeout_ms);
}

/*
 * The bytes a test peer has read from a socket past its last whole message. The reader takes everything the kernel
 * holds instead of peeking for a whole message: loopback queues data in segments of up to 64 KB, and while the kernel
 * holds part of one, its buffer memory can keep the receive window at zero, so the rest of the message never comes.
 * The caller owns one reader per connection, including during handshake. There is no socket cache or eviction.
 */
#define PEER_RX_BYTES   (64 * 1024)

typedef struct {
    int     fd;
    size_t  len;
    size_t  limit;  /* Largest message the peer accepts; 0 for 4096. 65535 once it negotiated Extended Message */
    uint8_t data[PEER_RX_BYTES];
} peer_rx_t;

/*
 * Read one whole BGP message, waiting up to timeout_ms for it. Returns its length; -1 on a closed or broken socket or
 * a malformed header; -1 with errno ETIMEDOUT when no whole message came. It waits for new bytes with poll(), so a
 * message is returned as soon as its last byte arrives.
 */
static inline int recv_bgp_message_with_timeout(peer_rx_t *rx, uint8_t *buffer, size_t buffer_size,
                                                uint8_t *msg_type, int timeout_ms) {
    int64_t deadline = wait_now_ms() + timeout_ms;

    if (!rx) {
        return -1;
    }
    for (;;) {
        ssize_t got;

        if (rx->len >= BGP_HEADER_SIZE) {
            uint16_t len = (uint16_t)(rx->data[16] << 8 | rx->data[17]);

            for (int i = 0; i < BGP_MARKER_SIZE; i++) {
                if (rx->data[i] != 0xFF) {
                    return -1;
                }
            }
            if (len < BGP_HEADER_SIZE || len > (rx->limit ? rx->limit : BGP_MAX_MESSAGE_SIZE) || len > buffer_size) {
                return -1;
            }
            if (rx->len >= len) {
                memcpy(buffer, rx->data, len);
                *msg_type = rx->data[18];
                rx->len -= len;
                memmove(rx->data, rx->data + len, rx->len);
                return len;
            }
        }
        got = recv(rx->fd, rx->data + rx->len, sizeof(rx->data) - rx->len, MSG_DONTWAIT);
        if (got > 0) {
            rx->len += (size_t)got;
        } else if (got == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
            return -1;
        } else {
            int64_t       left_ms = deadline - wait_now_ms();
            struct pollfd pfd = {.fd = rx->fd, .events = POLLIN};

            if (left_ms <= 0) {
                errno = ETIMEDOUT;
                return -1;
            }
            poll(&pfd, 1, (int)left_ms);
        }
    }
}

static inline int send_raw(int fd, const uint8_t *buffer, size_t len) {
    return send(fd, buffer, len, 0) == (ssize_t)len ? 0 : -1;
}

typedef struct {
    bgp_neighbor_t *neighbor;
    uint64_t        keepalives;  /* rx_keepalive once the barrier KEEPALIVE is processed */
} keepalive_wait_t;

static inline int barrier_processed(void *opaque) {
    keepalive_wait_t *wait = opaque;

    return wait->neighbor->rx_keepalive >= wait->keepalives || wait->neighbor->state != BGP_STATE_ESTABLISHED;
}

/*
 * In-order barrier from the peer: send a KEEPALIVE and wait until bgpsim has processed it. bgpsim processes the
 * messages of a session in order, so it has then processed (and reacted to) everything the peer sent before; a test
 * checks "nothing happened" after this instead of after a pause. Returns 1 when the session is still ESTABLISHED.
 */
static inline int peer_barrier(int sock, bgp_neighbor_t *neighbor) {
    uint8_t          keepalive[BGP_HEADER_SIZE];
    keepalive_wait_t wait = {neighbor, neighbor->rx_keepalive + 1};

    return bgp_build_keepalive(keepalive, sizeof(keepalive)) == BGP_HEADER_SIZE &&
           send_raw(sock, keepalive, sizeof(keepalive)) == 0 &&
           wait_until(barrier_processed, &wait, SESSION_TIMEOUT_MS) && neighbor->rx_keepalive >= wait.keepalives &&
           neighbor->state == BGP_STATE_ESTABLISHED;
}

/*
 * A whole message of type is in the socket now; KEEPALIVEs before it are skipped. Does not wait.
 */
static inline int peer_has_message(peer_rx_t *peer, uint8_t type) {
    uint8_t buffer[BGP_MAX_MESSAGE_SIZE];
    uint8_t got = 0;

    while (recv_bgp_message_with_timeout(peer, buffer, sizeof(buffer), &got, 0) > 0) {
        if (got == type) {
            return 1;
        }
    }
    return 0;
}

/*
 * Start the runtime of a passive sim whose router 0 is already configured and wait for its listener.
 */
static inline int session_start_runtime(bgp_sim_t *sim, char *socket_path, size_t socket_path_size) {
    sim->passive_mode = 1;
    return start_runtime(sim, socket_path, socket_path_size) == 0 &&
                   wait_until(router_listening, sim->routers[0], SESSION_TIMEOUT_MS)
               ? 0
               : -1;
}

/*
 * Bring the session of a connected raw peer (identifier 2.2.2.2) to ESTABLISHED: read the OPEN of bgpsim, send an
 * OPEN with peer_caps (NULL: no capabilities), read the KEEPALIVE and send one. Takes the socket over: returns it, or
 * closes it and returns -1.
 */
static inline int session_handshake(peer_rx_t *peer, int sock, bgp_neighbor_t *neighbor, bgp_capabilities_t *peer_caps) {
    bgp_capabilities_t none;
    uint8_t            open_msg[BGP_MAX_MESSAGE_SIZE];
    uint8_t            buffer[BGP_MAX_MESSAGE_SIZE];
    uint8_t            type = 0;
    int                len;

    memset(&none, 0, sizeof(none));
    *peer = (peer_rx_t){.fd = sock};
    if (sock < 0) {
        return -1;
    }
    len = bgp_build_open_with_capabilities(open_msg, sizeof(open_msg), neighbor->remote_as, 0x02020202,
                                           peer_caps ? peer_caps : &none);
    if (recv_bgp_message_with_timeout(peer, buffer, sizeof(buffer), &type, SESSION_TIMEOUT_MS) <= 0 ||
        type != BGP_MSG_OPEN || len <= 0 || send_raw(sock, open_msg, (size_t)len) != 0 ||
        recv_bgp_message_with_timeout(peer, buffer, sizeof(buffer), &type, SESSION_TIMEOUT_MS) <= 0 ||
        type != BGP_MSG_KEEPALIVE) {
        close(sock);
        return -1;
    }

    len = bgp_build_keepalive(buffer, sizeof(buffer));
    if (len <= 0 || send_raw(sock, buffer, (size_t)len) != 0 ||
        !wait_until(neighbor_established, &(neighbor_wait_t){.neighbor = neighbor},
                    SESSION_TIMEOUT_MS)) {
        close(sock);
        return -1;
    }
    return sock;
}

/*
 * Connect a raw IPv4 loopback peer (AS 65001) to a neighbor and bring the session to ESTABLISHED with
 * session_handshake(). Returns the peer socket, or -1.
 */
static inline int session_connect_neighbor(peer_rx_t *peer, bgp_neighbor_t *neighbor, bgp_capabilities_t *peer_caps) {
    return session_handshake(peer, connect_ipv4_loopback_from_with_retry(neighbor->ip, neighbor->router->listen_port,
                                                                         SESSION_TIMEOUT_MS),
                             neighbor, peer_caps);
}

static inline int session_connect_peer(peer_rx_t *peer, bgp_sim_t *sim, bgp_capabilities_t *peer_caps) {
    return session_connect_neighbor(peer, sim->routers[0]->neighbors[0], peer_caps);
}

/*
 * session_start_runtime() and session_connect_peer().
 */
static inline int session_establish(peer_rx_t *peer, bgp_sim_t *sim, char *socket_path, size_t socket_path_size,
                                     bgp_capabilities_t *peer_caps) {
    if (session_start_runtime(sim, socket_path, socket_path_size) != 0) {
        return -1;
    }
    return session_connect_peer(peer, sim, peer_caps);
}

#endif /* BGPSIM_TEST_SESSION_H */
