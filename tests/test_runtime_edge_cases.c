#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "bgpsim.h"
#include "control.h"
#include "test_wait.h"
#include "bgp_router.h"
#include "test_result.h"
#include "bgp_neighbor.h"
#include "test_runtime.h"

typedef struct {
    bgp_neighbor_t *neighbor;
    int             min_retries;
} retry_wait_t;

static int neighbor_retried(void *opaque) {
    retry_wait_t *wait = opaque;

    return wait->neighbor->retry_count >= wait->min_retries &&
           wait->neighbor->session_resets >= (uint64_t)wait->min_retries;
}

static int wait_for_neighbor_retries(bgp_neighbor_t *neighbor, int min_retries) {
    return wait_until(neighbor_retried, &(retry_wait_t){neighbor, min_retries}, WAIT_TIMEOUT_MS);
}

static int count_retrying_neighbors(bgp_router_t *router, int min_retries) {
    int count = 0;

    for (int i = 0; i < router->neighbor_count; i++) {
        if (router->neighbors[i]->retry_count >= min_retries) {
            count++;
        }
    }

    return count;
}

typedef struct {
    bgp_router_t *router;
    int           min_retries;
    int           neighbors;
} retrying_wait_t;

static int neighbors_retrying(void *opaque) {
    retrying_wait_t *wait = opaque;

    return count_retrying_neighbors(wait->router, wait->min_retries) >= wait->neighbors;
}

/*
 * Every active router listens and has the expected neighbor count, and every neighbor is set up, idle, without a
 * stream and without retries. The active router count must also match.
 */
static int all_passive_neighbors_initialized(bgp_sim_t *sim, int expected_routers, int expected_neighbors_per_router) {
    int active_routers = 0;

    for (int i = 0; i < sim->router_count; i++) {
        bgp_router_t *router = sim->routers[i];

        if (!router->active) {
            continue;
        }
        active_routers++;
        if (!router->listener_initialized || !router->listener_open ||
            router->neighbor_count != expected_neighbors_per_router) {
            return 0;
        }

        for (int j = 0; j < router->neighbor_count; j++) {
            bgp_neighbor_t *neighbor = router->neighbors[j];

            if (!neighbor->runtime_initialized || neighbor->retry_count != 0 ||
                neighbor->state != BGP_STATE_IDLE || neighbor->stream_open) {
                return 0;
            }
        }
    }

    return active_routers == expected_routers;
}

typedef struct {
    bgp_sim_t *sim;
    int        routers;
    int        neighbors_per_router;
} passive_wait_t;

static int passive_neighbors_ready(void *opaque) {
    passive_wait_t *wait = opaque;

    return all_passive_neighbors_initialized(wait->sim, wait->routers, wait->neighbors_per_router);
}

static void test_active_neighbor_retries_without_peer(void) {
    bgp_sim_t *sim = create_sim();
    char       socket_path[108] = "";
    int        passed = 0;

    if (sim != NULL) {
        sim->passive_mode = 0;
        if (bgp_add_router(sim, 65000) == 1 &&
            bgp_add_neighbor(sim, 65000, "127.0.0.10", 65001) == 1 &&
            start_runtime(sim, socket_path, sizeof(socket_path)) == 0 &&
            wait_for_neighbor_retries(sim->routers[0]->neighbors[0], 1)) {
            bgp_neighbor_t *neighbor = sim->routers[0]->neighbors[0];

            passed = neighbor->runtime_initialized &&
                     neighbor->retry_count >= 1 &&
                     neighbor->session_resets >= 1 &&
                     neighbor->active;
        }
    }

    test_result(passed, "Active neighbor retries and resets when no peer is listening");
    destroy_sim(sim);
    unlink(socket_path);
}

static void test_remove_retrying_neighbor_under_runtime(void) {
    bgp_sim_t *sim = create_sim();
    char       socket_path[108] = "";
    int        passed = 0;

    if (sim != NULL) {
        sim->passive_mode = 0;
        if (bgp_add_router(sim, 65000) == 1 &&
            bgp_add_neighbor(sim, 65000, "127.0.0.11", 65001) == 1 &&
            start_runtime(sim, socket_path, sizeof(socket_path)) == 0 &&
            wait_for_neighbor_retries(sim->routers[0]->neighbors[0], 1) &&
            bgp_remove_neighbor(sim, 65000, "127.0.0.11") == 1 &&
            wait_for_only_neighbor_freed(sim->routers[0])) {
            passed = sim->routers[0]->neighbor_count == 0;
        }
    }

    test_result(passed, "Retrying active neighbor can be removed cleanly under runtime churn");
    destroy_sim(sim);
    unlink(socket_path);
}

static void test_repeated_retrying_neighbor_add_remove_cycles(void) {
    bgp_sim_t  *sim = create_sim();
    char        socket_path[108] = "";
    const char *ip = "127.2.0.10";
    int         passed = 1;

    if (sim == NULL) {
        passed = 0;
    } else {
        sim->passive_mode = 0;
        if (bgp_add_router(sim, 65000) != 1 ||
            start_runtime(sim, socket_path, sizeof(socket_path)) != 0) {
            passed = 0;
        }
    }

    for (int i = 0; passed && i < 12; i++) {
        if (bgp_add_neighbor(sim, 65000, ip, 65001) != 1) {
            passed = 0;
            break;
        }

        if (!wait_for_neighbor_retries(sim->routers[0]->neighbors[0], 1)) {
            passed = 0;
            break;
        }

        if (bgp_remove_neighbor(sim, 65000, ip) != 1 ||
            !wait_for_only_neighbor_freed(sim->routers[0])) {
            passed = 0;
            break;
        }

        if (sim->routers[0]->neighbor_count != 0) {
            passed = 0;
            break;
        }
    }

    test_result(passed, "Repeated active neighbor add/remove cycles stay clean under retry churn");
    destroy_sim(sim);
    unlink(socket_path);
}

static void test_remove_router_with_many_retrying_neighbors(void) {
    bgp_sim_t *sim = create_sim();
    char       socket_path[108] = "";
    int        passed = 0;

    if (sim != NULL) {
        sim->passive_mode = 0;
        if (bgp_add_router(sim, 65100) == 1) {
            for (int i = 0; i < 24; i++) {
                char ip[32];

                snprintf(ip, sizeof(ip), "127.1.0.%d", i + 1);
                if (bgp_add_neighbor(sim, 65100, ip, (uint32_t)(65200 + i)) != 1) {
                    passed = 0;
                    goto done_many_retrying;
                }
            }

            if (start_runtime(sim, socket_path, sizeof(socket_path)) == 0 &&
                wait_until(neighbors_retrying, &(retrying_wait_t){sim->routers[0], 1, 12}, WAIT_TIMEOUT_MS)) {
                if (bgp_remove_router(sim, 65100) == 1 &&
                    wait_for_router_finalize(sim, sim->routers[0])) {
                    passed = 1;
                }
            }
        }
    }

done_many_retrying:
    test_result(passed, "Router teardown handles many concurrently retrying active neighbors");
    destroy_sim(sim);
    unlink(socket_path);
}

static void test_passive_scale_after_deferred_config_load(void) {
    bgp_sim_t *sim = create_sim();
    char       socket_path[108] = "";
    const int  router_count = 6;
    const int  neighbors_per_router = 16;
    int        passed = 0;

    if (sim != NULL) {
        sim->passive_mode = 1;
        sim->config_loading = 1;

        passed = 1;
        for (int i = 0; i < router_count && passed; i++) {
            uint32_t local_as = (uint32_t)(66000 + i);

            if (bgp_add_router(sim, local_as) != 1) {
                passed = 0;
                break;
            }

            for (int j = 0; j < neighbors_per_router; j++) {
                char ip[32];

                snprintf(ip, sizeof(ip), "127.%d.%d.%d", i + 2, j / 250, (j % 250) + 1);
                if (bgp_add_neighbor(sim, local_as, ip, (uint32_t)(67000 + i * 100 + j)) != 1) {
                    passed = 0;
                    break;
                }
            }
        }

        if (passed) {
            sim->config_loading = 0;
            passed = start_runtime(sim, socket_path, sizeof(socket_path)) == 0;
        }

        for (int i = 0; i < router_count && passed; i++) {
            passed = wait_for_router_listener(sim->routers[i]);
        }

        if (passed) {
            passed = wait_until(passive_neighbors_ready,
                                &(passive_wait_t){sim, router_count, neighbors_per_router}, WAIT_TIMEOUT_MS);
        }
    }

    test_result(passed, "Deferred passive runtime reconcile scales across many routers and neighbors");
    destroy_sim(sim);
    unlink(socket_path);
}

/*
 * The router has exactly one neighbor, and the runtime has set it up.
 */
static int single_neighbor_ready(void *opaque) {
    bgp_router_t *router = opaque;

    return router->neighbor_count == 1 && router->neighbors[0]->runtime_initialized;
}

static void test_runtime_neighbor_slot_reuse_under_churn(void) {
    bgp_sim_t *sim = create_sim();
    char       socket_path[108] = "";
    int        passed = 0;

    if (sim != NULL) {
        sim->passive_mode = 1;
        if (bgp_add_router(sim, 68000) == 1 &&
            start_runtime(sim, socket_path, sizeof(socket_path)) == 0 &&
            wait_for_router_listener(sim->routers[0])) {
            passed = 1;
            for (int i = 0; i < 30 && passed; i++) {
                char ip[32];

                snprintf(ip, sizeof(ip), "127.10.0.%d", i + 1);
                if (bgp_add_neighbor(sim, 68000, ip, (uint32_t)(69000 + i)) != 1) {
                    passed = 0;
                    break;
                }

                if (!wait_until(single_neighbor_ready, sim->routers[0], WAIT_TIMEOUT_MS)) {
                    passed = 0;
                    break;
                }

                if (bgp_remove_neighbor(sim, 68000, ip) != 1 ||
                    !wait_for_only_neighbor_freed(sim->routers[0]) ||
                    sim->routers[0]->neighbor_count != 0) {
                    passed = 0;
                    break;
                }
            }
        }
    }

    test_result(passed, "Runtime neighbor slots can be reused repeatedly under add/remove churn");
    destroy_sim(sim);
    unlink(socket_path);
}

/*
 * A connected loopback socket bound to a kernel-chosen port, as an outgoing connection holds its local port. Returns
 * the socket and its peer (both closed by the caller) and the port.
 */
static int hold_local_port(int *peer_out, int *listener_out, uint16_t *port_out) {
#ifndef __linux__
    /*
     * BSD SO_REUSEADDR lets the "::" listener bind beside a connected 127.0.0.1 socket: only a socket bound to the
     * same wildcard address takes the port there.
     */
    struct sockaddr_in6 any = {.sin6_family = AF_INET6};
    socklen_t           any_len = sizeof(any);
    int                 holder = socket(AF_INET6, SOCK_STREAM, 0);

    if (holder < 0 || bind(holder, (struct sockaddr *)&any, sizeof(any)) != 0 ||
        getsockname(holder, (struct sockaddr *)&any, &any_len) != 0) {
        close(holder);
        return -1;
    }
    *port_out = ntohs(any.sin6_port);
    *peer_out = *listener_out = -1;
    return holder;
#else
    struct sockaddr_in addr = {.sin_family = AF_INET};
    socklen_t          len = sizeof(addr);
    int                listener = socket(AF_INET, SOCK_STREAM, 0);
    int                holder = socket(AF_INET, SOCK_STREAM, 0);
    int                peer = -1;

    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (listener < 0 || holder < 0 || bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(listener, 1) != 0 || getsockname(listener, (struct sockaddr *)&addr, &len) != 0 ||
        bind(holder, (struct sockaddr *)&(struct sockaddr_in){.sin_family = AF_INET,
                                                                .sin_addr.s_addr = htonl(INADDR_LOOPBACK)},
             sizeof(addr)) != 0 ||
        connect(holder, (struct sockaddr *)&addr, sizeof(addr)) != 0 || (peer = accept(listener, NULL, NULL)) < 0) {
        close(listener);
        close(holder);
        return -1;
    }
    len = sizeof(addr);
    getsockname(holder, (struct sockaddr *)&addr, &len);
    *port_out = ntohs(addr.sin_port);
    *peer_out = peer;
    *listener_out = listener;
    return holder;
#endif
}

static int listener_failed(void *opaque) {
    return ((bgp_router_t *)opaque)->listener_error == UV_EADDRINUSE;
}

/*
 * A passive listener whose port is taken reports it and opens once the port is free: an outgoing connection can hold
 * any port of the ephemeral range, and a listener that gave up would leave the router deaf for good.
 */
static void test_passive_listener_retries_taken_port(void) {
    bgp_sim_t  *sim = create_sim();
    char        socket_path[108] = "";
    const char *saved = getenv("BGPSIM_LISTEN_BASE_PORT");
    char        saved_copy[16] = "";
    char        port_text[16];
    int         peer = -1, listener = -1, holder;
    uint16_t    port = 0;
    int         reported = 0, opened = 0, accepts = 0;

    snprintf(saved_copy, sizeof(saved_copy), "%s", saved ? saved : "");
    holder = hold_local_port(&peer, &listener, &port);
    if (sim != NULL && holder >= 0) {
        snprintf(port_text, sizeof(port_text), "%u", port);
        setenv("BGPSIM_LISTEN_BASE_PORT", port_text, 1);
        sim->passive_mode = 1;
        if (bgp_add_router(sim, 65300) == 1 && sim->routers[0]->listen_port == port &&
            start_runtime(sim, socket_path, sizeof(socket_path)) == 0) {
            reported = wait_until(listener_failed, sim->routers[0], WAIT_TIMEOUT_MS) && !sim->routers[0]->listener_open;
            // An abortive close frees the port at once (no TIME_WAIT).
            setsockopt(holder, SOL_SOCKET, SO_LINGER, &(struct linger){.l_onoff = 1, .l_linger = 0},
                       sizeof(struct linger));
            close(holder);
            holder = -1;
            opened = wait_for_router_listener(sim->routers[0]) && sim->routers[0]->listener_error == 0;
            if (opened) {
                int sock = socket(AF_INET, SOCK_STREAM, 0);
                struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(port),
                                           .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};

                accepts = sock >= 0 && connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0;
                if (sock >= 0) {
                    close(sock);
                }
            }
        }
    }
    if (saved_copy[0] != '\0') {
        setenv("BGPSIM_LISTEN_BASE_PORT", saved_copy, 1);
    } else {
        unsetenv("BGPSIM_LISTEN_BASE_PORT");
    }
    if (holder >= 0) {
        close(holder);
    }
    if (peer >= 0) {
        close(peer);
    }
    if (listener >= 0) {
        close(listener);
    }
    destroy_sim(sim);
    unlink(socket_path);
    test_result(reported, "A passive listener whose port is taken records the error and stays closed");
    test_result(opened && accepts, "The listener opens on its own once the port is free, and accepts connections");
}

int main(void) {
    printf("BGP Runtime Edge-Case Tests\n");
    printf("===========================\n");

    test_active_neighbor_retries_without_peer();
    test_remove_retrying_neighbor_under_runtime();
    test_repeated_retrying_neighbor_add_remove_cycles();
    test_remove_router_with_many_retrying_neighbors();
    test_passive_scale_after_deferred_config_load();
    test_runtime_neighbor_slot_reuse_under_churn();
    test_passive_listener_retries_taken_port();

    printf("\nPassed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
