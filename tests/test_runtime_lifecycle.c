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

/*
 * The runtime has set the neighbor up (runtime_reconcile_neighbor() ran for it).
 */
static int neighbor_runtime_ready(void *opaque) {
    return ((bgp_neighbor_t *)opaque)->runtime_initialized;
}

static int wait_for_neighbor_runtime(bgp_neighbor_t *neighbor) {
    return wait_until(neighbor_runtime_ready, neighbor, WAIT_TIMEOUT_MS);
}

static int passive_neighbor_connected(void *opaque) {
    bgp_neighbor_t *neighbor = opaque;

    return neighbor->sock_fd >= 0 && neighbor->stream_open && neighbor->is_passive == 1;
}

static int wait_for_passive_neighbor_connection(bgp_neighbor_t *neighbor) {
    return wait_until(passive_neighbor_connected, neighbor, WAIT_TIMEOUT_MS);
}

static int connect_ipv6_loopback_with_retry(uint16_t port) {
    struct sockaddr_in6 local_addr;
    struct sockaddr_in6 remote_addr;
    int64_t             deadline = wait_now_ms() + WAIT_TIMEOUT_MS;
    useconds_t          delay = WAIT_FIRST_DELAY_US;

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "::1", &local_addr.sin6_addr);

    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin6_family = AF_INET6;
    remote_addr.sin6_port = htons(port);
    inet_pton(AF_INET6, "::1", &remote_addr.sin6_addr);

    do {
        int sock = socket(AF_INET6, SOCK_STREAM, 0);

        if (sock >= 0) {
            if (bind(sock, (struct sockaddr *)&local_addr, sizeof(local_addr)) == 0 &&
                connect(sock, (struct sockaddr *)&remote_addr, sizeof(remote_addr)) == 0) {
                return sock;
            }
            close(sock);
        }
    } while (wait_backoff(deadline, &delay));

    return -1;
}

static void test_basic_init_and_shutdown(void) {
    bgp_sim_t *sim = create_sim();

    test_result(sim != NULL && sim->router_count == 0, "basic init and shutdown");
    destroy_sim(sim);
}

static void test_router_thread_start_and_shutdown(void) {
    bgp_sim_t *sim = create_sim();
    char       socket_path[108] = "";
    int        passed = 0;

    if (sim != NULL) {
        sim->passive_mode = 1;
        passed = bgp_add_router(sim, 65000) == 1;
        passed = passed && start_runtime(sim, socket_path, sizeof(socket_path)) == 0;
        passed = passed && wait_for_router_listener(sim->routers[0]);
    }

    test_result(passed, "router runtime listener starts and shuts down");
    destroy_sim(sim);
    unlink(socket_path);
}

static void test_neighbor_thread_start_and_shutdown(void) {
    bgp_sim_t *sim = create_sim();
    char       socket_path[108] = "";
    int        passed = 0;

    if (sim != NULL) {
        sim->passive_mode = 1;
        passed = bgp_add_router(sim, 65000) == 1;
        passed = passed && bgp_add_neighbor(sim, 65000, "127.0.0.1", 65001) == 1;
        passed = passed && start_runtime(sim, socket_path, sizeof(socket_path)) == 0;
        passed = passed && wait_for_neighbor_runtime(sim->routers[0]->neighbors[0]);
        passed = passed && sim->routers[0]->neighbors[0]->state == BGP_STATE_IDLE;
    }

    test_result(passed, "neighbor runtime state initializes");
    destroy_sim(sim);
    unlink(socket_path);
}

static void test_deferred_startup_during_config_load(void) {
    bgp_sim_t *sim = create_sim();
    char       socket_path[108] = "";
    int        passed = 0;

    if (sim != NULL) {
        sim->passive_mode = 1;
        sim->config_loading = 1;

        passed = bgp_add_router(sim, 65000) == 1;
        passed = passed && bgp_add_neighbor(sim, 65000, "127.0.0.1", 65001) == 1;
        passed = passed && !sim->routers[0]->listener_initialized;
        passed = passed && !sim->routers[0]->neighbors[0]->runtime_initialized;

        sim->config_loading = 0;
        passed = passed && start_runtime(sim, socket_path, sizeof(socket_path)) == 0;
        passed = passed && wait_for_router_listener(sim->routers[0]);
        passed = passed && sim->routers[0]->neighbors[0]->runtime_initialized == 1;
    }

    test_result(passed, "config load can be reconciled into runtime after startup");
    destroy_sim(sim);
    unlink(socket_path);
}

static void test_passive_loopback_neighbor_does_not_retry_actively(void) {
    bgp_sim_t *sim = create_sim();
    char       socket_path[108] = "";
    int        passed = 0;

    if (sim != NULL) {
        sim->passive_mode = 1;
        passed = bgp_add_router(sim, 65000) == 1;
        passed = passed && bgp_add_neighbor(sim, 65000, "127.0.0.1", 65001) == 1;
        passed = passed && start_runtime(sim, socket_path, sizeof(socket_path)) == 0;
        // Once the runtime has set the neighbor up, a passive-only neighbor has no connection attempt scheduled.
        passed = passed && wait_for_neighbor_runtime(sim->routers[0]->neighbors[0]);
        passed = passed && !uv_is_active((uv_handle_t *)&sim->routers[0]->neighbors[0]->reconnect_timer);

        passed = passed && sim->routers[0]->neighbors[0]->retry_count == 0;
        passed = passed && sim->routers[0]->neighbors[0]->state == BGP_STATE_IDLE;
        passed = passed && sim->routers[0]->neighbors[0]->sock_fd == -1;
    }

    test_result(passed, "passive loopback neighbor stays idle without active retries");
    destroy_sim(sim);
    unlink(socket_path);
}

static void test_duplicate_neighbor_mismatched_as_is_rejected(void) {
    bgp_sim_t *sim = create_sim();
    int        passed = 0;

    if (sim != NULL) {
        sim->config_loading = 1;
        passed = bgp_add_router(sim, 65000) == 1;
        passed = passed && bgp_add_neighbor(sim, 65000, "10.0.0.1", 65001) == 1;
        passed = passed && bgp_add_neighbor(sim, 65000, "10.0.0.1", 65002) == -1;
    }

    test_result(passed, "duplicate neighbor with mismatched remote-as is rejected");
    destroy_sim(sim);
}

static void test_remove_running_neighbor(void) {
    bgp_sim_t *sim = create_sim();
    char       socket_path[108] = "";
    int        passed = 0;

    if (sim != NULL) {
        sim->passive_mode = 1;
        passed = bgp_add_router(sim, 65000) == 1;
        passed = passed && bgp_add_neighbor(sim, 65000, "127.0.0.1", 65001) == 1;
        passed = passed && start_runtime(sim, socket_path, sizeof(socket_path)) == 0;
        passed = passed && wait_for_neighbor_runtime(sim->routers[0]->neighbors[0]);

        passed = passed && bgp_remove_neighbor(sim, 65000, "127.0.0.1") == 1;
        passed = passed && wait_for_only_neighbor_freed(sim->routers[0]);
        passed = passed && sim->routers[0]->neighbor_count == 0;
    }

    test_result(passed, "running neighbor can be removed cleanly");
    destroy_sim(sim);
    unlink(socket_path);
}

static void test_remove_running_router(void) {
    bgp_sim_t *sim = create_sim();
    char       socket_path[108] = "";
    int        passed = 0;

    if (sim != NULL) {
        sim->passive_mode = 1;
        passed = bgp_add_router(sim, 65000) == 1;
        passed = passed && bgp_add_neighbor(sim, 65000, "127.0.0.1", 65001) == 1;
        passed = passed && start_runtime(sim, socket_path, sizeof(socket_path)) == 0;
        passed = passed && wait_for_neighbor_runtime(sim->routers[0]->neighbors[0]);

        passed = passed && bgp_remove_router(sim, 65000) == 1;
        passed = passed && wait_for_router_finalize(sim, sim->routers[0]);
    }

    test_result(passed, "running router can be removed cleanly");
    destroy_sim(sim);
    unlink(socket_path);
}

static void test_neighbor_slot_reuse(void) {
    bgp_sim_t *sim = create_sim();
    int        passed = 0;

    if (sim != NULL) {
        sim->config_loading = 1;
        passed = bgp_add_router(sim, 65000) == 1;
        passed = passed && bgp_add_neighbor(sim, 65000, "10.0.0.1", 65001) == 1;
        passed = passed && bgp_add_neighbor(sim, 65000, "10.0.0.2", 65002) == 1;
        passed = passed && bgp_remove_neighbor(sim, 65000, "10.0.0.1") == 1;
        passed = passed && sim->routers[0]->neighbor_count == 2;
        passed = passed && bgp_add_neighbor(sim, 65000, "10.0.0.3", 65003) == 1;
        passed = passed && sim->routers[0]->neighbor_count == 2;
        passed = passed && strcmp(sim->routers[0]->neighbors[0]->ip, "10.0.0.3") == 0;
    }

    test_result(passed, "neighbor slots are reused after removal");
    destroy_sim(sim);
}

static void test_router_slot_reuse(void) {
    bgp_sim_t *sim = create_sim();
    int        passed = 0;

    if (sim != NULL) {
        sim->config_loading = 1;
        passed = bgp_add_router(sim, 65000) == 1;
        passed = passed && bgp_add_router(sim, 65001) == 1;
        passed = passed && bgp_remove_router(sim, 65000) == 1;
        passed = passed && sim->router_count == 2;
        passed = passed && bgp_add_router(sim, 65002) == 1;
        passed = passed && sim->router_count == 2;
        passed = passed && sim->routers[0]->active == 1;
        passed = passed && sim->routers[0]->local_as == 65002;
    }

    test_result(passed, "router slots are reused after removal");
    destroy_sim(sim);
}

static void test_repeated_start_stop_cycles(void) {
    int passed = 1;

    for (int i = 0; i < 10; i++) {
        bgp_sim_t *sim = create_sim();
        char       socket_path[108] = "";

        if (sim == NULL) {
            passed = 0;
            break;
        }

        sim->passive_mode = 1;
        if (bgp_add_router(sim, (uint32_t)(65000 + i)) != 1 ||
            bgp_add_neighbor(sim, (uint32_t)(65000 + i), "127.0.0.1", (uint32_t)(65100 + i)) != 1 ||
            start_runtime(sim, socket_path, sizeof(socket_path)) != 0) {
            passed = 0;
        }

        // Shut down a runtime that is up: its listener is open.
        if (passed && !wait_for_router_listener(sim->routers[0])) {
            passed = 0;
        }
        destroy_sim(sim);
        unlink(socket_path);

        if (!passed) {
            break;
        }
    }

    test_result(passed, "repeated start/stop cycles stay stable");
}

static void test_add_ipv6_neighbor(void) {
    bgp_sim_t *sim = create_sim();
    int        passed = 0;

    if (sim != NULL) {
        passed = bgp_add_router(sim, 100) == 1;
        passed = passed && bgp_add_neighbor(sim, 100, "2001:db8::1", 200) == 1;
        passed = passed && sim->routers[0]->neighbor_count == 1;
        passed = passed && strcmp(sim->routers[0]->neighbors[0]->ip, "2001:db8::1") == 0;
        passed = passed && sim->routers[0]->neighbors[0]->af == AF_INET6;
        passed = passed && sim->routers[0]->neighbors[0]->remote_as == 200;
    }

    test_result(passed, "add IPv6 neighbor");
    destroy_sim(sim);
}

static void test_multiple_ipv6_neighbors(void) {
    bgp_sim_t *sim = create_sim();
    int        passed = 0;

    if (sim != NULL) {
        passed = bgp_add_router(sim, 100) == 1;
        passed = passed && bgp_add_neighbor(sim, 100, "2001:db8::1", 200) == 1;
        passed = passed && bgp_add_neighbor(sim, 100, "2001:db8::2", 200) == 1;
        passed = passed && bgp_add_neighbor(sim, 100, "fe80::1", 300) == 1;
        passed = passed && sim->routers[0]->neighbor_count == 3;
        passed = passed && sim->routers[0]->neighbors[0]->af == AF_INET6;
        passed = passed && sim->routers[0]->neighbors[1]->af == AF_INET6;
        passed = passed && sim->routers[0]->neighbors[2]->af == AF_INET6;
    }

    test_result(passed, "add multiple IPv6 neighbors");
    destroy_sim(sim);
}

static void test_mixed_ipv4_ipv6_neighbors(void) {
    bgp_sim_t *sim = create_sim();
    int        passed = 0;

    if (sim != NULL) {
        passed = bgp_add_router(sim, 100) == 1;
        passed = passed && bgp_add_neighbor(sim, 100, "192.168.1.1", 200) == 1;
        passed = passed && bgp_add_neighbor(sim, 100, "2001:db8::1", 200) == 1;
        passed = passed && bgp_add_neighbor(sim, 100, "10.0.0.1", 300) == 1;
        passed = passed && bgp_add_neighbor(sim, 100, "fe80::2", 300) == 1;
        passed = passed && sim->routers[0]->neighbor_count == 4;
        passed = passed && sim->routers[0]->neighbors[0]->af == AF_INET;
        passed = passed && sim->routers[0]->neighbors[1]->af == AF_INET6;
        passed = passed && sim->routers[0]->neighbors[2]->af == AF_INET;
        passed = passed && sim->routers[0]->neighbors[3]->af == AF_INET6;
    }

    test_result(passed, "mix IPv4 and IPv6 neighbors");
    destroy_sim(sim);
}

static void test_invalid_neighbor_ip_address(void) {
    bgp_sim_t *sim = create_sim();
    int        passed = 0;

    if (sim != NULL) {
        passed = bgp_add_router(sim, 100) == 1;
        passed = passed && bgp_add_neighbor(sim, 100, "not-an-ip", 200) == -1;
        passed = passed && sim->routers[0]->neighbor_count == 0;
    }

    test_result(passed, "reject invalid neighbor IP address");
    destroy_sim(sim);
}

static void test_ipv6_loopback_neighbor(void) {
    bgp_sim_t *sim = create_sim();
    int        passed = 0;

    if (sim != NULL) {
        passed = bgp_add_router(sim, 100) == 1;
        passed = passed && bgp_add_neighbor(sim, 100, "::1", 200) == 1;
        passed = passed && sim->routers[0]->neighbor_count == 1;
        passed = passed && sim->routers[0]->neighbors[0]->af == AF_INET6;
    }

    test_result(passed, "add IPv6 loopback neighbor");
    destroy_sim(sim);
}

static void test_compressed_ipv6_neighbors(void) {
    bgp_sim_t *sim = create_sim();
    int        passed = 0;

    if (sim != NULL) {
        passed = bgp_add_router(sim, 100) == 1;
        passed = passed && bgp_add_neighbor(sim, 100, "2001:db8::", 200) == 1;
        passed = passed && bgp_add_neighbor(sim, 100, "::1", 200) == 1;
        passed = passed && bgp_add_neighbor(sim, 100, "::", 200) == 1;
        passed = passed && sim->routers[0]->neighbor_count == 3;
        passed = passed && sim->routers[0]->neighbors[0]->af == AF_INET6;
        passed = passed && sim->routers[0]->neighbors[1]->af == AF_INET6;
        passed = passed && sim->routers[0]->neighbors[2]->af == AF_INET6;
    }

    test_result(passed, "handle compressed IPv6 addresses");
    destroy_sim(sim);
}

static void test_ipv6_passive_listener_accepts_connection(void) {
    bgp_sim_t *sim = create_sim();
    char       socket_path[108] = "";
    int        client_sock = -1;
    int        passed = 0;

    if (sim != NULL) {
        sim->passive_mode = 1;

        if (bgp_add_router(sim, 100) == 1 && bgp_add_neighbor(sim, 100, "::1", 200) == 1 &&
            start_runtime(sim, socket_path, sizeof(socket_path)) == 0) {
            passed = wait_for_router_listener(sim->routers[0]);
            if (passed) {
                client_sock = connect_ipv6_loopback_with_retry(sim->routers[0]->listen_port);
                if (client_sock >= 0) {
                    passed = wait_for_passive_neighbor_connection(sim->routers[0]->neighbors[0]);
                } else {
                    passed = 0;
                }
            }
        }
    }

    test_result(passed, "accept IPv6 passive connection");

    if (client_sock >= 0) {
        close(client_sock);
    }
    destroy_sim(sim);
    unlink(socket_path);
}

/*
 * Shut down while the runtime may be accepting a connection: its loop thread uses the simulator's runtime until the
 * thread has ended, so shutdown must not take it away first. The race window is short; 50 rounds hit it.
 */
static void test_shutdown_while_accepting(void) {
    int passed = 1;

    for (int i = 0; i < 50 && passed; i++) {
        bgp_sim_t *sim = create_sim();
        char       socket_path[108] = "";
        int        sock = -1;

        if (sim == NULL) {
            passed = 0;
            break;
        }
        sim->passive_mode = 1;
        if (bgp_add_router(sim, 65000) != 1 || bgp_add_neighbor(sim, 65000, "127.0.0.1", 65001) != 1 ||
            start_runtime(sim, socket_path, sizeof(socket_path)) != 0 || !wait_for_router_listener(sim->routers[0])) {
            passed = 0;
        } else {
            struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(sim->routers[0]->listen_port),
                                       .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};

            sock = socket(AF_INET, SOCK_STREAM, 0);
            passed = sock >= 0 && connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0;
        }
        destroy_sim(sim);  /* At once: the loop thread may be in the accept callback */
        if (sock >= 0) {
            close(sock);
        }
        unlink(socket_path);
    }
    test_result(passed, "shutdown while a connection is being accepted");
}

static void test_growth_preserves_model_addresses(void) {
    bgp_sim_t *sim = create_sim();
    int passed = sim && bgp_add_router(sim, 65000) == 1 &&
                 bgp_add_neighbor(sim, 65000, "2001:db8::1", 65100) == 1;
    bgp_router_t   *first = passed ? bgp_find_router(sim, 65000) : NULL;
    bgp_neighbor_t *peer = passed ? bgp_find_neighbor(first, "2001:db8::1") : NULL;
    for (int i = 1; i < 500 && passed; i++) passed = bgp_add_router(sim, (uint32_t)(65000 + i)) == 1;
    for (int i = 1; i < 1000 && passed; i++) {
        char ip[INET6_ADDRSTRLEN];
        snprintf(ip, sizeof(ip), "2001:db8::%x", i + 1);
        passed = bgp_add_neighbor(sim, 65000, ip, 65100) == 1;
    }
    passed = passed && sim->router_count == 500 && first->neighbor_count == 1000 &&
             bgp_find_router(sim, 65000) == first && bgp_find_neighbor(first, "2001:db8::1") == peer &&
             bgp_find_neighbor(first, "2001:db8::3e8") != NULL && peer->router == first;
    test_result(passed, "10x router/peer growth preserves existing object addresses and complete lookup");
    destroy_sim(sim);
}

static void test_listener_port_exhaustion(void) {
    const char *prior = getenv("BGPSIM_LISTEN_BASE_PORT");
    char       *saved = prior ? strdup(prior) : NULL;
    bgp_sim_t  *sim = create_sim();
    setenv("BGPSIM_LISTEN_BASE_PORT", "65535", 1);
    int           ok = sim && bgp_add_router(sim, 65000) == 1;
    bgp_router_t *first = ok ? bgp_find_router(sim, 65000) : NULL;
    ok = ok && first->listen_port == 65535 && bgp_add_router(sim, 65001) == -1 &&
         sim->router_count == 1 && bgp_find_router(sim, 65000) == first && !bgp_find_router(sim, 65001) &&
         bgp_remove_router(sim, 65000) == 1 && bgp_add_router(sim, 65002) == 1 &&
         bgp_find_router(sim, 65002)->listen_port == 65535;
    if (saved) setenv("BGPSIM_LISTEN_BASE_PORT", saved, 1);
    else unsetenv("BGPSIM_LISTEN_BASE_PORT");
    free(saved);
    destroy_sim(sim);
    test_result(ok, "Listener-port exhaustion rejects without wrap or mutation; released ports are reusable");
}

int main(void) {
    printf("BGP Runtime Lifecycle Tests\n");
    printf("===========================\n");

    test_basic_init_and_shutdown();
    test_growth_preserves_model_addresses();
    test_listener_port_exhaustion();
    test_router_thread_start_and_shutdown();
    test_neighbor_thread_start_and_shutdown();
    test_deferred_startup_during_config_load();
    test_passive_loopback_neighbor_does_not_retry_actively();
    test_duplicate_neighbor_mismatched_as_is_rejected();
    test_remove_running_neighbor();
    test_remove_running_router();
    test_neighbor_slot_reuse();
    test_router_slot_reuse();
    test_repeated_start_stop_cycles();
    test_shutdown_while_accepting();
    test_add_ipv6_neighbor();
    test_multiple_ipv6_neighbors();
    test_mixed_ipv4_ipv6_neighbors();
    test_invalid_neighbor_ip_address();
    test_ipv6_loopback_neighbor();
    test_compressed_ipv6_neighbors();
    test_ipv6_passive_listener_accepts_connection();

    printf("\nPassed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);

    return (tests_failed == 0) ? 0 : 1;
}
