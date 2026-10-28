// Independent 1x/10x workloads; each child has an isolated peak RSS measurement.
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include "log.h"
#include "bgpsim.h"
#include "test_wire.h"
#include "bgp_ribout.h"
#include "bgp_peer_tx.h"
#include "test_session.h"

#define REQUIRE(expr) do { if (!(expr)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); exit(1); } } while (0)

static long peak_rss_kib(void) {
    struct rusage usage;
    REQUIRE(getrusage(RUSAGE_SELF, &usage) == 0);
#ifdef __APPLE__
    return usage.ru_maxrss / 1024;
#else
    return usage.ru_maxrss;
#endif
}

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

static void measure_model(int routers, int peers) {
    bgp_sim_t sim;
    size_t    made = 0;
    int       router_count = 0;
    double    start = now_ms();
    bgp_init_simulator(&sim);
    sim.config_loading = 1;
    for (int r = 0; r < routers; r++) {
        if (bgp_add_router(&sim, (uint32_t)(65000 + r)) != 1) break;
        router_count++;
        for (int p = 0; p < peers; p++) {
            char ip[INET6_ADDRSTRLEN];
            snprintf(ip, sizeof(ip), "2001:db8::%x", p + 1);
            if (bgp_add_neighbor(&sim, (uint32_t)(65000 + r), ip, 65100) != 1) break;
            made++;
        }
    }
    double create_ms = now_ms() - start;
    start = now_ms();
    size_t found = 0;
    for (int r = 0; r < router_count; r++) {
        bgp_router_t *router = bgp_find_router(&sim, (uint32_t)(65000 + r));
        for (int p = 0; p < router->neighbor_count; p++) {
            char ip[INET6_ADDRSTRLEN];
            snprintf(ip, sizeof(ip), "2001:db8::%x", p + 1);
            found += bgp_find_neighbor(router, ip) != NULL;
        }
    }
    double lookup_ms = now_ms() - start;
    start = now_ms();
    bgp_shutdown_sim(&sim);
    double destroy_ms = now_ms() - start;
    printf("routers=%d/%d peers=%zu/%zu found=%zu create_ms=%.3f lookup_ms=%.3f destroy_ms=%.3f peak_rss_kib=%ld\n",
           router_count, routers, made, (size_t)routers * peers, found, create_ms, lookup_ms, destroy_ms,
           peak_rss_kib());
    REQUIRE(router_count == routers && made == (size_t)routers * peers && found == made);
}

static bgp_ribout_config_t *make_ribout(bgp_sim_t *sim, int index) {
    char name[32], prefix[64];
    snprintf(name, sizeof(name), "ribout%d", index);
    snprintf(prefix, sizeof(prefix), "10.%d.%d.0/24", index / 256, index % 256);
    bgp_ribout_config_t *block = bgp_sim_add_ribout(sim, name);
    REQUIRE(block && bgp_ribout_edit(block, "prefix", prefix, 0) == 0 &&
            bgp_ribout_edit(block, "next-hop", "192.0.2.1", 0) == 0 &&
            bgp_ribout_generate(block) == BGP_RIBOUT_GENERATED);
    return block;
}

static size_t drain(bgp_peer_tx_t *tx) {
    size_t messages = 0;
    while (bgp_peer_tx_fill_batch(tx, 1, BGP_TX_BATCH_BYTES)) {
        bgp_tx_batch_result_t result;
        bgp_peer_tx_batch_done(tx, 1, 1, &result);
        REQUIRE(!result.stale);
        messages += result.msgs;
    }
    REQUIRE(tx->job_count == 0);
    return messages;
}

static double plan_and_drain(bgp_peer_tx_t *tx, bgp_tx_op_t op, size_t count) {
    double           start = now_ms();
    bgp_tx_request_t request = {.op = op, .family = {1, 1}};
    bgp_tx_plan_t   *plan;
    char             reason[BGP_TX_REASON_SIZE];
    REQUIRE(bgp_peer_tx_plan(tx, &request, &plan, reason) == BGP_TX_PLAN_OK);
    bgp_peer_tx_commit(tx, plan);
    REQUIRE(tx->job_count == count && drain(tx) == count);
    return now_ms() - start;
}

static void measure_exports(int count) {
    bgp_sim_t sim;
    bgp_init_simulator(&sim);
    bgp_peer_tx_t *tx = bgp_peer_tx_create();
    REQUIRE(tx);
    double start = now_ms();
    for (int i = 0; i < count; i++) make_ribout(&sim, i);
    double generate_ms = now_ms() - start;
    start = now_ms();
    for (int i = 0; i < count; i++) {
        bgp_ribout_config_t *block = sim.ribouts[i];
        bgp_tx_request_t     request = {.op = BGP_TX_OP_ADVERTISE, .name = block->name, .snapshot = block->snapshot};
        bgp_tx_plan_t       *plan;
        char                 reason[BGP_TX_REASON_SIZE];
        REQUIRE(bgp_peer_tx_plan(tx, &request, &plan, reason) == BGP_TX_PLAN_OK);
        bgp_peer_tx_commit(tx, plan);
    }
    REQUIRE(tx->binding_count == (size_t)count && tx->job_count == (size_t)count && drain(tx) == (size_t)count);
    double advertise_ms = now_ms() - start;
    double refresh_ms = plan_and_drain(tx, BGP_TX_OP_REFRESH, (size_t)count);
    double withdraw_ms = plan_and_drain(tx, BGP_TX_OP_WITHDRAW_ALL, (size_t)count);
    REQUIRE(tx->binding_count == 0);
    bgp_peer_tx_destroy(tx);
    bgp_shutdown_sim(&sim);
    printf("ribouts_bindings_jobs=%d generate_ms=%.3f advertise_drain_ms=%.3f refresh_drain_ms=%.3f "
           "withdraw_drain_ms=%.3f peak_rss_kib=%ld\n", count, generate_ms, advertise_ms, refresh_ms,
           withdraw_ms, peak_rss_kib());
}

/*
 * Configuration/clone scale is separate from wire scale: a large segment-list
 * inventory can still exceed the negotiated UPDATE attribute-size limit.
 */
static void measure_attributes(int scale) {
    bgp_ribout_config_t vpn, policy;
    REQUIRE(bgp_ribout_init(&vpn, "vpn") == 0 && bgp_ribout_init(&policy, "policy") == 0);
    double start = now_ms();
    char   value[128];
    snprintf(value, sizeof(value), "10.0.0.0/24 x %d", 256 * scale);
    REQUIRE(bgp_ribout_edit(&vpn, "prefix", value, 0) == 0);
    REQUIRE(bgp_ribout_edit(&vpn, "next-hop", "192.0.2.1", 0) == 0);
    snprintf(value, sizeof(value), "rotate 65000:1 x %d", 256 * scale);
    REQUIRE(bgp_ribout_edit(&vpn, "rd", value, 0) == 0);
    snprintf(value, sizeof(value), "rotate 16000 x %d", 100 * scale);
    REQUIRE(bgp_ribout_edit(&vpn, "label", value, 0) == 0);
    snprintf(value, sizeof(value), "1 x %d", 2048 * scale);
    REQUIRE(bgp_ribout_edit(&vpn, "color", value, 0) == 0);
    snprintf(value, sizeof(value), "[65000:1] x %d", 256 * scale);
    REQUIRE(bgp_ribout_edit(&vpn, "rt-set", value, 0) == 0);
    REQUIRE(bgp_ribout_edit(&policy, "distinguisher", "1", 0) == 0 &&
            bgp_ribout_edit(&policy, "color", "1", 0) == 0 &&
            bgp_ribout_edit(&policy, "endpoint", "192.0.2.1", 0) == 0 &&
            bgp_ribout_edit(&policy, "rt", "192.0.2.3:1", 0) == 0);
    for (int i = 0; i < 64 * scale; i++) {
        snprintf(value, sizeof(value), "65000:%d", i);
        REQUIRE(bgp_ribout_edit(&vpn, "community", value, 0) == 0);
        snprintf(value, sizeof(value), "65000:1:%d", i);
        REQUIRE(bgp_ribout_edit(&vpn, "large-community", value, 0) == 0);
        snprintf(value, sizeof(value), "%d weight 1 mpls 16000", i + 1);
        REQUIRE(bgp_ribout_edit(&policy, "segment-list", value, 0) == 0);
    }
    double edit_ms = now_ms() - start;
    start = now_ms();
    bgp_ribout_config_t *copy = bgp_ribout_config_clone(&policy);
    double               clone_ms = now_ms() - start;
    REQUIRE(copy && copy->segment_lists != policy.segment_lists &&
            copy->segment_list_count == (uint32_t)(64 * scale) &&
            copy->segment_lists[64 * scale - 1].id == (uint32_t)(64 * scale));
    uint64_t bytes = bgp_ribout_config_bytes(&vpn) + bgp_ribout_config_bytes(&policy);
    start = now_ms();
    REQUIRE(bgp_ribout_generate(&vpn) == BGP_RIBOUT_GENERATED && vpn.snapshot->adv->count > 0 &&
            vpn.snapshot->config->rd_count == (uint32_t)(256 * scale) &&
            bgp_ribout_colors_at(vpn.snapshot->config, 2048 * scale - 1) == (uint32_t)(2048 * scale));
    double generate_ms = now_ms() - start;
    printf("attribute_scale=%d rd=%u labels=%u colors=%u rt_sets=%u community_groups=%u segment_lists=%u "
           "edit_ms=%.3f clone_ms=%.3f vpn_generate_ms=%.3f config_bytes=%llu empty_config_bytes=%zu "
           "peak_rss_kib=%ld\n", scale, vpn.rd_count, vpn.label_count, vpn.color_count, vpn.rt_set_count,
           vpn.community_group_count, policy.segment_list_count, edit_ms, clone_ms, generate_ms,
           (unsigned long long)bytes, sizeof(vpn), peak_rss_kib());
    bgp_ribout_config_clone_free(copy);
    bgp_ribout_destroy(&vpn);
    bgp_ribout_destroy(&policy);
}

static void control_command(bgpsim_control_client_t *client, const char *command) {
    cli_mode_t    mode = CLI_MODE_EXEC;
    cli_session_t session;
    cli_session_init(&session);
    int status = -1;
    REQUIRE(bgpsim_control_client_execute(client, command, &mode, &session, NULL, NULL, NULL, &status) == 0 && status >= 0);
}

static void read_route(int sock, int withdrawn) {
    uint8_t message[BGP_MAX_MESSAGE_SIZE], type = 0;
    int                len = recv_bgp_message_with_timeout(sock, message, sizeof(message), &type, SESSION_TIMEOUT_MS);
    test_wire_update_t view;
    static const uint8_t expected[] = {24, 10, 0, 0};
    REQUIRE(len > 0 && type == BGP_MSG_UPDATE && test_wire_update_view(message, (size_t)len, &view));
    REQUIRE(withdrawn ? view.withdrawn_len == sizeof(expected) && !memcmp(view.withdrawn, expected, sizeof(expected)) && !view.nlri_len :
                       view.nlri_len == sizeof(expected) && !memcmp(view.nlri, expected, sizeof(expected)) && !view.withdrawn_len);
    REQUIRE(peer_rx(sock)->len == 0);  /* No unread read-ahead when this fixture's receive slot is reused. */
}

static int all_tx_idle(void *opaque) {
    bgp_router_t *router = opaque;
    for (int i = 0; i < router->neighbor_count; i++) {
        bgp_neighbor_t *peer = router->neighbors[i];
        if (peer->state != BGP_STATE_ESTABLISHED || !peer->tx || peer->tx->job_count || peer->tx->batch.in_flight) return 0;
    }
    return 1;
}

static void measure_sessions(int count) {
    struct rlimit limit;
    REQUIRE(getrlimit(RLIMIT_NOFILE, &limit) == 0);
    rlim_t need = (rlim_t)count * 2 + 128;
    if (limit.rlim_cur < need) {
        limit.rlim_cur = need;
        REQUIRE(need <= limit.rlim_max && setrlimit(RLIMIT_NOFILE, &limit) == 0);
    }
    bgp_sim_t *sim = create_sim();
    REQUIRE(sim && bgp_add_router(sim, 65000) == 1);
    sim->config_loading = 1;
    for (int i = 0; i < count; i++) {
        char ip[32];
        snprintf(ip, sizeof(ip), "127.2.%d.%d", i / 256, i % 256);
        REQUIRE(bgp_add_neighbor(sim, 65000, ip, 65001) == 1);
    }
    bgp_router_t *router = bgp_find_router(sim, 65000);
    make_ribout(sim, 0);
    char path[108];
    int *sockets = malloc((size_t)count * sizeof(*sockets));
    REQUIRE(sockets);
    double start = now_ms();
    REQUIRE(session_start_runtime(sim, path, sizeof(path)) == 0);
    bgp_capabilities_t caps = {.ipv4_unicast = 1, .four_byte_asn = 1};
    for (int i = 0; i < count; i++) {
        sockets[i] = session_connect_neighbor(router->neighbors[i], &caps);
        REQUIRE(sockets[i] >= 0);
        uint8_t message[BGP_MAX_MESSAGE_SIZE], type;
        int len = recv_bgp_message_with_timeout(sockets[i], message, sizeof(message), &type, SESSION_TIMEOUT_MS);
        REQUIRE(type == BGP_MSG_UPDATE && len == 23 && !memcmp(message + 19, "\0\0\0\0", 4) && peer_rx(sockets[i])->len == 0);
    }
    double                  establish_ms = now_ms() - start;
    bgpsim_control_client_t client;
    REQUIRE(bgpsim_control_client_open(&client, path) == 0);
    start = now_ms();
    control_command(&client, "advertise ribout ribout0 peer all");
    for (int i = 0; i < count; i++) read_route(sockets[i], 0);
    REQUIRE(wait_until(all_tx_idle, router, SESSION_TIMEOUT_MS));
    double advertise_ms = now_ms() - start;
    start = now_ms();
    control_command(&client, "withdraw all peer all");
    for (int i = 0; i < count; i++) read_route(sockets[i], 1);
    REQUIRE(wait_until(all_tx_idle, router, SESSION_TIMEOUT_MS));
    double withdraw_ms = now_ms() - start;
    for (int i = 0; i < count; i++) {
        REQUIRE(router->neighbors[i]->tx->binding_count == 0);
        close(sockets[i]);
    }
    bgpsim_control_client_close(&client);
    destroy_sim(sim);
    unlink(path);
    free(sockets);
    printf("live_sessions=%d establish_ms=%.3f advertise_receive_ms=%.3f withdraw_receive_ms=%.3f peak_rss_kib=%ld\n",
           count, establish_ms, advertise_ms, withdraw_ms, peak_rss_kib());
}

typedef struct { int kind, first, second; } workload_t;

static int workload_count(const char *text, unsigned *value) {
    char *end;
    unsigned long parsed = strtoul(text, &end, 10);
    if (!*text || text[0] == '-' || *end || parsed > 1000000) return -1;
    *value = (unsigned)parsed;
    return 0;
}

int main(int argc, char **argv) {
    static const workload_t workloads[] = {
        {0, 50, 0}, {0, 500, 0}, {0, 1, 100}, {0, 1, 1000}, {0, 50, 100}, {0, 50, 1000},
        {1, 50}, {1, 500}, {1, 64}, {1, 640}, {2, 100}, {2, 1000}, {3, 1}, {3, 10}
    };
    workload_t        selected;
    const workload_t *runs = workloads;
    size_t            run_count = sizeof(workloads) / sizeof(*workloads);
    if (argc != 1) {
        unsigned first = 0, second = 0;
        if (argc < 3 || argc > 4 || workload_count(argv[2], &first) < 0 || !first ||
            (argc == 4 && workload_count(argv[3], &second) < 0)) {
            fprintf(stderr, "usage: %s [model routers peers | exports count | sessions count | attributes scale]\n", argv[0]);
            return 1;
        }
        if (!strcmp(argv[1], "model") && argc == 4) selected = (workload_t){0, (int)first, (int)second};
        else if (!strcmp(argv[1], "exports") && argc == 3) selected = (workload_t){1, (int)first, 0};
        else if (!strcmp(argv[1], "sessions") && argc == 3) selected = (workload_t){2, (int)first, 0};
        else if (!strcmp(argv[1], "attributes") && argc == 3 && first <= 100) selected = (workload_t){3, (int)first, 0};
        else return 1;
        runs = &selected;
        run_count = 1;
    }
    int failed = 0;
    for (size_t i = 0; i < run_count; i++) {
        fflush(NULL);
        pid_t child = fork();
        REQUIRE(child >= 0);
        if (!child) {
            log_init("/dev/null", 0);
            workload_t w = runs[i];
            if (w.kind == 0) measure_model(w.first, w.second);
            else if (w.kind == 1) measure_exports(w.first);
            else if (w.kind == 2) measure_sessions(w.first);
            else measure_attributes(w.first);
            log_close();
            exit(0);
        }
        int status;
        REQUIRE(waitpid(child, &status, 0) == child);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) failed = 1;
    }
    return failed;
}
