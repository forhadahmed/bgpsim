/*
 * Link-time allocator faults exercise the real edit/generation implementation.
 * There are no allocator hooks or altered behavior in the production binary.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "bgpsim.h"
#include "bgp_ribout.h"
#include "bgp_peer_tx.h"
#include "test_result.h"
#include "bgp_ribout_snapshot.h"

#define CHECK(expr) do {                                                                                            \
    if (!(expr)) { fprintf(stderr, "%s:%d: %s (allocation %zu)\n", __FILE__, __LINE__, #expr, fault_at); exit(1); } \
} while (0)

void *__real_malloc(size_t size);
void *__real_calloc(size_t count, size_t size);
void *__real_realloc(void *ptr, size_t size);
static size_t fault_at, allocations;
static int armed, injected;

static int fail_allocation(void) {
    if (!armed) return 0;
    allocations++;
    if (allocations != fault_at) return 0;
    injected = 1;
    return 1;
}

void *__wrap_malloc(size_t size) { return fail_allocation() ? NULL : __real_malloc(size); }
void *__wrap_calloc(size_t count, size_t size) { return fail_allocation() ? NULL : __real_calloc(count, size); }
void *__wrap_realloc(void *ptr, size_t size) { return fail_allocation() ? NULL : __real_realloc(ptr, size); }

static void arm(size_t nth) { fault_at = nth; allocations = 0; injected = 0; armed = 1; }

typedef struct message_snapshot {
    struct message_snapshot *next;
    size_t                   length;
    uint8_t                  data[];
} message_snapshot_t;

static message_snapshot_t *snapshot_messages(const bgp_msg_t *msg) {
    message_snapshot_t *head = NULL, **tail = &head;
    for (; msg; msg = msg->next) {
        message_snapshot_t *copy = malloc(sizeof(*copy) + msg->length);
        CHECK(copy);
        copy->next = NULL;
        copy->length = msg->length;
        memcpy(copy->data, msg->data, msg->length);
        *tail = copy;
        tail = &copy->next;
    }
    return head;
}

static int snapshot_matches(const message_snapshot_t *copy, const bgp_msg_t *msg) {
    while (copy && msg) {
        if (copy->length != msg->length || memcmp(copy->data, msg->data, copy->length) != 0) return 0;
        copy = copy->next;
        msg = msg->next;
    }
    return copy == NULL && msg == NULL;
}

static void free_snapshot(message_snapshot_t *copy) {
    while (copy) {
        message_snapshot_t *next = copy->next;
        free(copy);
        copy = next;
    }
}

static void configure(bgp_ribout_config_t *block) {
    CHECK(bgp_ribout_init(block, "faults") == 0);
    CHECK(bgp_ribout_edit(block, "prefix", "10.0.0.0/24 x 100", 0) == 0);
    CHECK(bgp_ribout_edit(block, "next-hop", "192.0.2.1", 0) == 0);
    CHECK(bgp_ribout_edit(block, "as-path", "65551 65552", 0) == 0);
}

static void test_edit_rollback(void) {
    bgp_ribout_config_t *block = malloc(sizeof(*block));
    bgp_ribout_config_t *before = malloc(sizeof(*before));
    CHECK(block && before);
    configure(block);
    CHECK(bgp_ribout_edit(block, "rd", "65000:1 x 2560", 0) == 0);
    CHECK(bgp_ribout_edit(block, "color", "1 x 20480", 0) == 0);
    CHECK(bgp_ribout_edit(block, "community", "65000:1 x 100", 0) == 0);
    CHECK(bgp_ribout_edit(block, "large-community", "65000:1:1 x 100", 0) == 0);
    CHECK(bgp_ribout_edit(block, "rt-set", "[65000:1] x 100", 0) == 0);
    CHECK(bgp_ribout_edit(block, "segment-list", "1 weight 1 mpls 16000", 0) == 0);
    CHECK(bgp_ribout_edit(block, "protocol", "6", 0) == 0);
    CHECK(block->flowspec != NULL);
    const bgp_ribout_flowspec_t flow_before = *block->flowspec;
    bgp_ribout_config_t        *independent = bgp_ribout_config_clone(block);
    CHECK(independent);
#define CHECK_INDEPENDENT(type, field, count)                     \
    if (block->field) CHECK(independent->field != block->field && \
        !memcmp(independent->field, block->field, (size_t)block->field##_capacity * sizeof(type)));
    BGP_RIBOUT_OWNED_ARRAYS(CHECK_INDEPENDENT)
#undef CHECK_INDEPENDENT
    arm(SIZE_MAX);
    CHECK(bgp_ribout_edit(block, "protocol", "17", 0) == 0);
    armed = 0;
    size_t count = allocations;
    CHECK(count > 8 && count < 100);
    CHECK(bgp_ribout_edit(block, "protocol", "6", 0) == 0);
    block->dirty = 0;
    memcpy(before, block, sizeof(*before));
    for (size_t nth = 1; nth <= count; nth++) {
        arm(nth);
        int rc = bgp_ribout_edit(block, "protocol", "17", 0);
        armed = 0;
        CHECK(injected && rc < 0);
        CHECK(memcmp(block, before, offsetof(bgp_ribout_config_t, ribout)) == 0);
        CHECK(memcmp(block->flowspec, &flow_before, sizeof(flow_before)) == 0);
        CHECK(block->dirty == 0);
#define CHECK_INVENTORY_UNCHANGED(type, field, count_field)               \
        if (block->field) CHECK(!memcmp(independent->field, block->field, \
            (size_t)block->field##_capacity * sizeof(type)));
        BGP_RIBOUT_OWNED_ARRAYS(CHECK_INVENTORY_UNCHANGED)
#undef CHECK_INVENTORY_UNCHANGED
    }
    CHECK(bgp_ribout_edit(block, "protocol", "17", 0) == 0 && block->dirty == 1);
    CHECK(memcmp(block->flowspec, &flow_before, sizeof(flow_before)) != 0);
    bgp_ribout_destroy(block);
    bgp_ribout_config_clone_free(independent);
    free(before);
    free(block);
    test_result(1, "Every edit/deep-copy allocation failure preserves all inventory bytes and permits retry");
}

static void configure_generation(bgp_ribout_config_t *block, int srpolicy) {
    if (!srpolicy) {
        configure(block);
        return;
    }
    CHECK(bgp_ribout_init(block, "faults-sr") == 0);
    CHECK(bgp_ribout_edit(block, "address-family", "ipv4 srpolicy", 0) == 0);
    CHECK(bgp_ribout_edit(block, "distinguisher", "1", 0) == 0);
    CHECK(bgp_ribout_edit(block, "color", "100", 0) == 0);
    CHECK(bgp_ribout_edit(block, "endpoint", "192.0.2.1", 0) == 0);
    CHECK(bgp_ribout_edit(block, "next-hop", "192.0.2.2", 0) == 0);
    CHECK(bgp_ribout_edit(block, "rt", "192.0.2.3:100", 0) == 0);
    // Nine lists cross the encoder's eight-wrapper stack fast path without exceeding one UPDATE.
    for (int i = 1; i <= 9; i++) {
        char text[80];
        snprintf(text, sizeof(text), "%d weight 1 mpls %d", i, 16000 + i);
        CHECK(bgp_ribout_edit(block, "segment-list", text, 0) == 0);
    }
}

static void test_generation_rollback(int srpolicy) {
    bgp_ribout_config_t *block = malloc(sizeof(*block));
    CHECK(block);
    configure_generation(block, srpolicy);
    arm(SIZE_MAX);
    CHECK(bgp_ribout_generate(block) == BGP_RIBOUT_GENERATED);
    armed = 0;
    size_t count = allocations;
    CHECK(count > 0 && count < 1000);
    bgp_ribout_destroy(block);
    unsigned map_failures = 0, message_failures = 0;
    for (size_t nth = 1; nth <= count; nth++) {
        configure_generation(block, srpolicy);
        CHECK(bgp_ribout_generate(block) == BGP_RIBOUT_GENERATED);
        bgp_msg_t                   *previous = block->messages;
        size_t                       previous_count = block->message_count;
        const bgp_ribout_snapshot_t *previous_snapshot = block->snapshot;
        uint64_t                     previous_id = block->snapshot->id;
        message_snapshot_t          *snapshot = snapshot_messages(block->messages);
        CHECK(bgp_ribout_edit(block, "localpref", "200", 0) == 0);
        arm(nth);
        bgp_ribout_generation_result_t rc = bgp_ribout_generate(block);
        armed = 0;
        CHECK(injected);
        if (rc != BGP_RIBOUT_GENERATED) {
            map_failures += rc == BGP_RIBOUT_MAP_FAILED;
            message_failures += rc == BGP_RIBOUT_MESSAGES_FAILED;
            CHECK(block->dirty == 1 && block->generation_time_ms == 0);
            CHECK(block->messages == previous && block->message_count == previous_count);
            CHECK(block->snapshot == previous_snapshot && block->snapshot->id == previous_id);
            CHECK(snapshot_matches(snapshot, block->messages));
        }
        CHECK(bgp_ribout_generate(block) == BGP_RIBOUT_GENERATED);
        CHECK(block->messages && block->message_count > 0 && block->dirty == 0);
        CHECK(block->snapshot->id > previous_id && block->snapshot->adv->msgs == block->messages);
        CHECK(!snapshot_matches(snapshot, block->messages));
        free_snapshot(snapshot);
        bgp_ribout_destroy(block);
    }
    CHECK(map_failures > 0 && message_failures > 0);
    free(block);
    test_result(1, srpolicy ? "SR generation faults cover heap segment-list wrappers, rollback and retry" :
                "Every generation allocation is faulted; failed builds preserve exact wire snapshot and retry");
}

static void test_withdrawal_derivation_rollback(void) {
    bgp_ribout_config_t *block = malloc(sizeof(*block));
    CHECK(block);
    configure(block);
    CHECK(bgp_ribout_generate(block) == BGP_RIBOUT_GENERATED);
    arm(SIZE_MAX);
    bgp_msg_stream_t *stream = bgp_ribout_snapshot_withdrawal(block->snapshot);
    armed = 0;
    size_t count = allocations;
    CHECK(stream && count > 0 && count < 1000);
    size_t messages = stream->count;
    bgp_msg_stream_unref(stream);
    CHECK(block->snapshot->withdrawal == NULL);
    for (size_t nth = 1; nth <= count; nth++) {
        arm(nth);
        stream = bgp_ribout_snapshot_withdrawal(block->snapshot);
        armed = 0;
        CHECK(injected && stream == NULL && block->snapshot->withdrawal == NULL);
    }
    stream = bgp_ribout_snapshot_withdrawal(block->snapshot);
    CHECK(stream && stream->count == messages);
    bgp_msg_stream_unref(stream);
    bgp_ribout_destroy(block);
    free(block);
    test_result(1, "Every withdrawal-derivation allocation is faulted; no stream or cache is left and retry works");
}

/*
 * Fault both the individual object allocation and growth of its pointer registry.
 */
static void test_registry_rollback(void) {
    for (int kind = 0; kind < 3; kind++) {
        for (size_t nth = 1; nth <= 2; nth++) {
            bgp_sim_t sim;
            bgp_init_simulator(&sim);
            CHECK(bgp_add_router(&sim, 65000) == 1);
            bgp_router_t *first = bgp_find_router(&sim, 65000);
            for (int i = 1; i < 8; i++) CHECK(bgp_add_router(&sim, 65000 + i) == 1);
            for (int i = 0; i < 8; i++) {
                char ip[32], name[32];
                snprintf(ip, sizeof(ip), "192.0.2.%d", i + 1);
                snprintf(name, sizeof(name), "r%d", i);
                CHECK(bgp_add_neighbor(&sim, 65000, ip, 65100) == 1);
                CHECK(bgp_sim_add_ribout(&sim, name));
            }
            bgp_neighbor_t      *peer = bgp_find_neighbor(first, "192.0.2.1");
            bgp_ribout_config_t *block = bgp_sim_find_ribout(&sim, "r0");
            arm(nth);
            int rc = kind == 0 ? bgp_add_router(&sim, 65008) :
                     kind == 1 ? bgp_add_neighbor(&sim, 65000, "192.0.2.9", 65100) :
                                 (bgp_sim_add_ribout(&sim, "r8") ? 1 : -1);
            armed = 0;
            CHECK(injected && rc < 0);
            CHECK(sim.router_count == 8 && first->neighbor_count == 8 && sim.ribout_count == 8);
            CHECK(bgp_find_router(&sim, 65000) == first && bgp_find_neighbor(first, "192.0.2.1") == peer);
            CHECK(bgp_sim_find_ribout(&sim, "r0") == block);
            CHECK(!bgp_find_router(&sim, 65008) && !bgp_find_neighbor(first, "192.0.2.9") &&
                  !bgp_sim_find_ribout(&sim, "r8"));
            CHECK(bgp_add_router(&sim, 65008) == 1);
            CHECK(bgp_add_neighbor(&sim, 65000, "192.0.2.9", 65100) == 1);
            CHECK(bgp_sim_add_ribout(&sim, "r8"));
            bgp_shutdown_sim(&sim);
        }
    }
    test_result(1, "Object and table allocation failures preserve all three registries and permit retry");
}

static void test_tx_plan_rollback(void) {
    bgp_ribout_config_t block;
    configure(&block);
    CHECK(bgp_ribout_generate(&block) == BGP_RIBOUT_GENERATED);
    bgp_peer_tx_t *tx = bgp_peer_tx_create();
    CHECK(tx);
    char             reason[BGP_TX_REASON_SIZE];
    bgp_tx_plan_t   *plan;
    bgp_tx_request_t request = {.op = BGP_TX_OP_ADVERTISE, .name = "faults", .snapshot = block.snapshot};
    for (int i = 0; i < 8; i++) {
        CHECK(bgp_peer_tx_plan(tx, &request, &plan, reason) == BGP_TX_PLAN_OK);
        bgp_peer_tx_commit(tx, plan);
    }
    CHECK(tx->job_count == 8 && tx->job_capacity == 8);
    request.op = BGP_TX_OP_REPLAY;
    request.snapshot = NULL;
    bgp_peer_tx_t before = *tx;
    bgp_tx_job_t  jobs[8];
    memcpy(jobs, tx->jobs, sizeof(jobs));
    uint32_t refs = block.snapshot->refs;
    arm(SIZE_MAX);
    CHECK(bgp_peer_tx_plan(tx, &request, &plan, reason) == BGP_TX_PLAN_OK);
    armed = 0;
    size_t count = allocations;
    CHECK(count > 0 && count < 20);
    bgp_tx_plan_free(plan);
    for (size_t nth = 1; nth <= count; nth++) {
        arm(nth);
        bgp_tx_verdict_t verdict = bgp_peer_tx_plan(tx, &request, &plan, reason);
        armed = 0;
        CHECK(injected && verdict == BGP_TX_PLAN_REJECTED && plan == NULL);
        CHECK(!memcmp(tx, &before, sizeof(before)) && !memcmp(tx->jobs, jobs, sizeof(jobs)));
        CHECK(block.snapshot->refs == refs);
    }
    CHECK(bgp_peer_tx_plan(tx, &request, &plan, reason) == BGP_TX_PLAN_OK);
    bgp_peer_tx_commit(tx, plan);
    CHECK(tx->job_count == 9 && tx->job_capacity >= 9);
    bgp_peer_tx_destroy(tx);
    CHECK(block.snapshot->refs == 1);
    bgp_ribout_destroy(&block);
    test_result(1, "Every TX plan/growth allocation is faulted without changing queue, bindings or references");
}

int main(void) {
    test_tx_plan_rollback();
    test_registry_rollback();
    test_edit_rollback();
    test_generation_rollback(0);
    test_generation_rollback(1);
    test_withdrawal_derivation_rollback();
    return tests_failed ? 1 : 0;
}
