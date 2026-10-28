#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bgp.h"
#include "util.h"
#include "bgp_tx.h"
#include "runtime.h"
#include "tx_exec.h"

const char *tx_peer_status_name(tx_peer_status_t status) {
    switch (status) {
        case TX_PEER_QUEUED:
            return "queued";
        case TX_PEER_WITHHELD:
            return "withheld";
        case TX_PEER_SKIPPED:
            return "skipped";
        case TX_PEER_REJECTED:
            return "rejected";
    }
    return "unknown";
}

static int active_router_count(const bgp_sim_t *sim, bgp_router_t **only) {
    int count = 0;

    for (int i = 0; i < sim->router_count; i++) {
        if (sim->routers[i]->active) {
            *only = sim->routers[i];
            count++;
        }
    }
    return count;
}

/*
 * The router of the request: the named one, the only one (peer "all"), or the one router with the peer.
 */
static bgp_router_t *resolve_router(bgp_sim_t *sim, const tx_request_t *request, char *error, size_t error_len) {
    bgp_router_t *router = NULL;
    int           matches = 0;

    if (request->router_as != 0) {
        router = bgp_find_router(sim, request->router_as);
        if (!router) {
            snprintf(error, error_len, "router bgp %u is not configured", request->router_as);
        }
        return router;
    }
    if (strcmp(request->peer, "all") == 0) {
        matches = active_router_count(sim, &router);
        if (matches == 1) {
            return router;
        }
        snprintf(error, error_len, matches == 0 ? "no router bgp is configured" :
                                                  "several routers are configured: name one with router <AS>");
        return NULL;
    }
    for (int i = 0; i < sim->router_count; i++) {
        if (sim->routers[i]->active && bgp_find_neighbor(sim->routers[i], request->peer)) {
            router = sim->routers[i];
            matches++;
        }
    }
    if (matches == 1) {
        return router;
    }
    snprintf(error, error_len, matches == 0 ? "neighbor %s is not configured" :
                                              "neighbor %s is on several routers: name one with router <AS>",
             request->peer);
    return NULL;
}

/*
 * The snapshot to advertise: the ribout must have one and its configuration must not have changed since.
 */
static bgp_ribout_snapshot_t *current_snapshot(bgp_sim_t *sim, const char *name, char *error, size_t error_len) {
    bgp_ribout_config_t *block = bgp_sim_find_ribout(sim, name);

    if (!block) {
        snprintf(error, error_len, "ribout %s is not configured", name);
        return NULL;
    }
    if (!block->snapshot) {
        snprintf(error, error_len, "ribout %s has no UPDATE snapshot (run update generate)", name);
        return NULL;
    }
    if (block->dirty) {
        snprintf(error, error_len, "ribout %s changed since its snapshot (run update generate)", name);
        return NULL;
    }
    return block->snapshot;
}

static int runtime_ready(bgp_sim_t *sim, char *error, size_t error_len) {
    if (!sim->runtime || !bgpsim_runtime_is_loop_thread(sim->runtime)) {
        snprintf(error, error_len, "sending UPDATEs needs the running runtime");
        return 0;
    }
    return 1;
}

size_t tx_result_capacity(const bgp_sim_t *sim) {
    size_t capacity = 1;
    for (int i = 0; i < sim->router_count; i++) {
        if (sim->routers[i]->active && (size_t)sim->routers[i]->neighbor_count > capacity)
            capacity = (size_t)sim->routers[i]->neighbor_count;
    }
    return capacity;
}

int tx_admit(bgp_sim_t *sim, const tx_request_t *request, tx_peer_result_t *results, size_t max_results,
             size_t *count, char *error, size_t error_len) {
    bgp_neighbor_t       **peers;
    bgp_tx_plan_t        **plans;
    bgp_ribout_snapshot_t *snapshot = NULL;
    bgp_router_t          *router;
    size_t                 peer_count = 0;
    int                    rejected = 0;

    *count = 0;
    error[0] = '\0';
    if (!runtime_ready(sim, error, error_len)) {
        return -1;
    }
    router = resolve_router(sim, request, error, error_len);
    if (!router) {
        return -1;
    }
    if (request->op == BGP_TX_OP_ADVERTISE &&
        !(snapshot = current_snapshot(sim, request->ribout, error, error_len))) {
        return -1;
    }

    int all = strcmp(request->peer, "all") == 0;
    peers = calloc(all && router->neighbor_count ? (size_t)router->neighbor_count : 1, sizeof(*peers));
    if (!peers) {
        snprintf(error, error_len, "no memory");
        return -1;
    }
    if (all) {
        for (int i = 0; i < router->neighbor_count; i++) {
            if (router->neighbors[i]->active) {
                peers[peer_count++] = router->neighbors[i];
            }
        }
    } else {
        bgp_neighbor_t *neighbor = bgp_find_neighbor(router, request->peer);

        if (!neighbor) {
            snprintf(error, error_len, "neighbor %s is not configured on router bgp %u", request->peer,
                     router->local_as);
            free(peers);
            return -1;
        }
        peers[peer_count++] = neighbor;
    }
    if (peer_count > max_results) {
        snprintf(error, error_len, "too many peers");
        free(peers);
        return -1;
    }

    plans = calloc(peer_count ? peer_count : 1, sizeof(*plans));
    if (!plans) {
        snprintf(error, error_len, "no memory");
        free(peers);
        return -1;
    }

    for (size_t i = 0; i < peer_count; i++) {
        bgp_neighbor_t   *neighbor = peers[i];
        tx_peer_result_t *result = &results[i];
        bgp_tx_request_t plan_request = {
            .op       = request->op,
            .name     = request->ribout,
            .snapshot = snapshot,
            .observer = request->observer,
        };

        memset(result, 0, sizeof(*result));
        result->router_as = router->local_as;
        snprintf(result->peer, sizeof(result->peer), "%s", neighbor->ip);
        plan_request.observer.peer_index = (uint32_t)i;

        if (neighbor->state != BGP_STATE_ESTABLISHED || !neighbor->tx) {
            result->status = TX_PEER_SKIPPED;
            snprintf(result->reason, sizeof(result->reason), "session not established");
            continue;
        }
        if (snapshot) {
            bgp_tx_compat_t compat = bgp_tx_check(&snapshot->profile, neighbor);

            result->snapshot_id = snapshot->id;
            if (compat != BGP_TX_COMPAT_OK) {
                result->status = TX_PEER_WITHHELD;
                bgp_tx_compat_reason(compat, &snapshot->profile, result->reason, sizeof(result->reason));
                bgp_peer_tx_set_withheld(neighbor->tx, request->ribout, snapshot->id, result->reason);
                continue;
            }
        } else if (request->ribout) {
            const bgp_tx_binding_t *binding = bgp_peer_tx_binding(neighbor->tx, request->ribout);

            result->snapshot_id = binding ? binding->snapshot->id : 0;
        }
        if (bgp_peer_tx_plan(neighbor->tx, &plan_request, &plans[i], result->reason) != BGP_TX_PLAN_OK) {
            result->status = TX_PEER_REJECTED;
            rejected = 1;
            continue;
        }
        result->status = TX_PEER_QUEUED;
        bgp_tx_plan_totals(plans[i], &result->msgs, &result->bytes);
    }

    for (size_t i = 0; i < peer_count; i++) {
        if (!plans[i]) {
            continue;
        }
        if (rejected) {
            bgp_tx_plan_free(plans[i]);
            results[i].status = TX_PEER_SKIPPED;
            snprintf(results[i].reason, sizeof(results[i].reason), "not sent: another peer rejected the operation");
            continue;
        }
        bgp_peer_tx_commit(peers[i]->tx, plans[i]);
        bgpsim_runtime_peer_kick(peers[i]);
    }
    free(plans);
    free(peers);
    *count = peer_count;
    return 0;
}

int tx_admit_peer(bgp_neighbor_t *neighbor, const bgp_tx_request_t *request, char *reason) {
    bgp_tx_plan_t *plan;

    if (!neighbor->tx) {
        snprintf(reason, BGP_TX_REASON_SIZE, "session not established");
        return -1;
    }
    if (bgp_peer_tx_plan(neighbor->tx, request, &plan, reason) != BGP_TX_PLAN_OK) {
        return -1;
    }
    bgp_peer_tx_commit(neighbor->tx, plan);
    bgpsim_runtime_peer_kick(neighbor);
    return 0;
}

// Standing advertisements

STATIC_ASSERT(BGP_NEIGHBOR_RIBOUT_NAME == BGP_RIBOUT_NAME_SIZE, "standing ribout names hold any ribout name");

static int standing_has(const bgp_neighbor_t *neighbor, const char *name) {
    for (int i = 0; i < neighbor->advertise_count; i++) {
        if (strcmp(neighbor->advertise[i], name) == 0) {
            return 1;
        }
    }
    return 0;
}

static int loop_owned(const bgp_neighbor_t *neighbor) {
    bgp_sim_t *sim = neighbor->router ? neighbor->router->sim : NULL;

    return sim && sim->runtime && bgpsim_runtime_is_loop_thread(sim->runtime) && neighbor->tx;
}

/*
 * Advertise the current snapshot of standing ribout name to an established neighbor, or record why not.
 */
static void standing_advertise(bgp_neighbor_t *neighbor, const char *name, int skip_identical) {
    bgp_ribout_config_t *block = bgp_sim_find_ribout(neighbor->router->sim, name);
    char                 reason[BGP_TX_REASON_SIZE];
    bgp_tx_compat_t      compat;
    bgp_tx_request_t     request = {.op = BGP_TX_OP_ADVERTISE, .name = name, .skip_identical = skip_identical};

    if (!block) {
        snprintf(reason, sizeof(reason), "ribout %s is not configured", name);
        bgp_peer_tx_set_withheld(neighbor->tx, name, 0, reason);
        return;
    }
    if (!block->snapshot) {
        snprintf(reason, sizeof(reason), "ribout %s has no UPDATE snapshot (run update generate)", name);
        bgp_peer_tx_set_withheld(neighbor->tx, name, 0, reason);
        return;
    }
    if (block->dirty) {
        snprintf(reason, sizeof(reason), "ribout %s changed since its snapshot (run update generate)", name);
        bgp_peer_tx_set_withheld(neighbor->tx, name, block->snapshot->id, reason);
        return;
    }
    compat = bgp_tx_check(&block->snapshot->profile, neighbor);
    if (compat != BGP_TX_COMPAT_OK) {
        bgp_tx_compat_reason(compat, &block->snapshot->profile, reason, sizeof(reason));
        bgp_peer_tx_set_withheld(neighbor->tx, name, block->snapshot->id, reason);
        return;
    }
    request.snapshot = block->snapshot;
    if (tx_admit_peer(neighbor, &request, reason) < 0) {
        bgp_peer_tx_set_withheld(neighbor->tx, name, block->snapshot->id, reason);
    }
}

void tx_session_up(bgp_neighbor_t *neighbor) {
    bgp_afi_safi_t   families[BGP_NUM_FAMILIES];
    bgp_tx_request_t eor = {.op = BGP_TX_OP_EOR, .eor_families = families};
    char             reason[BGP_TX_REASON_SIZE];

    if (!loop_owned(neighbor)) {
        return;
    }
    for (int i = 0; i < neighbor->advertise_count; i++) {
        standing_advertise(neighbor, neighbor->advertise[i], 0);
    }
    for (int i = 0; i < BGP_NUM_FAMILIES; i++) {
        if (bgp_tx_family_negotiated(neighbor, bgp_families[i].afi, bgp_families[i].safi)) {
            families[eor.eor_count].afi = bgp_families[i].afi;
            families[eor.eor_count].safi = bgp_families[i].safi;
            eor.eor_count++;
        }
    }
    if (eor.eor_count > 0 && tx_admit_peer(neighbor, &eor, reason) < 0) {
        fprintf(stderr, "Warning: End-of-RIB to %s not queued: %s\n", neighbor->ip, reason);
    }
}

void tx_standing_added(bgp_neighbor_t *neighbor, const char *name) {
    if (loop_owned(neighbor) && neighbor->state == BGP_STATE_ESTABLISHED) {
        standing_advertise(neighbor, name, 0);
    }
}

void tx_standing_regenerated(bgp_sim_t *sim, const char *name) {
    for (int r = 0; r < sim->router_count; r++) {
        bgp_router_t *router = sim->routers[r];

        for (int n = 0; router->active && n < router->neighbor_count; n++) {
            bgp_neighbor_t *neighbor = router->neighbors[n];

            if (neighbor->active && neighbor->state == BGP_STATE_ESTABLISHED && loop_owned(neighbor) &&
                standing_has(neighbor, name)) {
                standing_advertise(neighbor, name, 1);
            }
        }
    }
}

void tx_route_refresh(bgp_neighbor_t *neighbor, uint16_t afi, uint8_t subtype, uint8_t safi) {
    bgp_tx_request_t request = {.op = BGP_TX_OP_REFRESH, .family = {afi, safi}};
    char             reason[BGP_TX_REASON_SIZE];

    if (!loop_owned(neighbor) || subtype != 0 || !bgp_tx_family_negotiated(neighbor, afi, safi)) {
        return;
    }
    request.eor_after = neighbor->capabilities.graceful_restart && neighbor->peer_capabilities.graceful_restart;
    if (tx_admit_peer(neighbor, &request, reason) < 0) {
        fprintf(stderr, "Warning: route refresh from %s not answered: %s\n", neighbor->ip, reason);
    }
}
