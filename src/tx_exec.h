#ifndef TX_EXEC_H
#define TX_EXEC_H

#include <stddef.h>
#include <stdint.h>
#include "bgpsim.h"
#include "bgp_peer_tx.h"

/*
 * Admission of outbound UPDATE operations: one entry point for exec commands, standing advertisements, route refresh
 * and script steps. Runs on the runtime loop thread, which owns every peer's TX state.
 *
 * A request names a ribout and peers (an address or "all", and optionally the local router). Each resolved peer gets
 * a result: queued, withheld (its negotiated session cannot parse the snapshot; the reason is recorded for show),
 * skipped (session not established), or rejected (overlap, not bound, queue full, no memory). Plans are committed only
 * when no peer is rejected, so an operation reaches every peer it can or none.
 */

typedef enum {
    TX_PEER_QUEUED = 0,
    TX_PEER_WITHHELD,
    TX_PEER_SKIPPED,
    TX_PEER_REJECTED,
} tx_peer_status_t;

typedef struct {
    uint32_t         router_as;
    char             peer[INET6_ADDRSTRLEN];
    tx_peer_status_t status;
    char             reason[BGP_TX_REASON_SIZE];
    size_t           msgs;         /* Queued UPDATEs (QUEUED)                */
    uint64_t         bytes;
    uint64_t         snapshot_id;  /* Snapshot advertised, withheld or bound */
} tx_peer_result_t;

typedef struct {
    bgp_tx_op_t       op;         /* ADVERTISE, WITHDRAW, REPLAY or WITHDRAW_ALL           */
    const char       *ribout;     /* Not used by WITHDRAW_ALL                              */
    const char       *peer;       /* Canonical address or "all"                            */
    uint32_t          router_as;  /* 0: the one router that has the peer                   */
    bgp_tx_observer_t observer;   /* Script step (run_id 0: none); peer_index set per peer */
} tx_request_t;

/*
 * An upper bound for one request (which selects one router), including inactive slots.
 */
size_t tx_result_capacity(const bgp_sim_t *sim);

/*
 * Admit request. Returns 0 when the selectors resolved: results[0..*count) hold one entry per peer, and the
 * operation was queued unless some entry is REJECTED. Returns -1 with error when the request cannot be resolved (no
 * runtime, unknown or ambiguous router or peer, a ribout without a current snapshot).
 */
int tx_admit(bgp_sim_t *sim, const tx_request_t *request, tx_peer_result_t *results, size_t max_results,
             size_t *count, char *error, size_t error_len);

/*
 * Queue one prepared request for a single peer (standing advertisements, refresh, End-of-RIB). On a plan rejection
 * reason holds why and nothing is queued. Returns 0 when queued.
 */
int tx_admit_peer(bgp_neighbor_t *neighbor, const bgp_tx_request_t *request, char *reason);

const char *tx_peer_status_name(tx_peer_status_t status);

/*
 * Standing advertisements ("neighbor ... advertise <ribout>"): the neighbor keeps the current snapshot of each standing
 * ribout. A ribout that cannot be sent (not configured, no snapshot, changed since it, or incompatible with the
 * session) is withheld with the reason.
 */

/*
 * The session reached Established: queue the standing advertisements, then End-of-RIB for every negotiated family
 * (RFC 4724), so the markers follow the initial update.
 */
void tx_session_up(bgp_neighbor_t *neighbor);

/*
 * A standing ribout was added to a neighbor: advertise it now if the session is up (no End-of-RIB).
 */
void tx_standing_added(bgp_neighbor_t *neighbor, const char *name);

/*
 * update generate published a new snapshot of ribout name: advertise it to every established neighbor that has it
 * standing. A snapshot with the same bytes as the bound one is rebound without sending.
 */
void tx_standing_regenerated(bgp_sim_t *sim, const char *name);

/*
 * ROUTE-REFRESH (RFC 2918) for afi/safi: queue a replay of every snapshot bound to the peer in that family, then
 * End-of-RIB when both sides negotiated graceful restart. A non-zero subtype (RFC 7313) or a family that is not
 * negotiated is ignored.
 */
void tx_route_refresh(bgp_neighbor_t *neighbor, uint16_t afi, uint8_t subtype, uint8_t safi);

#endif /* TX_EXEC_H */
