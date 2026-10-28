#ifndef BGP_PEER_TX_H
#define BGP_PEER_TX_H

#include <uv.h>
#include <stddef.h>
#include <stdint.h>
#include "bgp_ribout_snapshot.h"

/*
 * Outbound UPDATE state of one peer: what the peer should hold, what is queued to get it there, and the batch on the
 * wire. The runtime owns the socket and calls in from the loop thread; nothing here calls libuv.
 *
 * Operations are resolved when they are admitted, against the intended bindings: the ribout snapshots the peer holds
 * once the queue drains. A plan computes the jobs and the new binding without changing anything; commit applies a
 * plan and cannot fail, so admission to many peers is all or nothing.
 *
 *   advertise X, no binding or same keys   jobs: advertise(new)                binding X = new
 *   advertise X, route keys changed        jobs: withdraw(old), advertise(new) binding X = new
 *   withdraw X                             jobs: withdraw(bound)               binding X cleared
 *   withdraw all                           jobs: one withdraw per binding      bindings cleared
 *   replay X                               jobs: advertise(bound)              binding unchanged
 *   route refresh (AFI/SAFI)               jobs: replays of that family, EoR   bindings unchanged
 */

#define BGP_TX_DEFAULT_JOBS           1024
#define BGP_TX_DEFAULT_BINDINGS       1024
#define BGP_TX_DEFAULT_RETAINED_BYTES UINT64_C(1073741824)
#define BGP_TX_BATCH_BUFS             256    /* Messages in one write                     */
#define BGP_TX_BATCH_BYTES            65536  /* Bytes in one write (at least one message) */
#define BGP_TX_REASON_SIZE            128
#define BGP_TX_MAX_EOR                32

typedef enum {
    BGP_TX_JOB_ADVERTISE = 0,
    BGP_TX_JOB_WITHDRAW,
    BGP_TX_JOB_EOR,
} bgp_tx_job_kind_t;

/*
 * Who waits for a job: a script run step. run_id 0: nobody. base_* is the progress of earlier jobs of the same
 * admission, so that a withdraw-then-advertise reports one running total.
 */
typedef struct {
    uint32_t run_id;
    uint32_t peer_index;
    uint64_t step_token;
    size_t   base_msgs;
    uint64_t base_bytes;
} bgp_tx_observer_t;

typedef struct {
    uint8_t                kind;                        /* bgp_tx_job_kind_t                */
    uint8_t                replay;                      /* Resend of the bound snapshot     */
    char                   name[BGP_RIBOUT_NAME_SIZE];  /* Ribout; empty for End-of-RIB     */
    bgp_ribout_snapshot_t *snapshot;                    /* Snapshot advertised or withdrawn */
    bgp_msg_stream_t      *stream;                      /* Bytes to send                    */
    const bgp_msg_t       *cursor;                      /* First message not yet sent       */
    size_t                 sent_msgs;                   /* Messages completed               */
    uint64_t               sent_bytes;                  /* Bytes completed                  */
    uint64_t               id;                          /* Increasing per peer              */
    bgp_afi_safi_t         family;                      /* End-of-RIB: the family it marks  */
    bgp_tx_observer_t      observer;                    /* Script step waiting for it       */
} bgp_tx_job_t;

typedef struct {
    char                   name[BGP_RIBOUT_NAME_SIZE];  /* Ribout                               */
    bgp_ribout_snapshot_t *snapshot;                    /* Snapshot the peer holds once drained */
} bgp_tx_binding_t;

typedef struct {
    char     name[BGP_RIBOUT_NAME_SIZE];  /* Ribout                       */
    char     reason[BGP_TX_REASON_SIZE];  /* Why it was not sent          */
    uint64_t snapshot_id;                 /* Snapshot withheld, 0 if none */
} bgp_tx_withheld_t;

/*
 * The write in flight: its buffers point into stream, which it pins until the write callback.
 */
typedef struct {
    uv_write_t        req;
    uv_buf_t          bufs[BGP_TX_BATCH_BUFS];
    unsigned          nbufs;
    size_t            msgs;
    uint64_t          bytes;
    uint64_t          epoch;  /* Session the batch was written on */
    uint64_t          job_id;
    bgp_msg_stream_t *stream;
    int               in_flight;
} bgp_tx_batch_t;

typedef struct {
    size_t   jobs;
    size_t   bindings;
    uint64_t retained_bytes;
} bgp_tx_limits_t;

typedef struct bgp_peer_tx {
    bgp_tx_limits_t    limits;
    bgp_tx_binding_t  *bindings;
    size_t             binding_count;
    int                binding_capacity;
    bgp_tx_withheld_t *withheld;
    size_t             withheld_count;
    int                withheld_capacity;
    bgp_tx_job_t      *jobs;                      /* Growable ring; batch buffers remain pinned independently */
    int                job_capacity;
    size_t             job_head;
    size_t             job_count;
    uint64_t           next_job_id;
    bgp_afi_safi_t     eor_sent[BGP_TX_MAX_EOR];  /* End-of-RIB markers written                               */
    size_t             eor_sent_count;
    bgp_tx_batch_t     batch;
} bgp_peer_tx_t;

typedef enum {
    BGP_TX_OP_ADVERTISE = 0,
    BGP_TX_OP_WITHDRAW,
    BGP_TX_OP_REPLAY,
    BGP_TX_OP_WITHDRAW_ALL,
    BGP_TX_OP_REFRESH,
    BGP_TX_OP_EOR,
} bgp_tx_op_t;

typedef struct {
    bgp_tx_op_t            op;
    const char            *name;            /* Ribout (advertise, withdraw, replay)           */
    bgp_ribout_snapshot_t *snapshot;        /* Advertise: the ribout's current snapshot       */
    bgp_afi_safi_t         family;          /* Refresh: the requested family                  */
    int                    eor_after;       /* Refresh: queue End-of-RIB after the replays    */
    int                    skip_identical;  /* Advertise: rebind, not resend, identical bytes */
    const bgp_afi_safi_t  *eor_families;    /* End-of-RIB: the families, in order             */
    size_t                 eor_count;
    bgp_tx_observer_t      observer;        /* Script step to report to (run_id 0: none)      */
} bgp_tx_request_t;

typedef enum {
    BGP_TX_PLAN_OK = 0,    /* Jobs to queue (possibly none: withdraw all with nothing bound)  */
    BGP_TX_PLAN_REJECTED,  /* reason says why: not bound, overlap, queue full, no memory, ... */
} bgp_tx_verdict_t;

typedef struct bgp_tx_plan bgp_tx_plan_t;

bgp_peer_tx_t *bgp_peer_tx_create(void);
bgp_peer_tx_t *bgp_peer_tx_create_with_limits(const bgp_tx_limits_t *limits);
/*
 * Free the state and drop every reference. The batch must not be in flight (its callback has run).
 */
void bgp_peer_tx_destroy(bgp_peer_tx_t *tx);

/*
 * Plan request against tx. On OK *plan holds the jobs (free it with bgp_tx_plan_free() or pass it to commit); on
 * REJECTED reason (BGP_TX_REASON_SIZE octets) says why and *plan is NULL.
 */
bgp_tx_verdict_t bgp_peer_tx_plan(const bgp_peer_tx_t *tx, const bgp_tx_request_t *request, bgp_tx_plan_t **plan,
                                  char *reason);
/*
 * Messages and bytes the plan queues.
 */
void bgp_tx_plan_totals(const bgp_tx_plan_t *plan, size_t *msgs, uint64_t *bytes);
/*
 * Apply a plan made against tx (no other change to tx in between) and free it. Cannot fail.
 */
void bgp_peer_tx_commit(bgp_peer_tx_t *tx, bgp_tx_plan_t *plan);
void bgp_tx_plan_free(bgp_tx_plan_t *plan);

/*
 * Withheld records for show: set replaces the record of name, clear removes it.
 */
void bgp_peer_tx_set_withheld(bgp_peer_tx_t *tx, const char *name, uint64_t snapshot_id, const char *reason);
void bgp_peer_tx_clear_withheld(bgp_peer_tx_t *tx, const char *name);

/*
 * The job at the head of the queue, or NULL.
 */
const bgp_tx_job_t *bgp_peer_tx_head(const bgp_peer_tx_t *tx);
const bgp_tx_job_t *bgp_peer_tx_job(const bgp_peer_tx_t *tx, size_t index);
/*
 * The job that has binding name pending, or NULL: the last queued job for that ribout.
 */
const bgp_tx_job_t *bgp_peer_tx_pending(const bgp_peer_tx_t *tx, const char *name);

/*
 * Fill the batch from the head job: whole messages, at most BGP_TX_BATCH_BUFS and max_bytes (at least one). Returns
 * the messages in the batch, 0 when the queue is empty or a batch is in flight. The caller writes it with
 * batch.req, batch.bufs and batch.nbufs.
 */
size_t bgp_peer_tx_fill_batch(bgp_peer_tx_t *tx, uint64_t epoch, size_t max_bytes);

/*
 * What a completed write did.
 */
typedef struct {
    size_t            msgs;          /* Messages of the batch                          */
    uint64_t          bytes;
    int               stale;         /* Written on an older session: nothing advanced  */
    int               job_started;   /* The batch was the first one of its job         */
    int               job_complete;  /* The job has now sent all its messages          */
    uint8_t           job_kind;
    bgp_tx_observer_t observer;
    size_t            job_msgs;      /* The job's messages and bytes done (cumulative) */
    uint64_t          job_bytes;
} bgp_tx_batch_result_t;

/*
 * The batch's write finished (ok: written; else failed or cancelled). Releases the batch and, for a successful write
 * on session epoch, advances the head job and pops it when complete.
 */
void bgp_peer_tx_batch_done(bgp_peer_tx_t *tx, uint64_t epoch, int ok, bgp_tx_batch_result_t *result);

/*
 * The session ended: drop every queued job (reporting each observed one to abort), the bindings, the withheld
 * records and the End-of-RIB record. A batch in flight stays pinned until its callback.
 */
typedef void (*bgp_tx_abort_cb)(void *ctx, const bgp_tx_observer_t *observer);
void bgp_peer_tx_reset(bgp_peer_tx_t *tx, bgp_tx_abort_cb abort_cb, void *ctx);

/*
 * UPDATE messages queued and not yet written.
 */
uint64_t bgp_peer_tx_outq(const bgp_peer_tx_t *tx);

/*
 * The binding of name, or NULL.
 */
const bgp_tx_binding_t *bgp_peer_tx_binding(const bgp_peer_tx_t *tx, const char *name);

#endif /* BGP_PEER_TX_H */
