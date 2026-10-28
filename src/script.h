#ifndef BGPSIM_SCRIPT_H
#define BGPSIM_SCRIPT_H

#include <stddef.h>
#include <stdint.h>
#include "bgp_ribout_config.h"

#define SCRIPT_NAME_SIZE   64
#define SCRIPT_PEER_SIZE   46
#define SCRIPT_MAX_SCRIPTS 64
#define SCRIPT_MAX_STEPS   256
#define SCRIPT_MAX_RUNS    128

typedef enum {
    SCRIPT_ADVERTISE,
    SCRIPT_WITHDRAW,
    SCRIPT_REPLAY,
    SCRIPT_SLEEP
} script_action_t;

typedef struct {
    script_action_t action;
    char            ribout[BGP_RIBOUT_NAME_SIZE];
    char            peer[SCRIPT_PEER_SIZE];  /* Canonical IP address or "all".                  */
    uint32_t        router_as;               /* Zero means resolve an unambiguous router later. */
    uint64_t        sleep_ms;
} script_step_t;

typedef struct {
    char           name[SCRIPT_NAME_SIZE];
    script_step_t *steps;
    size_t         step_count;
    uint64_t       revision;
} bgpsim_script_t;

typedef enum {
    RUN_PENDING,
    RUN_RUNNING,
    RUN_COMPLETE,
    RUN_FAILED,
    RUN_CANCELLED
} script_run_state_t;

typedef enum {
    RUN_PHASE_NONE,
    RUN_PHASE_PREPARE,
    RUN_PHASE_QUEUE,
    RUN_PHASE_TRANSMIT,
    RUN_PHASE_SLEEP,
    RUN_PHASE_COUNT
} script_run_phase_t;

typedef struct {
    uint64_t samples;
    uint64_t total_ms;
    uint64_t min_ms;
    uint64_t max_ms;
} script_timing_t;

typedef struct {
    script_timing_t phases[RUN_PHASE_COUNT];
} script_step_stats_t;

/*
 * What a step does for one resolved peer. Withheld and skipped peers send nothing and say why.
 */
typedef enum {
    SCRIPT_PEER_PLANNED = 0,  /* UPDATEs queued                               */
    SCRIPT_PEER_WITHHELD,     /* The peer's session cannot parse the snapshot */
    SCRIPT_PEER_SKIPPED,      /* The session is not established               */
} script_peer_status_t;

#define SCRIPT_REASON_SIZE 128

typedef struct {
    char     peer[SCRIPT_PEER_SIZE];      /* Canonical peer address                     */
    uint32_t router_as;                   /* Local router                               */
    uint64_t export_version;              /* Snapshot id; 0 only for a peer not planned */
    uint64_t messages_total;              /* UPDATEs the step sends to the peer         */
    uint64_t bytes_total;                 /* Their octets                               */
    uint8_t  status;                      /* script_peer_status_t                       */
    char     reason[SCRIPT_REASON_SIZE];  /* Why the peer was withheld or skipped       */
} script_peer_plan_t;

typedef struct {
    script_peer_plan_t plan;
    uint64_t           messages_done;
    uint64_t           bytes_done;
    uint64_t           started_ms;
    uint64_t           finished_ms;
    int                started;
    int                complete;
} script_peer_progress_t;

/*
 * A run owns a frozen script, current-step peer metrics and bounded per-step
 * aggregates. No timers, sockets, BGP state, or execution callbacks live here.
 */
typedef struct {
    uint32_t                id;
    bgpsim_script_t         script;
    script_run_state_t      state;
    uint32_t                repeat;  /* Zero means forever; the CLI defaults to one. */
    uint64_t                iteration;
    size_t                  step_index;
    script_run_phase_t      phase;
    uint64_t                created_ms;
    uint64_t                updated_ms;
    uint64_t                finished_ms;
    uint64_t                phase_started_ms;
    uint64_t                current_ms[RUN_PHASE_COUNT];
    script_step_stats_t    *stats;
    script_peer_progress_t *peers;
    size_t                  peer_count;
    char                    error[128];
} script_run_t;

/*
 * Zero initialization is sufficient. Slots are pointers so edits/removals do
 * not move objects; CLI sessions still retain names rather than pointers.
 */
typedef struct {
    bgpsim_script_t *scripts[SCRIPT_MAX_SCRIPTS];
    size_t           script_count;
    script_run_t    *runs[SCRIPT_MAX_RUNS];
    size_t           run_count;
    uint32_t         last_run_id;
} script_store_t;

enum {
    SCRIPT_OK        = 0,
    SCRIPT_INVALID   = -1,
    SCRIPT_NOT_FOUND = -2,
    SCRIPT_LIMIT     = -3,
    SCRIPT_STATE     = -4,
    SCRIPT_NOMEM     = -5
};

const char *script_error(int error);
const char *script_action_name(script_action_t action);
const char *script_run_state_name(script_run_state_t state);
const char *script_run_phase_name(script_run_phase_t phase);
int script_name_valid(const char *name);
int script_parse_duration(const char *text, uint64_t *ms);
int script_step_action(script_step_t *step, script_action_t action,
                       const char *ribout, const char *peer, uint32_t router_as);
int script_step_sleep(script_step_t *step, const char *duration);
void script_format_step(const script_step_t *step, char *buffer, size_t size);

bgpsim_script_t *script_find(const script_store_t *store, const char *name);
int script_create(script_store_t *store, const char *name, bgpsim_script_t **result);
int script_remove(script_store_t *store, const char *name);
int script_append(bgpsim_script_t *script, const script_step_t *step);
int script_remove_step(bgpsim_script_t *script, size_t index);
void script_store_destroy(script_store_t *store);

script_run_t *script_run_find(const script_store_t *store, uint32_t id);
int script_run_create(script_store_t *store, const char *name, uint32_t repeat, uint64_t now_ms, script_run_t **result);
int script_run_remove(script_store_t *store, uint32_t id);

/*
 * The clock of every run observation: monotonic milliseconds.
 */
uint64_t script_now_ms(void);

/*
 * Observations of a run, from the executor or a test. Times are monotonic milliseconds supplied by the caller,
 * allowing deterministic fake clocks.
 */
int script_run_start(script_run_t *run, uint64_t now_ms);
int script_run_set_peers(script_run_t *run, const script_peer_plan_t *peers, size_t count, uint64_t now_ms);
int script_run_set_phase(script_run_t *run, script_run_phase_t phase, uint64_t now_ms);
int script_run_peer_start(script_run_t *run, size_t peer_index, uint64_t now_ms);
int script_run_tx_progress(script_run_t *run, size_t peer_index, uint64_t messages, uint64_t bytes, uint64_t now_ms);
int script_run_finish_step(script_run_t *run, uint64_t now_ms);
int script_run_fail(script_run_t *run, const char *reason, uint64_t now_ms);
int script_run_cancel(script_run_t *run, uint64_t now_ms);
uint64_t script_run_phase_elapsed(const script_run_t *run, uint64_t now_ms);
uint64_t script_run_elapsed(const script_run_t *run, uint64_t now_ms);
uint64_t script_run_peer_elapsed(const script_run_t *run, size_t peer_index, uint64_t now_ms);

#endif
