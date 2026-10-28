/*
 * Outbound UPDATEs on a real session: a raw loopback peer with chosen capabilities, commands through the control
 * socket (they run on the runtime loop thread), and the bytes the peer receives decoded with test_wire.h.
 */
#include <stdint.h>
#include <inttypes.h>
#include "test_case.h"
#include "test_wire.h"
#include "bgp_ribout.h"
#include "bgp_peer_tx.h"
#include "test_session.h"
#include "test_nlri_templates.h"

#define TX_TIMEOUT_MS 10000

typedef struct {
    bgp_sim_t              *sim;
    char                    socket_path[108];
    int                     peer;
    int                     client_open;
    bgpsim_control_client_t client;
    cli_mode_t              mode;
    cli_session_t           session;
    char                    out[262144];
    size_t                  out_len;
    uint64_t                seen;  /* tx_update of the UPDATEs the peer has read (tx_update counts every session) */
} tx_env_t;

static void collect_output(void *opaque, output_stream_t stream, const char *data, size_t len) {
    tx_env_t *env = opaque;

    (void)stream;
    if (env->out_len + len >= sizeof(env->out)) {
        len = sizeof(env->out) - env->out_len - 1;
    }
    memcpy(env->out + env->out_len, data, len);
    env->out_len += len;
    env->out[env->out_len] = '\0';
}

/*
 * Run one command; env->out holds its stdout and stderr. Returns the command status (negative on failure).
 */
static int cmd(tx_env_t *env, const char *command) {
    int status = -1;

    env->out_len = 0;
    env->out[0] = '\0';
    if (bgpsim_control_client_execute(&env->client, command, &env->mode, &env->session, collect_output, NULL, env,
                                      &status) != 0) {
        return -100;
    }
    return status;
}

static int cmds(tx_env_t *env, const char *const *commands) {
    for (; *commands; commands++) {
        if (cmd(env, *commands) < 0) {
            fprintf(stderr, "command failed: %s: %s\n", *commands, env->out);
            return -1;
        }
    }
    return 0;
}

/*
 * Router 65000 with neighbor 127.0.0.1 (AS 65001); local_caps adjusts the neighbor and setup runs CLI commands
 * in-process before the runtime starts. The raw peer opens with peer_caps.
 */
static int env_start_setup(tx_env_t *env, bgp_capabilities_t *peer_caps, void (*local_caps)(bgp_capabilities_t *caps),
                           const char *const *setup) {
    memset(env, 0, sizeof(*env));
    env->peer = -1;
    env->mode = CLI_MODE_EXEC;
    cli_session_init(&env->session);
    env->sim = create_sim();
    if (!env->sim || bgp_add_router(env->sim, 65000) != 1 ||
        bgp_add_neighbor(env->sim, 65000, "127.0.0.1", 65001) != 1) {
        return -1;
    }
    if (local_caps) {
        local_caps(&env->sim->routers[0]->neighbors[0]->capabilities);
    }
    for (; setup && *setup; setup++) {
        if (cli_process_command(&env->session, env->sim, &env->mode, *setup) < 0) {
            fprintf(stderr, "setup failed: %s\n", *setup);
            return -1;
        }
    }
    env->mode = CLI_MODE_EXEC;
    cli_session_init(&env->session);
    env->seen = 0;
    env->peer = session_establish(env->sim, env->socket_path, sizeof(env->socket_path), peer_caps);
    if (env->peer < 0 || bgpsim_control_client_open(&env->client, env->socket_path) != 0) {
        return -1;
    }
    env->client_open = 1;
    return 0;
}

static int env_start(tx_env_t *env, bgp_capabilities_t *peer_caps, void (*local_caps)(bgp_capabilities_t *caps)) {
    return env_start_setup(env, peer_caps, local_caps, NULL);
}

static void env_stop(tx_env_t *env) {
    if (env->peer >= 0) {
        close(env->peer);
    }
    if (env->client_open) {
        bgpsim_control_client_close(&env->client);
    }
    destroy_sim(env->sim);
    unlink(env->socket_path);
}

static bgp_neighbor_t *peer_neighbor(tx_env_t *env) {
    return env->sim->routers[0]->neighbors[0];
}

static bgp_capabilities_t ipv4_peer(void) {
    bgp_capabilities_t caps;

    memset(&caps, 0, sizeof(caps));
    caps.ipv4_unicast = 1;
    caps.four_byte_asn = 1;
    return caps;
}

// The peer side

typedef struct {
    uint8_t  (*msgs)[BGP_MAX_MESSAGE_SIZE];
    uint16_t *lens;
    size_t    count;
    size_t    cap;
} rx_list_t;

static void rx_free(rx_list_t *rx) {
    free(rx->msgs);
    free(rx->lens);
    memset(rx, 0, sizeof(*rx));
}

/*
 * Read UPDATEs until rx holds want, skipping KEEPALIVEs; each one read counts in env->seen. Returns rx->count.
 */
static size_t read_updates(tx_env_t *env, size_t want, rx_list_t *rx) {
    while (rx->count < want) {
        uint8_t msg[BGP_MAX_MESSAGE_SIZE];
        uint8_t type = 0;
        int     len = recv_bgp_message_with_timeout(env->peer, msg, sizeof(msg), &type, TX_TIMEOUT_MS);

        if (len <= 0 || type == BGP_MSG_NOTIFICATION) {
            break;
        }
        if (type != BGP_MSG_UPDATE) {
            continue;
        }
        if (rx->count == rx->cap) {
            rx->cap = rx->cap ? rx->cap * 2 : 256;
            rx->msgs = realloc(rx->msgs, rx->cap * sizeof(*rx->msgs));
            rx->lens = realloc(rx->lens, rx->cap * sizeof(*rx->lens));
        }
        memcpy(rx->msgs[rx->count], msg, (size_t)len);
        rx->lens[rx->count++] = (uint16_t)len;
        env->seen++;
    }
    return rx->count;
}

/*
 * bgpsim has written all it queued for the peer: no UPDATE job is left and no batch is in flight. Commands run on the
 * runtime loop, so once one returns, what it queued is already in the queue.
 */
static int tx_idle(void *opaque) {
    const bgp_peer_tx_t *tx = peer_neighbor(opaque)->tx;

    return !tx || (tx->job_count == 0 && !tx->batch.in_flight);
}

/*
 * bgpsim has a write batch in flight and more UPDATEs queued behind it: the peer is not reading.
 */
static int tx_backed_up(void *opaque) {
    tx_env_t            *env = opaque;
    const bgp_peer_tx_t *tx = peer_neighbor(env)->tx;

    return tx && tx->job_count > 0 && tx->batch.in_flight && tx->batch.stream &&
           bgp_peer_tx_outq(tx) > tx->batch.msgs;
}

/*
 * Read every UPDATE bgpsim has written so far: wait until its queue is idle, then read until the peer has read as many
 * as tx_update counts. Returns the number added to rx.
 */
static size_t read_written(tx_env_t *env, rx_list_t *rx) {
    size_t before = rx->count;

    if (wait_until(tx_idle, env, TX_TIMEOUT_MS) && peer_neighbor(env)->tx_update >= env->seen) {
        read_updates(env, rx->count + (size_t)(peer_neighbor(env)->tx_update - env->seen), rx);
    }
    return rx->count - before;
}

/*
 * bgpsim sent nothing the peer has not read: its queue is idle, tx_update matches what the peer read, and no UPDATE
 * is waiting in the socket.
 */
static int nothing_sent(tx_env_t *env) {
    return wait_until(tx_idle, env, TX_TIMEOUT_MS) && peer_neighbor(env)->tx_update == env->seen &&
           !peer_has_message(env->peer, BGP_MSG_UPDATE);
}

/*
 * End-of-RIB (RFC 4724): an UPDATE with nothing in it, or only an empty MP_UNREACH_NLRI.
 */
static int is_eor(const uint8_t *msg, size_t len, uint16_t *afi, uint8_t *safi) {
    test_wire_update_t view;

    if (!test_wire_update_view(msg, len, &view) || view.withdrawn_len != 0 || view.nlri_len != 0) {
        return 0;
    }
    if (view.attr_count == 0) {
        *afi = 1;
        *safi = 1;
        return len == BGP_HEADER_SIZE + 4;
    }
    *afi = view.unreach_afi;
    *safi = view.unreach_safi;
    return view.attr_count == 1 && view.has_unreach && view.unreach_len == 0;
}

/*
 * The End-of-RIB markers of a new session are written.
 */
static int eor_written(void *opaque) {
    const bgp_peer_tx_t *tx = peer_neighbor(opaque)->tx;

    return tx && tx->eor_sent_count > 0 && tx_idle(opaque);
}

/*
 * Read what bgpsim wrote when the session came up: wait until its End-of-RIB markers are written, then read them.
 * Returns how many End-of-RIB markers came.
 */
static int skip_eor(tx_env_t *env) {
    rx_list_t rx = {0};
    int       eors = 0;

    if (wait_until(eor_written, env, TX_TIMEOUT_MS)) {
        read_written(env, &rx);
    }
    for (size_t i = 0; i < rx.count; i++) {
        uint16_t afi;
        uint8_t  safi;

        eors += is_eor(rx.msgs[i], rx.lens[i], &afi, &safi);
    }
    rx_free(&rx);
    return eors;
}

static int same_bytes(const rx_list_t *rx, size_t first, const bgp_msg_t *msgs) {
    size_t i = first;

    for (const bgp_msg_t *msg = msgs; msg; msg = msg->next, i++) {
        if (i >= rx->count || rx->lens[i] != msg->length || memcmp(rx->msgs[i], msg->data, msg->length) != 0) {
            return 0;
        }
    }
    return 1;
}

/*
 * IPv4 unicast prefixes: advertised (classic NLRI) or withdrawn (Withdrawn Routes); 4 octets per /24 key here.
 */
static size_t count_prefixes(const rx_list_t *rx, size_t first, size_t last, int withdrawn) {
    size_t total = 0;

    for (size_t i = first; i < last; i++) {
        test_wire_update_t view;
        const uint8_t     *region;
        size_t             len;

        if (!test_wire_update_view(rx->msgs[i], rx->lens[i], &view)) {
            return 0;
        }
        region = withdrawn ? view.withdrawn : view.nlri;
        len = withdrawn ? view.withdrawn_len : view.nlri_len;
        if ((withdrawn && (view.attr_count != 0 || view.nlri_len != 0)) || (!withdrawn && view.withdrawn_len != 0)) {
            return 0;
        }
        for (size_t off = 0; off < len;) {
            size_t size = test_wire_nlri_size(1, 1, 0, region + off, len - off);

            if (size == 0) {
                return 0;
            }
            total++;
            off += size;
        }
    }
    return total;
}

/*
 * Independent fixture oracle: each /24 from 10.0.0.0 appears exactly once, with the configured cycling
 * LOCAL_PREF. Counts alone would accept duplicate keys, stale attributes, or an entirely different route set.
 */
static int blue_routes(const rx_list_t *rx, size_t first, size_t last, size_t count, int withdrawn,
                       uint32_t lp_min, uint32_t lp_max) {
    uint8_t seen[2000] = {0};
    size_t  total = 0;

    if (count > sizeof(seen) || first >= last || last > rx->count) {
        return 0;
    }
    for (size_t i = first; i < last; i++) {
        test_wire_update_t view;
        const uint8_t     *lp = NULL, *p;
        uint16_t           lp_len = 0;
        size_t             len;

        if (!test_wire_update_view(rx->msgs[i], rx->lens[i], &view) || view.has_reach || view.has_unreach ||
            (withdrawn && (view.attr_count != 0 || view.nlri_len != 0)) ||
            (!withdrawn && (view.withdrawn_len != 0 ||
                           !test_wire_find_attr(rx->msgs[i], rx->lens[i], 5, &lp, &lp_len, NULL) || lp_len != 4))) {
            return 0;
        }
        p = withdrawn ? view.withdrawn : view.nlri;
        len = withdrawn ? view.withdrawn_len : view.nlri_len;
        if (len == 0 || len % 4 != 0) {
            return 0;
        }
        for (size_t off = 0; off < len; off += 4) {
            size_t key = (size_t)p[off + 2] * 256 + p[off + 3];

            if (p[off] != 24 || p[off + 1] != 10 || key >= count || seen[key]++ ||
                (!withdrawn && read_u32(lp) != lp_min + key % (lp_max - lp_min + 1))) {
                return 0;
            }
            total++;
        }
    }
    return total == count;
}

typedef struct {
    bgp_neighbor_t *neighbor;
    uint64_t        updates;
} tx_wait_t;

static int sent_updates(void *opaque) {
    tx_wait_t *wait = opaque;

    return wait->neighbor->tx_update >= wait->updates;
}

static int session_down(void *opaque) {
    return ((neighbor_wait_t *)opaque)->neighbor->state != BGP_STATE_ESTABLISHED;
}

static const char *const k_blue[] = {
    "config", "ribout blue", "prefix 10.0.0.0/24 x 2000", "next-hop 192.0.2.1", "localpref range(1,400)", "end",
    "update generate", NULL};

// Cases

static void test_advertise_and_withdraw(void) {
    tx_env_t               env;
    bgp_capabilities_t     caps = ipv4_peer();
    rx_list_t              rx = {0};
    bgp_ribout_snapshot_t *snapshot;
    int ok_start, advertise_rc, withdraw_rc = -1, eors = 0;
    size_t adv_count = 0, adv_prefixes = 0, withdrawn = 0;
    int    bytes_match = 0, counted = 0, shown = 0;

    TEST("advertise sends the snapshot bytes; withdraw removes the same prefixes");
    ok_start = env_start(&env, &caps, NULL) == 0 && (eors = skip_eor(&env)) > 0 && cmds(&env, k_blue) == 0;
    if (ok_start) {
        snapshot = env.sim->ribouts[0]->snapshot;
        adv_count = snapshot->adv->count;
        advertise_rc = cmd(&env, "advertise ribout blue peer 127.0.0.1");
        if (advertise_rc >= 0 && strstr(env.out, "queued to 127.0.0.1 (router 65000)") &&
            read_updates(&env, adv_count, &rx) == adv_count) {
            bytes_match = same_bytes(&rx, 0, snapshot->adv->msgs);
            adv_prefixes = count_prefixes(&rx, 0, rx.count, 0);
            counted = wait_until(sent_updates, &(tx_wait_t){peer_neighbor(&env), adv_count + eors}, TX_TIMEOUT_MS) &&
                      peer_neighbor(&env)->tx_update == adv_count + (uint64_t)eors;
            cmd(&env, "show bgp neighbors");
            shown = strstr(env.out, "blue: snapshot") && strstr(env.out, "(ipv4-unicast), advertised");
            withdraw_rc = cmd(&env, "withdraw ribout blue peer 127.0.0.1");
            read_written(&env, &rx);
            withdrawn = count_prefixes(&rx, adv_count, rx.count, 1);
        }
    }
    env_stop(&env);
    rx_free(&rx);
    ASSERT(ok_start, "session up and ribout generated");
    ASSERT(bytes_match, "the peer received exactly the snapshot UPDATEs in order");
    ASSERT(adv_prefixes == 2000, "2000 prefixes advertised");
    ASSERT(counted, "tx_update counts every UPDATE written, End-of-RIB included");
    ASSERT(shown, "show bgp neighbors lists the advertised ribout");
    ASSERT(withdraw_rc >= 0 && withdrawn == 2000, "the withdrawal removes all 2000 prefixes");
    PASS();
}

static void test_regenerate_same_and_changed_keys(void) {
    static const char *const attr_change[] = {"config", "ribout blue", "localpref range(500,900)", "end",
                                              "update generate", NULL};
    static const char *const key_edit[] = {"config", "ribout blue", "prefix 10.0.0.0/24 x 1000", "end", NULL};
    tx_env_t           env;
    bgp_capabilities_t caps = ipv4_peer();
    rx_list_t          rx = {0};
    size_t             first = 0, second = 0, split;
    int                ok = 0, replace_only = 0, stale_refused = 0, changed_keys = 0;

    TEST("A regeneration with the same keys replaces in place; changed keys withdraw first");
    if (env_start(&env, &caps, NULL) == 0 && skip_eor(&env) > 0 && cmds(&env, k_blue) == 0 &&
        cmd(&env, "advertise ribout blue peer 127.0.0.1") >= 0) {
        first = read_updates(&env, env.sim->ribouts[0]->snapshot->adv->count, &rx);
        ok = first == env.sim->ribouts[0]->snapshot->adv->count && blue_routes(&rx, 0, first, 2000, 0, 1, 400);

        if (cmds(&env, attr_change) == 0 && cmd(&env, "advertise ribout blue peer 127.0.0.1") >= 0) {
            second = read_updates(&env, first + env.sim->ribouts[0]->snapshot->adv->count, &rx);
            replace_only = blue_routes(&rx, first, second, 2000, 0, 500, 900) && nothing_sent(&env);
        }

        if (cmds(&env, key_edit) == 0) {
            stale_refused = cmd(&env, "advertise ribout blue peer 127.0.0.1") < 0 && strstr(env.out, "update generate") &&
                            nothing_sent(&env);
        }
        if (cmd(&env, "update generate") >= 0 && cmd(&env, "advertise ribout blue peer 127.0.0.1") >= 0) {
            read_written(&env, &rx);
            for (split = second; split < rx.count; split++) {
                test_wire_update_t view;

                if (!test_wire_update_view(rx.msgs[split], rx.lens[split], &view) || view.withdrawn_len == 0) {
                    break;
                }
            }
            changed_keys = blue_routes(&rx, second, split, 2000, 1, 0, 0) &&
                           blue_routes(&rx, split, rx.count, 1000, 0, 500, 900);
        }
    }
    env_stop(&env);
    rx_free(&rx);
    ASSERT(ok, "first advertisement: exact /24 keys and LOCAL_PREF cycle 1..400");
    ASSERT(replace_only, "same keys: no withdrawals; exact 2000 keys with new LOCAL_PREF cycle 500..900");
    ASSERT(stale_refused, "an edited ribout must be regenerated before it is advertised");
    ASSERT(changed_keys, "changed keys: exact 2000 old keys withdrawn before exact 1000 new keys and attributes");
    PASS();
}

static void enable_ipv4_addpath(bgp_capabilities_t *caps);

/*
 * Add-Path IPv4 /24 routes of UPDATEs [first, last), advertised or withdrawn: keys[n] = Path ID << 32 | prefix number
 * (10.0.0.0/24 is 0), and for an advertisement the low half of its first community in comms[n] (-1 for none).
 * Returns the count, or -1 when an UPDATE is of another kind (an advertisement with withdrawals or the reverse).
 */
static long addpath_routes(const rx_list_t *rx, size_t first, size_t last, int withdrawn, uint64_t *keys,
                           int32_t *comms, size_t max) {
    size_t n = 0;

    for (size_t i = first; i < last; i++) {
        test_wire_update_t view;
        const uint8_t *p, *comm = NULL;
        uint16_t comm_len = 0;
        size_t   len;

        if (!test_wire_update_view(rx->msgs[i], rx->lens[i], &view) ||
            (withdrawn ? view.nlri_len != 0 : view.withdrawn_len != 0)) {
            return -1;
        }
        p = withdrawn ? view.withdrawn : view.nlri;
        len = withdrawn ? view.withdrawn_len : view.nlri_len;
        if (!withdrawn) {
            test_wire_find_attr(rx->msgs[i], rx->lens[i], BGP_ATTR_COMMUNITIES, &comm, &comm_len, NULL);
        }
        for (size_t off = 0; off + 8 <= len && n < max; off += 8) {  /* Path ID, length 24, 3 octets */
            if (p[off + 4] != 24) {
                return -1;
            }
            keys[n] = (uint64_t)read_u32(p + off) << 32 | (uint32_t)((p[off + 6] - 0) << 8 | p[off + 7]);
            comms[n] = comm ? (int32_t)read_u16(comm + 2) : -1;
            n++;
        }
    }
    return (long)n;
}

/*
 * Config changes on a live session, each followed by update generate and advertise: a community change keeps the
 * keys, so the routes are replaced in place; turning path-id rotate into a plain path-id list changes the keys, so
 * the old ones are withdrawn first; reverting everything withdraws those and sends the first advertisement again,
 * byte for byte.
 */
static void test_regenerate_communities_and_rotation(void) {
    static const char *const base[] = {"config", "ribout tags", "prefix 10.0.0.0/24 x 300", "path-id rotate 1 x 3",
                                       "next-hop 192.0.2.1", "community 65000:1 x 3", "end", "update generate", NULL};
    static const char *const communities[] = {"config", "ribout tags", "no community",
                                              "community [65000:7,no-export]", "end", "update generate", NULL};
    static const char *const plain_ids[] = {"config", "ribout tags", "path-id 1 x 3", "end", "update generate",
                                            NULL};
    static const char *const revert[] = {"config", "ribout tags", "path-id rotate 1 x 3", "no community",
                                         "community 65000:1 x 3", "end", "update generate", NULL};
    static uint64_t keys[1000];
    static int32_t comms[1000];
    tx_env_t           env;
    bgp_capabilities_t caps = ipv4_peer();
    rx_list_t          rx = {0};
    size_t             first = 0, mark = 0, split;
    long               n;
    int                base_ok = 0, replaced = 0, rekeyed = 0, reverted = 0, identical = 0;

    TEST("Config changes on a live session: communities replace in place, rotate to plain re-keys, revert restores");
    caps.add_path_ipv4 = ADD_PATH_RECEIVE;
    if (env_start(&env, &caps, enable_ipv4_addpath) == 0 && skip_eor(&env) > 0 && cmds(&env, base) == 0 &&
        cmd(&env, "advertise ribout tags peer 127.0.0.1") >= 0) {
        first = read_updates(&env, env.sim->ribouts[0]->snapshot->adv->count, &rx);
        n = addpath_routes(&rx, 0, first, 0, keys, comms, 1000);
        base_ok = n == 300;
        for (long i = 0; base_ok && i < n; i++) {
            uint32_t prefix = (uint32_t)keys[i], id = (uint32_t)(keys[i] >> 32);

            base_ok = prefix < 300 && id == 1 + prefix % 3 && comms[i] == (int32_t)(1 + prefix % 3);
        }

        if (cmds(&env, communities) == 0 && cmd(&env, "advertise ribout tags peer 127.0.0.1") >= 0) {
            mark = read_updates(&env, first + env.sim->ribouts[0]->snapshot->adv->count, &rx);
            n = addpath_routes(&rx, first, mark, 0, keys, comms, 1000);
            replaced = n == 300 && nothing_sent(&env);
            for (long i = 0; replaced && i < n; i++) {
                uint32_t prefix = (uint32_t)keys[i];

                replaced = (uint32_t)(keys[i] >> 32) == 1 + prefix % 3 && comms[i] == 7;
            }
        }

        if (cmds(&env, plain_ids) == 0 && cmd(&env, "advertise ribout tags peer 127.0.0.1") >= 0) {
            size_t start = rx.count;

            read_written(&env, &rx);
            for (split = start; split < rx.count; split++) {
                test_wire_update_t view;

                if (!test_wire_update_view(rx.msgs[split], rx.lens[split], &view) || view.withdrawn_len == 0) {
                    break;
                }
            }
            rekeyed = addpath_routes(&rx, start, split, 1, keys, comms, 1000) == 300 &&
                      addpath_routes(&rx, split, rx.count, 0, keys, comms, 1000) == 900;
            for (size_t i = 0; rekeyed && i < 900; i++) {
                rekeyed = (uint32_t)(keys[i] >> 32) >= 1 && (uint32_t)(keys[i] >> 32) <= 3 && comms[i] == 7;
            }
        }

        if (cmds(&env, revert) == 0 && cmd(&env, "advertise ribout tags peer 127.0.0.1") >= 0) {
            size_t start = rx.count;

            read_written(&env, &rx);
            for (split = start; split < rx.count; split++) {
                test_wire_update_t view;

                if (!test_wire_update_view(rx.msgs[split], rx.lens[split], &view) || view.withdrawn_len == 0) {
                    break;
                }
            }
            reverted = addpath_routes(&rx, start, split, 1, keys, comms, 1000) == 900 && rx.count - split == first;
            identical = reverted;
            for (size_t i = 0; identical && i < first; i++) {
                identical = rx.lens[split + i] == rx.lens[i] && memcmp(rx.msgs[split + i], rx.msgs[i], rx.lens[i]) == 0;
            }
        }
    }
    env_stop(&env);
    rx_free(&rx);
    ASSERT(base_ok, "first advertisement: prefix i once, Path ID 1 + i % 3 and community 65000:(1 + i % 3)");
    ASSERT(replaced, "community change: the same 300 keys again with 65000:7, no withdrawals, nothing more");
    ASSERT(rekeyed, "path-id rotate to plain: the 300 old keys withdrawn before 900 new ones");
    ASSERT(reverted, "revert: the 900 keys withdrawn, then as many UPDATEs as the first advertisement");
    ASSERT(identical, "revert: the first advertisement again, byte for byte");
    PASS();
}

static void enable_flowspec6(bgp_capabilities_t *caps) {
    caps->ipv6_flowspec = 1;
}

static void test_flowspec_offset_overlap(const char *component) {
    char a[80], b[80];
    const char *const setup[] = {
        "config", "ribout a", "address-family ipv6 flowspec", a, "dst-port 80", "exit",
        "ribout b", "address-family ipv6 flowspec", b, "dst-port 80", "end", "update generate", NULL};
    // RFC 8956: bits before offset 32 are absent. Both configurations must have this same wire key.
    const uint8_t expected[] = {10, !strcmp(component, "prefix") ? 1 : 2, 64, 32, 0, 1, 0, 0, 5, 0x81, 80};
    tx_env_t           env;
    bgp_capabilities_t caps = ipv4_peer();
    rx_list_t          rx = {0};
    test_wire_update_t view;
    int                started = 0, wire_key = 0, rejected = 0, quiet = 0, preserved = 0, withdrawn = 0;

    TEST(!strcmp(component, "prefix") ? "IPv6 FlowSpec destination offset collision is rejected on a real session" :
                                      "IPv6 FlowSpec source offset collision is rejected on a real session");
    snprintf(a, sizeof(a), "%s 2001:db8:1::/32-64", component);
    snprintf(b, sizeof(b), "%s 3001:db8:1::/32-64", component);
    caps.ipv6_flowspec = 1;
    if (env_start(&env, &caps, enable_flowspec6) == 0 && skip_eor(&env) > 0 && cmds(&env, setup) == 0 &&
        cmd(&env, "advertise ribout a peer 127.0.0.1") >= 0 && read_updates(&env, 1, &rx) == 1) {
        started = 1;
        wire_key = test_wire_update_view(rx.msgs[0], rx.lens[0], &view) && view.has_reach &&
                   view.reach_afi == 2 && view.reach_safi == 133 && view.reach_len == sizeof(expected) &&
                   memcmp(view.reach, expected, sizeof(expected)) == 0;
        rejected = cmd(&env, "advertise ribout b peer 127.0.0.1") < 0 &&
                   strstr(env.out, "rejected by 127.0.0.1: route keys overlap ribout a");
        quiet = nothing_sent(&env);
        preserved = cmd(&env, "show bgp neighbors") >= 0 && strstr(env.out, "BGP state = Established") &&
                    strstr(env.out, "a: snapshot") && !strstr(env.out, "b: snapshot");
        if (rejected && quiet && cmd(&env, "withdraw ribout a peer 127.0.0.1") >= 0 &&
            read_updates(&env, 2, &rx) == 2) {
            withdrawn = test_wire_update_view(rx.msgs[1], rx.lens[1], &view) && view.has_unreach &&
                        view.unreach_afi == 2 && view.unreach_safi == 133 && view.unreach_len == sizeof(expected) &&
                        memcmp(view.unreach, expected, sizeof(expected)) == 0 && nothing_sent(&env);
        }
    }
    env_stop(&env);
    rx_free(&rx);
    ASSERT(started, "real OPEN negotiation, generated ribouts, and first advertisement");
    ASSERT(wire_key, "first advertisement contains the independently specified offset NLRI");
    ASSERT(rejected, "second ribout with identical encoded NLRI must be rejected as overlapping a");
    ASSERT(quiet && preserved, "rejection sends no UPDATE and keeps the established session and binding a");
    ASSERT(withdrawn, "the original binding remains withdrawable with exactly its wire key");
    PASS();
}

static void test_overlap_rejected(void) {
    static const char *const red[] = {"config", "ribout red", "prefix 10.0.100.0/24 x 10", "next-hop 192.0.2.1",
                                      "end", "update generate", NULL};
    tx_env_t           env;
    bgp_capabilities_t caps = ipv4_peer();
    rx_list_t          rx = {0};
    int                ok = 0, rejected = 0, quiet = 0;

    TEST("A ribout whose route keys overlap a bound one is rejected and nothing is sent");
    if (env_start(&env, &caps, NULL) == 0 && skip_eor(&env) > 0 && cmds(&env, k_blue) == 0 && cmds(&env, red) == 0 &&
        cmd(&env, "advertise ribout blue peer 127.0.0.1") >= 0 &&
        read_updates(&env, env.sim->ribouts[0]->snapshot->adv->count, &rx) > 0) {
        ok = 1;
        rejected = cmd(&env, "advertise ribout red peer 127.0.0.1") < 0 &&
                   strstr(env.out, "rejected by 127.0.0.1: route keys overlap ribout blue");
        quiet = nothing_sent(&env);
    }
    env_stop(&env);
    rx_free(&rx);
    ASSERT(ok, "blue advertised");
    ASSERT(rejected, "red rejected with the overlap reason");
    ASSERT(quiet, "no UPDATE for red");
    PASS();
}

static void enable_vpnv4(bgp_capabilities_t *caps) {
    caps->vpnv4_unicast = 1;
}

static bgp_capabilities_t vpnv4_peer(void) {
    bgp_capabilities_t caps = ipv4_peer();

    caps.vpnv4_unicast = 1;
    return caps;
}

static void enable_ipv4_addpath(bgp_capabilities_t *caps) {
    caps->add_path_ipv4 = ADD_PATH_SEND | ADD_PATH_RECEIVE;
}

static void test_withheld_reasons(void) {
    static const char *const ribouts[] = {
        "config", "ribout v6", "prefix 2001:db8::/64 x 4", "next-hop 2001:db8::1", "exit",
        "ribout ids", "prefix 172.16.0.0/24 x 4", "path-id 1 2", "next-hop 192.0.2.1", "end", "update generate",
        NULL};
    tx_env_t           env;
    bgp_capabilities_t caps = ipv4_peer();
    int                ok = 0, as4 = 0, family = 0, addpath = 0, shown = 0, in_ribout = 0, quiet = 0;

    TEST("Advertisements the peer could not parse are withheld and shown with the reason");
    caps.four_byte_asn = 0;
    if (env_start(&env, &caps, enable_ipv4_addpath) == 0 && skip_eor(&env) > 0 && cmds(&env, k_blue) == 0 && cmds(&env, ribouts) == 0) {
        ok = 1;
        as4 = cmd(&env, "advertise ribout blue peer 127.0.0.1") >= 0 &&
              strstr(env.out, "withheld from 127.0.0.1: 4-octet AS not negotiated (AS_PATH is 4-octet)");
        family = cmd(&env, "advertise ribout v6 peer 127.0.0.1") >= 0 &&
                 strstr(env.out, "withheld from 127.0.0.1: IPv6 Unicast not negotiated");
        cmd(&env, "advertise ribout ids peer 127.0.0.1");
        addpath = strstr(env.out, "withheld from 127.0.0.1: 4-octet AS") != NULL;
        cmd(&env, "show bgp neighbors");
        shown = strstr(env.out, "blue: withheld: 4-octet AS not negotiated") &&
                strstr(env.out, "v6: withheld: IPv6 Unicast not negotiated");
        cmd(&env, "show ribout blue");
        in_ribout = strstr(env.out, "Peers:") && strstr(env.out, "127.0.0.1 (router 65000): withheld: 4-octet AS");
        quiet = nothing_sent(&env);
    }
    env_stop(&env);
    ASSERT(ok, "session up");
    ASSERT(as4, "4-octet AS reason");
    ASSERT(family, "family reason");
    ASSERT(addpath, "the first failing rule is reported");
    ASSERT(shown, "show bgp neighbors lists the withheld ribouts");
    ASSERT(in_ribout, "show ribout lists the peer that withheld it");
    ASSERT(quiet, "nothing was sent");
    PASS();
}

static void test_addpath_withheld(void) {
    static const char *const ids[] = {"config", "ribout ids", "prefix 172.16.0.0/24 x 4", "path-id 1 2",
                                      "next-hop 192.0.2.1", "end", "update generate", NULL};
    tx_env_t           env;
    bgp_capabilities_t caps = ipv4_peer();
    int                required = 0, unexpected = 0;

    TEST("ADD-PATH must match in both directions");
    caps.add_path_ipv4 = ADD_PATH_RECEIVE;
    if (env_start(&env, &caps, NULL) == 0 && skip_eor(&env) > 0 && cmds(&env, ids) == 0) {
        required = cmd(&env, "advertise ribout ids peer 127.0.0.1") >= 0 &&
                   strstr(env.out, "ribout has path-id but ADD-PATH send is not negotiated for IPv4 Unicast");
    }
    env_stop(&env);
    if (env_start(&env, &caps, enable_ipv4_addpath) == 0 && skip_eor(&env) > 0 && cmds(&env, k_blue) == 0) {
        unexpected = cmd(&env, "advertise ribout blue peer 127.0.0.1") >= 0 &&
                     strstr(env.out, "ADD-PATH is negotiated for IPv4 Unicast but the ribout has no path-id");
    }
    env_stop(&env);
    ASSERT(required, "path-id without negotiated ADD-PATH send");
    ASSERT(unexpected, "negotiated ADD-PATH send without path-id");
    PASS();
}

static void test_withdraw_after_no_ribout(void) {
    static const char *const remove[] = {"config", "no ribout blue", "end", NULL};
    tx_env_t           env;
    bgp_capabilities_t caps = ipv4_peer();
    rx_list_t          rx = {0};
    size_t             adv = 0;
    int                ok = 0, withdrawn = 0, all_rc = -1;

    TEST("A ribout removed from the configuration can still be withdrawn from the peer");
    if (env_start(&env, &caps, NULL) == 0 && skip_eor(&env) > 0 && cmds(&env, k_blue) == 0 &&
        cmd(&env, "advertise ribout blue peer 127.0.0.1") >= 0) {
        adv = env.sim->ribouts[0]->snapshot->adv->count;
        ok = read_updates(&env, adv, &rx) == adv && cmds(&env, remove) == 0;
        if (ok && cmd(&env, "withdraw ribout blue peer 127.0.0.1") >= 0) {
            read_written(&env, &rx);
            withdrawn = count_prefixes(&rx, adv, rx.count, 1) == 2000;
        }
        all_rc = cmd(&env, "withdraw all peer all");
    }
    env_stop(&env);
    rx_free(&rx);
    ASSERT(ok, "advertised, then no ribout blue");
    ASSERT(withdrawn, "withdraw by name after no ribout");
    ASSERT(all_rc >= 0, "withdraw all with nothing bound succeeds");
    PASS();
}

/*
 * 20000 VPNv4 UPDATEs of about 650 octets (64 route targets each), more than the loopback socket buffers
 * hold.
 */
static char k_big_rts[64][24];
static const char *k_big[8 + 64 + 3];

static void build_big_ribout(void) {
    static const char *const head[] = {"config", "ribout big", "prefix 10.0.0.0/24 x 20000", "rd 65000:1",
                                       "label 100", "next-hop 192.0.2.1", "localpref range(1,20000)",
                                       "as-path 65001 65002"};
    size_t n = 0;

    for (size_t i = 0; i < sizeof(head) / sizeof(head[0]); i++) {
        k_big[n++] = head[i];
    }
    for (int i = 0; i < 64; i++) {
        snprintf(k_big_rts[i], sizeof(k_big_rts[i]), "rt 65000:%d", i + 1);
        k_big[n++] = k_big_rts[i];
    }
    k_big[n++] = "end";
    k_big[n++] = "update generate";
    k_big[n] = NULL;
}

static void test_slow_reader_then_clear(void) {
    tx_env_t           env;
    bgp_capabilities_t caps = vpnv4_peer();
    int                ok = 0, backlog = 0, cleared = 0, responsive = 0;

    TEST("A peer that does not read: UPDATEs back up, then clear bgp resets the session cleanly");
    if (env_start(&env, &caps, enable_vpnv4) == 0 && skip_eor(&env) > 0 && cmds(&env, (const char *const *)k_big) == 0 &&
        cmd(&env, "advertise ribout big peer 127.0.0.1") >= 0) {
        ok = 1;
        backlog = wait_until(tx_backed_up, &env, TX_TIMEOUT_MS) &&
                  peer_neighbor(&env)->tx_update < env.sim->ribouts[0]->snapshot->adv->count;
        cleared = cmd(&env, "clear bgp 127.0.0.1") >= 0 &&
                  wait_until(session_down, &(neighbor_wait_t){peer_neighbor(&env)}, TX_TIMEOUT_MS);
        responsive = cmd(&env, "show bgp summary") >= 0;
    }
    env_stop(&env);
    ASSERT(ok, "big ribout queued");
    ASSERT(backlog, "the kernel buffers fill and the queue backs up");
    ASSERT(cleared && responsive, "the session resets and the runtime stays responsive");
    PASS();
}

/*
 * Drain already-buffered bytes: shutdown can occur in the middle of a BGP message. A timeout is not closure.
 */
static int peer_closed(void *opaque) {
    int     sock = *(int *)opaque;
    uint8_t bytes[65536];
    ssize_t len;

    do {
        len = recv(sock, bytes, sizeof(bytes), MSG_DONTWAIT);
    } while (len > 0 || (len < 0 && errno == EINTR));
    return len == 0 || (len < 0 && errno == ECONNRESET);
}

static int neighbor_finalized(void *opaque) {
    tx_env_t             *env = opaque;
    const bgp_neighbor_t *neighbor = peer_neighbor(env);

    return env->sim->routers[0]->neighbor_count == 0 && !neighbor->active && !neighbor->runtime_initialized &&
           !neighbor->stream_initialized && !neighbor->destroy_pending && !neighbor->tx;
}

static void test_remove_neighbor_with_queue(void) {
    static const char *const remove[] = {"config", "router bgp 65000", "no neighbor 127.0.0.1 remote-as 65001",
                                         "end", NULL};
    tx_env_t           env;
    bgp_capabilities_t caps = vpnv4_peer();
    int                ok = 0, backlog = 0, removed = 0, finalized = 0, closed = 0;

    TEST("Removing a neighbor with UPDATEs queued and a batch in flight");
    if (env_start(&env, &caps, enable_vpnv4) == 0 && skip_eor(&env) > 0 && cmds(&env, (const char *const *)k_big) == 0 &&
        cmd(&env, "advertise ribout big peer 127.0.0.1") >= 0) {
        ok = 1;
        backlog = wait_until(tx_backed_up, &env, TX_TIMEOUT_MS);
        if (backlog) {
            removed = cmds(&env, remove) == 0 && cmd(&env, "show bgp neighbors") >= 0 &&
                      !strstr(env.out, "BGP neighbor is 127.0.0.1,") && cmd(&env, "show running-config") >= 0 &&
                      !strstr(env.out, "neighbor 127.0.0.1");
            closed = wait_until(peer_closed, &env.peer, TX_TIMEOUT_MS);
            finalized = wait_until(neighbor_finalized, &env, TX_TIMEOUT_MS);
        }
    }
    env_stop(&env);
    ASSERT(ok, "big ribout queued on an established VPNv4 session");
    ASSERT(backlog, "queued UPDATEs remain with a pinned write batch in flight before removal");
    ASSERT(removed, "neighbor is absent from operational output and running configuration");
    ASSERT(closed, "peer observes EOF or reset, not just a quiet socket");
    ASSERT(finalized, "close callbacks reclaim the neighbor slot and TX state while runtime remains responsive");
    PASS();
}

static void test_notification_between_messages(void) {
    static const uint8_t bad_marker[BGP_HEADER_SIZE] = {0};
    tx_env_t           env;
    bgp_capabilities_t caps = vpnv4_peer();
    int                ok = 0, whole = 1, notified = 0;
    size_t             updates = 0;

    TEST("A NOTIFICATION during a stream of UPDATEs arrives after whole messages only");
    if (env_start(&env, &caps, enable_vpnv4) == 0 && skip_eor(&env) > 0 && cmds(&env, (const char *const *)k_big) == 0 &&
        cmd(&env, "advertise ribout big peer 127.0.0.1") >= 0) {
        uint8_t msg[BGP_MAX_MESSAGE_SIZE];
        uint8_t type = 0;
        int     len;

        // Some UPDATEs are written before the bad header arrives.
        ok = wait_until(sent_updates, &(tx_wait_t){peer_neighbor(&env), env.seen + 1}, TX_TIMEOUT_MS);
        send_raw(env.peer, bad_marker, sizeof(bad_marker));  /* Message header error: bgpsim sends a NOTIFICATION */
        while ((len = recv_bgp_message_with_timeout(env.peer, msg, sizeof(msg), &type, 2000)) > 0) {
            test_wire_update_t view;

            if (type == BGP_MSG_NOTIFICATION) {
                notified = msg[BGP_HEADER_SIZE] == BGP_ERR_MESSAGE_HEADER;
                break;
            }
            if (type == BGP_MSG_UPDATE) {
                updates++;
                whole &= test_wire_update_view(msg, (size_t)len, &view);
            }
        }
    }
    env_stop(&env);
    ASSERT(ok, "big ribout queued");
    ASSERT(notified, "the peer receives the Message Header Error NOTIFICATION");
    ASSERT(whole && updates > 0, "every UPDATE before it is a whole message");
    PASS();
}

// Standing advertisements and End-of-RIB

static const char *const k_standing_blue[] = {
    "config", "ribout blue", "prefix 10.0.0.0/24 x 2000", "next-hop 192.0.2.1", "localpref range(1,400)", "exit",
    "router bgp 65000", "neighbor 127.0.0.1 remote-as 65001", "advertise blue", "end", "update generate", NULL};

static void test_eor_without_mp(void) {
    tx_env_t           env;
    bgp_capabilities_t caps;
    rx_list_t          rx = {0};
    uint16_t           afi = 0;
    uint8_t            safi = 0;
    int                ok = 0, one = 0;

    TEST("A peer that sent no Multiprotocol capability gets one IPv4 End-of-RIB: an empty 23-octet UPDATE");
    memset(&caps, 0, sizeof(caps));
    caps.four_byte_asn = 1;
    if (env_start(&env, &caps, NULL) == 0) {
        ok = 1;
        ok = wait_until(eor_written, &env, TX_TIMEOUT_MS);
        read_written(&env, &rx);
        one = rx.count == 1 && rx.lens[0] == 23 && is_eor(rx.msgs[0], rx.lens[0], &afi, &safi) && afi == 1 &&
              safi == 1;
    }
    env_stop(&env);
    rx_free(&rx);
    ASSERT(ok && one, "exactly one IPv4 unicast End-of-RIB");
    PASS();
}

static void test_eor_per_negotiated_family(void) {
    tx_env_t           env;
    bgp_capabilities_t caps = vpnv4_peer();
    rx_list_t          rx = {0};
    uint16_t           afi[2] = {0};
    uint8_t            safi[2] = {0};
    int                ok = 0, both = 0, shown = 0;

    TEST("An MP peer gets End-of-RIB for each negotiated family: classic IPv4 and MP_UNREACH_NLRI for VPNv4");
    if (env_start(&env, &caps, enable_vpnv4) == 0) {
        ok = 1;
        ok = wait_until(eor_written, &env, TX_TIMEOUT_MS);
        read_written(&env, &rx);
        both = rx.count == 2 && is_eor(rx.msgs[0], rx.lens[0], &afi[0], &safi[0]) &&
               is_eor(rx.msgs[1], rx.lens[1], &afi[1], &safi[1]) && afi[0] == 1 && safi[0] == 1 && afi[1] == 1 &&
               safi[1] == 128 && rx.lens[1] == 29;
        cmd(&env, "show bgp neighbors");
        shown = strstr(env.out, "End-of-RIB sent: IPv4 Unicast, VPNv4 Unicast") != NULL;
    }
    env_stop(&env);
    rx_free(&rx);
    ASSERT(ok && both, "IPv4 unicast then VPNv4 End-of-RIB; IPv6 unicast is not negotiated");
    ASSERT(shown, "show bgp neighbors lists the End-of-RIB families");
    PASS();
}

static void test_standing_then_eor_and_reconnect(void) {
    tx_env_t           env;
    bgp_capabilities_t caps = ipv4_peer();
    rx_list_t          rx = {0};
    size_t             adv = 0;
    uint16_t           afi;
    uint8_t            safi;
    int                ok = 0, first = 0, again = 0, config = 0;

    TEST("Standing ribouts are sent when the session comes up, then End-of-RIB; again after a reconnect");
    if (env_start_setup(&env, &caps, NULL, k_standing_blue) == 0) {
        bgp_ribout_snapshot_t *snapshot = env.sim->ribouts[0]->snapshot;

        ok = 1;
        adv = snapshot->adv->count;
        read_updates(&env, adv + 1, &rx);
        first = rx.count == adv + 1 && same_bytes(&rx, 0, snapshot->adv->msgs) &&
                is_eor(rx.msgs[adv], rx.lens[adv], &afi, &safi);
        cmd(&env, "show running-config");
        config = strstr(env.out, "    advertise blue\n") != NULL;

        cmd(&env, "clear bgp 127.0.0.1");
        wait_until(session_down, &(neighbor_wait_t){peer_neighbor(&env)}, TX_TIMEOUT_MS);
        close(env.peer);
        rx_free(&rx);
        wait_until(tx_idle, &env, TX_TIMEOUT_MS);
        env.seen = peer_neighbor(&env)->tx_update;
        env.peer = session_connect_peer(env.sim, &caps);
        if (env.peer >= 0) {
            read_updates(&env, adv + 1, &rx);
            again = rx.count == adv + 1 && same_bytes(&rx, 0, snapshot->adv->msgs) &&
                    is_eor(rx.msgs[adv], rx.lens[adv], &afi, &safi);
        }
    }
    env_stop(&env);
    rx_free(&rx);
    ASSERT(ok && first, "the standing snapshot, then End-of-RIB");
    ASSERT(config, "running-config keeps the standing advertise line");
    ASSERT(again, "after clear bgp and a new session the standing ribout is sent again");
    PASS();
}

static void test_standing_withheld_until_generated(void) {
    static const char *const ungenerated[] = {
        "config", "ribout blue", "prefix 10.0.0.0/24 x 20", "next-hop 192.0.2.1", "exit", "router bgp 65000",
        "neighbor 127.0.0.1 remote-as 65001", "advertise blue", "end", NULL};
    tx_env_t           env;
    bgp_capabilities_t caps = ipv4_peer();
    rx_list_t          rx = {0};
    uint16_t           afi;
    uint8_t            safi;
    int                ok = 0, eor_only = 0, withheld = 0, sent = 0, cleared = 0;

    TEST("A standing ribout without a snapshot is withheld, End-of-RIB goes at once, and update generate sends it");
    if (env_start_setup(&env, &caps, NULL, ungenerated) == 0) {
        ok = 1;
        ok = wait_until(eor_written, &env, TX_TIMEOUT_MS);
        read_written(&env, &rx);
        eor_only = rx.count == 1 && is_eor(rx.msgs[0], rx.lens[0], &afi, &safi);
        cmd(&env, "show bgp neighbors");
        withheld = strstr(env.out, "blue: withheld: ribout blue has no UPDATE snapshot (run update generate)") != NULL;
        cmd(&env, "update generate");
        read_written(&env, &rx);
        sent = rx.count == 2 && count_prefixes(&rx, 1, 2, 0) == 20;
        cmd(&env, "show bgp neighbors");
        cleared = strstr(env.out, "withheld") == NULL && strstr(env.out, "blue: snapshot") != NULL;
    }
    env_stop(&env);
    rx_free(&rx);
    ASSERT(ok && eor_only, "only End-of-RIB at session up");
    ASSERT(withheld, "the withheld reason is shown");
    ASSERT(sent, "update generate sends the standing ribout, without another End-of-RIB");
    ASSERT(cleared, "the withheld record is replaced by the binding");
    PASS();
}

static void test_standing_follows_regeneration(void) {
    static const char *const attr_change[] = {"config", "ribout blue", "localpref range(500,900)", "end",
                                              "update generate", NULL};
    tx_env_t           env;
    bgp_capabilities_t caps = ipv4_peer();
    rx_list_t          rx = {0};
    size_t             adv = 0;
    int                ok = 0, replaced = 0, unchanged_quiet = 0;

    TEST("A standing ribout follows update generate: new bytes replace in place; identical bytes are not resent");
    if (env_start_setup(&env, &caps, NULL, k_standing_blue) == 0) {
        adv = env.sim->ribouts[0]->snapshot->adv->count;
        ok = read_updates(&env, adv + 1, &rx) == adv + 1;
        cmds(&env, attr_change);
        read_written(&env, &rx);
        replaced = rx.count == adv + 1 + env.sim->ribouts[0]->snapshot->adv->count &&
                   same_bytes(&rx, adv + 1, env.sim->ribouts[0]->snapshot->adv->msgs);
        cmd(&env, "update generate");
        unchanged_quiet = nothing_sent(&env) && bgp_peer_tx_binding(peer_neighbor(&env)->tx, "blue")->snapshot ==
                                                           env.sim->ribouts[0]->snapshot;
    }
    env_stop(&env);
    rx_free(&rx);
    ASSERT(ok, "standing blue and End-of-RIB");
    ASSERT(replaced, "the regenerated snapshot is sent with no withdrawal and no End-of-RIB");
    ASSERT(unchanged_quiet, "a regeneration with identical bytes rebinds without sending");
    PASS();
}

static void test_selected_color_set_regeneration(void) {
    static const char *const setup[] = {
        "config", "ribout steer", "address-family ipv6 flowspec", "prefix 2001:db8::/64",
        "action redirect-ip 192.0.2.9", "color 100", "exit",
        "ribout background", "prefix 10.0.0.0/24", "next-hop 192.0.2.1", "exit",
        "router bgp 65000", "neighbor 127.0.0.1 remote-as 65001", "advertise steer", "advertise background",
        "end", "update generate", NULL};
    static const char *const edits[] = {
        "config", "ribout steer", "color set 100 300 200", "exit",
        "ribout background", "localpref 500", "end", NULL};
    static const uint8_t expected_ext[] = {
        3, 11, 0, 0, 0, 0, 0, 100, 3, 11, 0, 0, 0, 0, 1, 44, 3, 11, 0, 0, 0, 0, 0, 200,
        1, 12, 192, 0, 2, 9, 0, 0
    };
    static const uint8_t expected_key[] = {11, 1, 64, 0, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0};
    static const uint8_t background_key[] = {24, 10, 0, 0};
    tx_env_t           env;
    bgp_capabilities_t caps = ipv4_peer();
    caps.ipv6_flowspec = 1;
    rx_list_t rx = {0};
    int       selected = 0, changed = 0, quiet = 0;
    TEST("Selected Color-set generation replaces live FlowSpec attributes and changed generation sends only the remainder");
    if (env_start_setup(&env, &caps, enable_flowspec6, setup) == 0 && skip_eor(&env) == 2 &&
        cmds(&env, edits) == 0) {
        bgp_ribout_config_t *background = bgp_sim_find_ribout(env.sim, "background");
        bgp_ribout_config_t *steer = bgp_sim_find_ribout(env.sim, "steer");
        uint64_t             old_background = background->snapshot->id;
        test_wire_update_t   view;
        const uint8_t       *ext = NULL;
        uint16_t             len = 0;
        selected = cmd(&env, "update generate ribout steer") >= 0 && read_written(&env, &rx) == 1 &&
                   background->snapshot->id == old_background && background->dirty && !steer->dirty &&
                   test_wire_update_view(rx.msgs[0], rx.lens[0], &view) &&
                   view.has_reach && view.reach_afi == 2 && view.reach_safi == 133 && !view.has_unreach &&
                   !view.withdrawn_len && view.reach_len == sizeof(expected_key) &&
                   !memcmp(view.reach, expected_key, sizeof(expected_key)) &&
                   test_wire_find_attr(rx.msgs[0], rx.lens[0], 16, &ext, &len, NULL) &&
                   len == sizeof(expected_ext) && !memcmp(ext, expected_ext, sizeof(expected_ext)) && nothing_sent(&env);
        uint64_t steer_id = steer->snapshot->id;
        if (selected) {
            changed = cmd(&env, "update generate changed") >= 0 && read_written(&env, &rx) == 1 &&
                      rx.count == 2 && !background->dirty && background->snapshot->id > old_background &&
                      steer->snapshot->id == steer_id && test_wire_update_view(rx.msgs[1], rx.lens[1], &view) &&
                      !view.withdrawn_len && !view.has_unreach && view.nlri_len == sizeof(background_key) &&
                      !memcmp(view.nlri, background_key, sizeof(background_key)) &&
                      test_wire_find_attr(rx.msgs[1], rx.lens[1], 5, &ext, &len, NULL) && len == 4 && read_u32(ext) == 500;
            quiet = cmd(&env, "update generate changed") >= 0 && nothing_sent(&env) &&
                    peer_neighbor(&env)->state == BGP_STATE_ESTABLISHED;
        }
    }
    env_stop(&env);
    rx_free(&rx);
    ASSERT(selected, "exact FlowSpec NLRI, all three Colors, and redirect endpoint arrive in one replacement UPDATE");
    ASSERT(changed, "only the other dirty standing ribout is regenerated and sent, with its new local preference");
    ASSERT(quiet, "no remaining dirty blocks sends nothing and keeps the established session");
    PASS();
}

static void test_live_standing_advertise(void) {
    static const char *const green[] = {"config", "ribout green", "prefix 172.16.0.0/24 x 5", "next-hop 192.0.2.1",
                                        "end", "update generate", NULL};
    static const char *const add[] = {"config", "router bgp 65000", "neighbor 127.0.0.1 remote-as 65001",
                                      "advertise green", "end", NULL};
    static const char *const remove[] = {"config", "router bgp 65000", "neighbor 127.0.0.1 remote-as 65001",
                                         "no advertise green", "end", NULL};
    tx_env_t           env;
    bgp_capabilities_t caps = ipv4_peer();
    rx_list_t          rx = {0};
    int                ok = 0, sent = 0, kept = 0;

    TEST("advertise <ribout> on an established session sends it at once; no advertise does not withdraw");
    if (env_start(&env, &caps, NULL) == 0 && skip_eor(&env) > 0 && cmds(&env, green) == 0) {
        ok = cmds(&env, add) == 0;
        read_written(&env, &rx);
        sent = rx.count == 1 && count_prefixes(&rx, 0, 1, 0) == 5;
        cmds(&env, remove);
        kept = nothing_sent(&env) && bgp_peer_tx_binding(peer_neighbor(&env)->tx, "green") != NULL;
    }
    env_stop(&env);
    rx_free(&rx);
    ASSERT(ok && sent, "green sent when added");
    ASSERT(kept, "removing the standing line sends nothing and keeps the binding");
    PASS();
}

// ROUTE-REFRESH

static void enable_refresh(bgp_capabilities_t *caps) {
    caps->route_refresh = 1;
}

static void enable_refresh_and_gr(bgp_capabilities_t *caps) {
    caps->route_refresh = 1;
    caps->graceful_restart = 1;
    caps->restart_time = 120;
}

static int send_route_refresh(int sock, uint16_t afi, uint8_t safi) {
    uint8_t msg[BGP_HEADER_SIZE + 4];

    memset(msg, 0xff, 16);
    msg[16] = 0;
    msg[17] = sizeof(msg);
    msg[18] = BGP_MSG_ROUTE_REFRESH;
    msg[19] = (uint8_t)(afi >> 8);
    msg[20] = (uint8_t)afi;
    msg[21] = 0;
    msg[22] = safi;
    return send_raw(sock, msg, sizeof(msg));
}

static void test_route_refresh(void) {
    tx_env_t           env;
    bgp_capabilities_t caps = ipv4_peer();
    rx_list_t          rx = {0};
    size_t             adv = 0;
    int                ok = 0, replayed = 0, ignored = 0, up = 0;

    TEST("ROUTE-REFRESH replays the bound snapshot; a family that is not negotiated is ignored");
    caps.route_refresh = 1;
    if (env_start(&env, &caps, enable_refresh) == 0 && skip_eor(&env) > 0 && cmds(&env, k_blue) == 0 &&
        cmd(&env, "advertise ribout blue peer 127.0.0.1") >= 0) {
        adv = env.sim->ribouts[0]->snapshot->adv->count;
        ok = read_updates(&env, adv, &rx) == adv;
        send_route_refresh(env.peer, 1, 1);
        peer_barrier(env.peer, peer_neighbor(&env));
        read_written(&env, &rx);
        replayed = rx.count == 2 * adv && same_bytes(&rx, adv, env.sim->ribouts[0]->snapshot->adv->msgs);
        send_route_refresh(env.peer, 2, 1);
        ignored = peer_barrier(env.peer, peer_neighbor(&env)) && nothing_sent(&env);
        up = peer_neighbor(&env)->state == BGP_STATE_ESTABLISHED;
    }
    env_stop(&env);
    rx_free(&rx);
    ASSERT(ok, "blue advertised");
    ASSERT(replayed, "the refresh resends the bound snapshot, with no End-of-RIB without graceful restart");
    ASSERT(ignored && up, "an IPv6 refresh (not negotiated) is ignored and the session stays up");
    PASS();
}

static void test_route_refresh_eor_with_gr(void) {
    tx_env_t           env;
    bgp_capabilities_t caps = ipv4_peer();
    rx_list_t          rx = {0};
    size_t             adv = 0;
    uint16_t           afi = 0;
    uint8_t            safi = 0;
    int                ok = 0, eor = 0;

    TEST("With graceful restart negotiated, End-of-RIB follows the refresh replay");
    caps.route_refresh = 1;
    caps.graceful_restart = 1;
    caps.restart_time = 120;
    if (env_start(&env, &caps, enable_refresh_and_gr) == 0 && skip_eor(&env) > 0 && cmds(&env, k_blue) == 0 &&
        cmd(&env, "advertise ribout blue peer 127.0.0.1") >= 0) {
        adv = env.sim->ribouts[0]->snapshot->adv->count;
        ok = read_updates(&env, adv, &rx) == adv;
        send_route_refresh(env.peer, 1, 1);
        peer_barrier(env.peer, peer_neighbor(&env));
        read_written(&env, &rx);
        eor = rx.count == 2 * adv + 1 && is_eor(rx.msgs[2 * adv], rx.lens[2 * adv], &afi, &safi) && afi == 1 &&
              safi == 1;
    }
    env_stop(&env);
    rx_free(&rx);
    ASSERT(ok, "blue advertised");
    ASSERT(eor, "replay, then the IPv4 unicast End-of-RIB");
    PASS();
}

// Script runs

static const char *const k_churn[] = {
    "config", "script churn", "advertise ribout blue peer 127.0.0.1", "sleep 200ms",
    "withdraw ribout blue peer 127.0.0.1", "end", NULL};

typedef struct {
    bgp_sim_t         *sim;
    script_run_state_t state;
} run_wait_t;

static int run_reached(void *opaque) {
    run_wait_t *wait = opaque;

    return wait->sim->scripts.run_count > 0 && wait->sim->scripts.runs[0]->state == wait->state;
}

static void test_script_advertise_sleep_withdraw(void) {
    tx_env_t           env;
    bgp_capabilities_t caps = ipv4_peer();
    rx_list_t          rx = {0};
    size_t             advertised = 0, withdrawn = 0, split;
    int                ok = 0, complete = 0, shown = 0, timed = 0;

    TEST("run script: advertise, sleep and withdraw reach the peer in order, with measured phases");
    if (env_start(&env, &caps, NULL) == 0 && skip_eor(&env) > 0 && cmds(&env, k_blue) == 0 &&
        cmds(&env, k_churn) == 0) {
        ok = cmd(&env, "run script churn") >= 0 && strstr(env.out, "Run 1: script churn started.");
        complete = wait_until(run_reached, &(run_wait_t){env.sim, RUN_COMPLETE}, TX_TIMEOUT_MS);
        read_written(&env, &rx);
        for (split = 0; split < rx.count; split++) {
            test_wire_update_t view;

            if (test_wire_update_view(rx.msgs[split], rx.lens[split], &view) && view.withdrawn_len > 0) {
                break;
            }
        }
        advertised = count_prefixes(&rx, 0, split, 0);
        withdrawn = count_prefixes(&rx, split, rx.count, 1);
        cmd(&env, "show run 1");
        shown = strstr(env.out, "State: complete") && !strstr(env.out, "not connected") &&
                strstr(env.out, "complete");
        timed = env.sim->scripts.runs[0]->stats[1].phases[RUN_PHASE_SLEEP].samples == 1 &&
                env.sim->scripts.runs[0]->stats[1].phases[RUN_PHASE_SLEEP].total_ms >= 200 &&
                env.sim->scripts.runs[0]->stats[0].phases[RUN_PHASE_TRANSMIT].samples == 1;
    }
    env_stop(&env);
    rx_free(&rx);
    ASSERT(ok && complete, "the run starts and completes");
    ASSERT(advertised == 2000 && withdrawn == 2000, "2000 prefixes advertised, then withdrawn");
    ASSERT(shown, "show run reports the completed run");
    ASSERT(timed, "the sleep lasted at least 200ms and the transmit phase was sampled");
    PASS();
}

static void test_script_repeat(void) {
    tx_env_t           env;
    bgp_capabilities_t caps = ipv4_peer();
    rx_list_t          rx = {0};
    size_t             advertised = 0, withdrawn = 0;
    int                complete = 0;

    TEST("run script repeat 3 advertises and withdraws three times");
    if (env_start(&env, &caps, NULL) == 0 && skip_eor(&env) > 0 && cmds(&env, k_blue) == 0 &&
        cmds(&env, k_churn) == 0 && cmd(&env, "run script churn repeat 3") >= 0) {
        complete = wait_until(run_reached, &(run_wait_t){env.sim, RUN_COMPLETE}, 3 * TX_TIMEOUT_MS) &&
                   env.sim->scripts.runs[0]->iteration == 3;
        read_written(&env, &rx);
        for (size_t i = 0; i < rx.count; i++) {
            test_wire_update_t view;

            if (test_wire_update_view(rx.msgs[i], rx.lens[i], &view) && view.withdrawn_len > 0) {
                withdrawn += count_prefixes(&rx, i, i + 1, 1);
            } else {
                advertised += count_prefixes(&rx, i, i + 1, 0);
            }
        }
    }
    env_stop(&env);
    rx_free(&rx);
    ASSERT(complete, "three iterations");
    ASSERT(advertised == 6000 && withdrawn == 6000, "each iteration advertised and withdrew 2000 prefixes");
    PASS();
}

static void test_script_reset_fails_run(void) {
    static const char *const flood[] = {"config", "script flood", "advertise ribout big peer 127.0.0.1",
                                        "sleep 1s", "end", NULL};
    tx_env_t           env;
    bgp_capabilities_t caps = vpnv4_peer();
    int                ok = 0, failed = 0;

    TEST("A session reset while a step is sending fails the run");
    if (env_start(&env, &caps, enable_vpnv4) == 0 && skip_eor(&env) > 0 &&
        cmds(&env, (const char *const *)k_big) == 0 && cmds(&env, flood) == 0 &&
        cmd(&env, "run script flood") >= 0) {
        // The step is sending: its UPDATEs back up behind a peer that does not read.
        ok = wait_until(tx_backed_up, &env, TX_TIMEOUT_MS);
        cmd(&env, "clear bgp 127.0.0.1");
        failed = wait_until(run_reached, &(run_wait_t){env.sim, RUN_FAILED}, TX_TIMEOUT_MS) &&
                 strstr(env.sim->scripts.runs[0]->error, "session to 127.0.0.1 reset during the step");
    }
    env_stop(&env);
    ASSERT(ok, "run started");
    ASSERT(failed, "the run failed with the reset reason");
    PASS();
}

static void test_script_cancel_and_shutdown(void) {
    static const char *const nap[] = {"config", "script nap", "sleep 10s", "end", NULL};
    tx_env_t           env;
    bgp_capabilities_t caps = ipv4_peer();
    int                cancelled = 0, second_running = 0;

    TEST("cancel run during a sleep; shutdown with a run still sleeping");
    if (env_start(&env, &caps, NULL) == 0 && cmds(&env, nap) == 0 && cmd(&env, "run script nap") >= 0) {
        cancelled = cmd(&env, "cancel run 1") >= 0 && env.sim->scripts.runs[0]->state == RUN_CANCELLED;
        second_running = cmd(&env, "run script nap") >= 0 && env.sim->scripts.runs[1]->state == RUN_RUNNING;
    }
    env_stop(&env);  /* The runtime shuts down with run 2 sleeping */
    ASSERT(cancelled, "the sleeping run is cancelled");
    ASSERT(second_running, "a second run is sleeping at shutdown");
    PASS();
}

static void test_script_peer_all_withheld_and_skipped(void) {
    static const char *const setup[] = {"config", "router bgp 65000", "neighbor 192.0.2.99 remote-as 65002", "end",
                                        NULL};
    static const char *const all[] = {"config", "script all", "advertise ribout blue peer all", "end", NULL};
    tx_env_t           env;
    bgp_capabilities_t caps = ipv4_peer();
    int                complete = 0, shown = 0, quiet = 0;

    TEST("A peer-all step completes with one peer withheld and one skipped, and shows why");
    caps.four_byte_asn = 0;
    if (env_start_setup(&env, &caps, NULL, setup) == 0 && skip_eor(&env) > 0 && cmds(&env, k_blue) == 0 &&
        cmds(&env, all) == 0 && cmd(&env, "run script all") >= 0) {
        complete = wait_until(run_reached, &(run_wait_t){env.sim, RUN_COMPLETE}, TX_TIMEOUT_MS);
        cmd(&env, "show run 1");
        shown = strstr(env.out, "127.0.0.1: withheld: 4-octet AS not negotiated") &&
                strstr(env.out, "192.0.2.99: skipped: session not established");
        quiet = nothing_sent(&env);
    }
    env_stop(&env);
    ASSERT(complete, "the run completes");
    ASSERT(shown, "show run lists the withheld and skipped peers with reasons");
    ASSERT(quiet, "nothing was sent");
    PASS();
}

static void test_not_established_and_no_runtime(void) {
    bgp_sim_t    *sim = create_sim();
    cli_mode_t    mode = CLI_MODE_EXEC;
    cli_session_t session;
    int           rc;

    TEST("Without the runtime an advertise is an error");
    cli_session_init(&session);
    rc = sim ? cli_process_command(&session, sim, &mode, "advertise ribout blue peer 127.0.0.1") : 0;
    destroy_sim(sim);
    ASSERT(rc < 0, "advertise needs the runtime");
    PASS();
}

static const bgp_family_t *template_session_family;
static int template_session_add_path;

static void enable_template_session(bgp_capabilities_t *caps) {
    *(int *)((uint8_t *)caps + template_session_family->mp_offset) = 1;
    bgp_caps_set_add_path(caps, template_session_family->afi, template_session_family->safi,
                          template_session_add_path ? ADD_PATH_SEND : 0);
}

static void test_template_real_session(const template_vector_t *v, int add_path) {
    char name[128], nlri[1200], af[80];
    snprintf(name, sizeof(name), "%s real session advertisement/withdrawal (ADD-PATH %s)",
                v->name, add_path ? "on" : "off");
    TEST(name);
    template_session_family = bgp_family_lookup(v->afi, v->safi);
    template_session_add_path = add_path;
    ASSERT(template_session_family, "fixture AFI/SAFI is registered");
    snprintf(nlri, sizeof(nlri), "%s x %u", v->command, v->count);
    snprintf(af, sizeof(af), "address-family %s", template_session_family->cli_name);
    const char *const setup[] = {"config", "ribout typed", af, nlri, "next-hop 192.0.2.9",
                                 add_path ? "path-id 7" : "no path-id", "end", "update generate", NULL};
    tx_env_t           env;
    bgp_capabilities_t caps = ipv4_peer();
    *(int *)((uint8_t *)&caps + template_session_family->mp_offset) = 1;
    bgp_caps_set_add_path(&caps, v->afi, v->safi, add_path ? ADD_PATH_RECEIVE : 0);
    rx_list_t rx = {0};
    uint8_t   expected[1024];
    size_t    len = 0;
    for (unsigned i = 0; i < v->count; i++) len += template_expected(v, i, add_path, 7, expected + len);
    int adv = 0, withdrawn = 0;
    if (env_start(&env, &caps, enable_template_session) == 0 && skip_eor(&env) > 0 && cmds(&env, setup) == 0 &&
        cmd(&env, "advertise ribout typed peer 127.0.0.1") >= 0 && read_updates(&env, 1, &rx) == 1) {
        test_wire_update_t view;
        adv = test_wire_update_view(rx.msgs[0], rx.lens[0], &view) && view.has_reach &&
              view.reach_afi == v->afi && view.reach_safi == v->safi && view.reach_len == len &&
              !memcmp(view.reach, expected, len);
        if (adv && cmd(&env, "withdraw all peer 127.0.0.1") >= 0 && read_updates(&env, 2, &rx) == 2) {
            withdrawn = test_wire_update_view(rx.msgs[1], rx.lens[1], &view) && view.has_unreach &&
                        view.unreach_afi == v->afi && view.unreach_safi == v->safi && view.unreach_len == len &&
                        !memcmp(view.unreach, expected, len) && nothing_sent(&env) &&
                        cmd(&env, "show bgp neighbors") >= 0 && strstr(env.out, "BGP state = Established");
        }
    }
    env_stop(&env);
    rx_free(&rx);
    ASSERT(adv, "the negotiated socket receives independently specified NLRI and Path IDs");
    ASSERT(withdrawn, "withdraw-all removes exactly those keys without resetting the session");
    PASS();
}

static void test_template_peer_ownership(void) {
    TEST("Template ribouts share a peer only when their route-key ranges are disjoint");
    template_session_family = bgp_family_lookup(1, 132);
    template_session_add_path = 0;
    bgp_capabilities_t caps = ipv4_peer();
    *(int *)((uint8_t *)&caps + template_session_family->mp_offset) = 1;
    const char *const setup[] = {
        "config", "ribout one", "nlri rtc origin-as 65000 target 65000:1 x 3", "exit",
        "ribout two", "nlri rtc origin-as 65000 target 65000:4 x 3", "exit",
        "ribout collision", "nlri rtc origin-as 65000 target 65000:3 x 3", "end", "update generate", NULL
    };
    tx_env_t  env;
    rx_list_t rx = {0};
    int ok = env_start(&env, &caps, enable_template_session) == 0 && skip_eor(&env) > 0 &&
             cmds(&env, setup) == 0 && cmd(&env, "advertise ribout one peer 127.0.0.1") >= 0 &&
             read_updates(&env, 1, &rx) == 1 && cmd(&env, "advertise ribout two peer 127.0.0.1") >= 0 &&
             read_updates(&env, 2, &rx) == 2 && cmd(&env, "advertise ribout collision peer 127.0.0.1") < 0 &&
             nothing_sent(&env) && cmd(&env, "withdraw ribout one peer 127.0.0.1") >= 0 &&
             read_updates(&env, 3, &rx) == 3 && cmd(&env, "withdraw all peer 127.0.0.1") >= 0 &&
             read_updates(&env, 4, &rx) == 4;
    for (int i = 0; ok && i < 2; i++) {
        test_wire_update_t adv, unreach;
        ok = test_wire_update_view(rx.msgs[i], rx.lens[i], &adv) && adv.has_reach &&
             test_wire_update_view(rx.msgs[i + 2], rx.lens[i + 2], &unreach) && unreach.has_unreach &&
             adv.reach_len == 39 && unreach.unreach_len == adv.reach_len &&
             !memcmp(adv.reach, unreach.unreach, adv.reach_len);
    }
    env_stop(&env);
    rx_free(&rx);
    ASSERT(ok, "disjoint owners advertise and withdraw independently; overlapping keys send nothing");
    PASS();
}

static void test_live_registry_growth(void) {
    TEST("Live router/peer table growth preserves handles and selects every peer beyond 1024");
    tx_env_t           env;
    rx_list_t          rx = {0};
    bgp_capabilities_t caps = ipv4_peer();
    int                ok = env_start(&env, &caps, NULL) == 0 && skip_eor(&env) > 0;
    bgp_neighbor_t    *original = ok ? peer_neighbor(&env) : NULL;
    bgp_router_t      *router = original ? original->router : NULL;
    ok = ok && cmd(&env, "config") >= 0;
    for (int i = 1; i < 64 && ok; i++) {
        char line[80];
        snprintf(line, sizeof(line), "router bgp %d", 65000 + i);
        ok = cmd(&env, line) >= 0;
    }
    ok = ok && cmd(&env, "router bgp 65000") >= 0;
    for (int i = 1; i <= 1500 && ok; i++) {
        char line[100];
        snprintf(line, sizeof(line), "neighbor 127.1.%d.%d remote-as 65100", i / 256, i % 256);
        ok = cmd(&env, line) >= 0;
    }
    ok = ok && cmd(&env, "end") >= 0 && env.sim->router_count == 64 && router->neighbor_count == 1501 &&
         peer_neighbor(&env) == original && original->router == router &&
         original->stream.data == original && original->keepalive_timer.data == original &&
         original->state == BGP_STATE_ESTABLISHED && cmds(&env, k_blue) == 0 &&
         cmd(&env, "advertise ribout blue peer all router 65000") >= 0;
    size_t skipped = 0;
    if (ok) {
        for (const char *p = env.out; (p = strstr(p, "session not established")); p++) skipped++;
        ok = skipped == 1500 && strstr(env.out, "127.1.5.220") != NULL;
    }
    size_t want = ok ? bgp_sim_find_ribout(env.sim, "blue")->snapshot->adv->count : 0;
    ok = ok && read_updates(&env, want, &rx) == want && blue_routes(&rx, 0, want, 2000, 0, 1, 400) &&
         cmd(&env, "withdraw all peer 127.0.0.1 router 65000") >= 0;
    size_t               split = rx.count;
    bgp_ribout_config_t *blue = ok ? bgp_sim_find_ribout(env.sim, "blue") : NULL;
    bgp_msg_stream_t    *withdrawal = blue ? bgp_ribout_snapshot_withdrawal(blue->snapshot) : NULL;
    ok = ok && withdrawal && read_updates(&env, split + withdrawal->count, &rx) == split + withdrawal->count &&
         blue_routes(&rx, split, rx.count, 2000, 1, 0, 0) && original->state == BGP_STATE_ESTABLISHED;
    bgp_msg_stream_unref(withdrawal);
    static const char *const script[] = {"config", "script scale",
        "advertise ribout blue peer all router 65000", "end", "run script scale", NULL};
    size_t mark = rx.count;
    ok = ok && cmds(&env, script) == 0 &&
         wait_until(run_reached, &(run_wait_t){env.sim, RUN_COMPLETE}, TX_TIMEOUT_MS);
    if (ok) {
        const script_run_t *run = env.sim->scripts.runs[0];
        ok = run->peer_count == 1501 && run->peers[0].messages_done == want &&
             run->peers[1500].plan.status == SCRIPT_PEER_SKIPPED &&
             !strcmp(run->peers[1500].plan.peer, "127.1.5.220") &&
             read_updates(&env, mark + want, &rx) == mark + want &&
             blue_routes(&rx, mark, rx.count, 2000, 0, 1, 400);
    }
    env_stop(&env);
    rx_free(&rx);
    ASSERT(ok, "Exec and script paths record all 1501 peers; the original socket sends exact advertisements/withdrawals");
    PASS();
}

static int scale_route_set(const rx_list_t *rx, size_t first, size_t count, int withdrawn) {
    uint8_t seen[640] = {0};
    if (rx->count < first + count || count != sizeof(seen)) return 0;
    for (size_t i = first; i < first + count; i++) {
        test_wire_update_t view;
        if (!test_wire_update_view(rx->msgs[i], rx->lens[i], &view)) return 0;
        const uint8_t *nlri = withdrawn ? view.withdrawn : view.nlri;
        size_t         length = withdrawn ? view.withdrawn_len : view.nlri_len;
        if (length != 4 || nlri[0] != 24 || nlri[1] != 10 ||
            (withdrawn ? view.nlri_len : view.withdrawn_len) != 0) return 0;
        unsigned index = (unsigned)nlri[2] * 256 + nlri[3];
        if (index >= sizeof(seen) || seen[index]++) return 0;
    }
    return 1;
}

static void test_export_scale(void) {
    TEST("640 standing ribouts: independent advertisements, full refresh and withdraw-all on one socket");
    tx_env_t           env;
    rx_list_t          rx = {0};
    bgp_capabilities_t caps = ipv4_peer();
    caps.route_refresh = 1;
    int ok = env_start(&env, &caps, enable_refresh) == 0 && skip_eor(&env) > 0 && cmd(&env, "config") >= 0;
    for (int i = 0; i < 640 && ok; i++) {
        char name[64], prefix[80];
        snprintf(name, sizeof(name), "ribout scale%d", i);
        snprintf(prefix, sizeof(prefix), "prefix 10.%d.%d.0/24", i / 256, i % 256);
        ok = cmd(&env, name) >= 0 && cmd(&env, prefix) >= 0 && cmd(&env, "next-hop 192.0.2.1") >= 0;
    }
    ok = ok && cmd(&env, "exit") >= 0 && cmd(&env, "router bgp 65000") >= 0 &&
         cmd(&env, "neighbor 127.0.0.1 remote-as 65001") >= 0;
    for (int i = 0; i < 640 && ok; i++) {
        char line[64];
        snprintf(line, sizeof(line), "advertise scale%d", i);
        ok = cmd(&env, line) >= 0;
    }
    if (!ok || peer_neighbor(&env)->advertise_count != 640 || peer_neighbor(&env)->tx->withheld_count != 640)
        fprintf(stderr, "export setup: ok=%d standing=%d withheld=%zu: %s\n", ok,
                peer_neighbor(&env)->advertise_count, peer_neighbor(&env)->tx->withheld_count, env.out);
    ok = ok && peer_neighbor(&env)->advertise_count == 640 && peer_neighbor(&env)->tx->withheld_count == 640 &&
         cmd(&env, "end") >= 0 && cmd(&env, "update generate") >= 0 &&
         read_updates(&env, 640, &rx) == 640 && scale_route_set(&rx, 0, 640, 0) && nothing_sent(&env) &&
         peer_neighbor(&env)->tx->binding_count == 640 && !peer_neighbor(&env)->tx->withheld_count;
    int refreshed = ok && send_route_refresh(env.peer, 1, 1) == 0 &&
                    read_updates(&env, 1280, &rx) == 1280 && scale_route_set(&rx, 640, 640, 0) && nothing_sent(&env);
    int withdrawn = refreshed && cmd(&env, "withdraw all peer 127.0.0.1") >= 0 &&
                    read_updates(&env, 1920, &rx) == 1920 && scale_route_set(&rx, 1280, 640, 1) &&
                    nothing_sent(&env) && !peer_neighbor(&env)->tx->binding_count &&
                    peer_neighbor(&env)->state == BGP_STATE_ESTABLISHED;
    env_stop(&env);
    rx_free(&rx);
    ASSERT(ok, "all 640 independently specified routes advertise exactly once; withheld state clears");
    ASSERT(refreshed, "a real ROUTE-REFRESH replays all 640 bindings, not a truncated subset");
    ASSERT(withdrawn, "withdraw-all removes all 640 exact keys and leaves the session established");
    PASS();
}

/*
 * Linux has all of 127/8 on loopback; macOS has only 127.0.0.1 unless aliased (ifconfig lo0 alias 127.0.0.2).
 */
static int loopback_source_usable(const char *ip) {
    struct sockaddr_in addr = {.sin_family = AF_INET};
    int                sock = socket(AF_INET, SOCK_STREAM, 0);
    int ok = sock >= 0 && inet_pton(AF_INET, ip, &addr.sin_addr) == 1 &&
             bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0;

    if (sock >= 0) close(sock);
    return ok;
}

static void test_multi_peer_atomic_rejection(void) {
    if (!loopback_source_usable("127.0.0.2")) {
        TEST_PRINT_SKIP("A rejection by a later peer discards earlier peers' fully reserved plans: "
                        "127.0.0.2 is not a loopback address here (macOS: ifconfig lo0 alias 127.0.0.2)");
        return;
    }
    TEST("A rejection by a later peer discards earlier peers' fully reserved plans");
    const char *const setup[] = {"config", "router bgp 65000", "neighbor 127.0.0.2 remote-as 65001", "end", NULL};
    const char *const red[] = {"config", "ribout red", "prefix 10.0.0.0/24", "next-hop 192.0.2.1", "end",
                               "update generate", NULL};
    tx_env_t           env;
    rx_list_t          rx = {0};
    bgp_capabilities_t caps = ipv4_peer();
    int                second = -1;
    int                ok = env_start_setup(&env, &caps, NULL, setup) == 0 && skip_eor(&env) > 0;
    bgp_neighbor_t    *peer2 = ok ? bgp_find_neighbor(env.sim->routers[0], "127.0.0.2") : NULL;
    uint8_t message[BGP_MAX_MESSAGE_SIZE], type;
    if (ok) second = session_connect_neighbor(peer2, &caps);
    ok = ok && second >= 0 && recv_bgp_message_with_timeout(second, message, sizeof(message), &type, TX_TIMEOUT_MS) == 23 &&
         type == BGP_MSG_UPDATE && cmds(&env, k_blue) == 0 && cmds(&env, red) == 0 &&
         cmd(&env, "advertise ribout red peer 127.0.0.2") >= 0 &&
         recv_bgp_message_with_timeout(second, message, sizeof(message), &type, TX_TIMEOUT_MS) > 23 &&
         type == BGP_MSG_UPDATE;
    bgp_ribout_config_t *blue = ok ? bgp_sim_find_ribout(env.sim, "blue") : NULL;
    ok = ok && cmd(&env, "advertise ribout blue peer all") < 0 && strstr(env.out, "route keys overlap") &&
         strstr(env.out, "another peer rejected") && nothing_sent(&env) && !peer_neighbor(&env)->tx->binding_count &&
         !peer_neighbor(&env)->tx->job_count && blue->snapshot->refs == 1 && peer2->tx->binding_count == 1 &&
         !bgp_peer_tx_binding(peer2->tx, "blue") && peer_barrier(second, peer2) &&
         !peer_has_message(second, BGP_MSG_UPDATE);
    if (second >= 0) close(second);
    env_stop(&env);
    rx_free(&rx);
    ASSERT(ok, "Neither peer gets new bytes/bindings and the first peer's plan releases all snapshot references");
    PASS();
}

int main(void) {
    test_multi_peer_atomic_rejection();
    test_export_scale();
    test_live_registry_growth();
    test_template_peer_ownership();
    for (size_t i = 0; i < sizeof(template_vectors) / sizeof(*template_vectors); i++) {
        test_template_real_session(&template_vectors[i], 0);
        test_template_real_session(&template_vectors[i], 1);
    }
    build_big_ribout();
    test_advertise_and_withdraw();
    test_regenerate_same_and_changed_keys();
    test_regenerate_communities_and_rotation();
    test_overlap_rejected();
    test_flowspec_offset_overlap("prefix");
    test_flowspec_offset_overlap("src-prefix");
    test_withheld_reasons();
    test_addpath_withheld();
    test_withdraw_after_no_ribout();
    test_slow_reader_then_clear();
    test_remove_neighbor_with_queue();
    test_notification_between_messages();
    test_eor_without_mp();
    test_eor_per_negotiated_family();
    test_standing_then_eor_and_reconnect();
    test_standing_withheld_until_generated();
    test_standing_follows_regeneration();
    test_selected_color_set_regeneration();
    test_live_standing_advertise();
    test_route_refresh();
    test_route_refresh_eor_with_gr();
    test_script_advertise_sleep_withdraw();
    test_script_repeat();
    test_script_reset_fails_run();
    test_script_cancel_and_shutdown();
    test_script_peer_all_withheld_and_skipped();
    test_not_established_and_no_runtime();
    printf("\nTests run: %d, passed: %d, failed: %d\n", tests_run, tests_passed, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
