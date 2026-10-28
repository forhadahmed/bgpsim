/*
 * Churn: generated UPDATEs keep their identity through configuration changes.
 *
 * Each case starts from a complex ribout of one family (rotators and multipliers together) and generates it. Then
 * seeded random edits go through bgp_ribout_edit(), the CLI's path: lists swapped between rotate and plain, counts
 * changed ("{a-b}" in an edit is a random number in that range), appended lines added, cleared and reordered,
 * rotate-every / rotate-period toggled, and lines that must be rejected. After every edit:
 *  - a rejected edit leaves the configuration bytes as they were;
 *  - a configuration that generates sends every path once (NLRIs on the wire = total paths, read with the test-side
 *    readers), with total paths / (multipliers that are not keys) distinct route keys;
 *  - its running-config, loaded into a new simulator, generates the same bytes.
 * Then every edited keyword goes back to its base lines: the UPDATEs are byte for byte the original ones, the keyspace
 * is the same, and a block built fresh from the base lines generates the same bytes too.
 *
 * CHURN_SEED and CHURN_ROUNDS override the seed and the number of edits per case.
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "bgpsim.h"
#include "output.h"
#include "test_case.h"
#include "bgp_ribout.h"
#include "test_helpers.h"
#include "test_route_keys.h"
#include "bgp_ribout_snapshot.h"

typedef struct {
    const char *name;
    const char *base[24];   /* NULL-terminated "keyword value" lines                                   */
    const char *edits[64];  /* NULL-terminated; "no <keyword>", "; " joins several lines into one edit */
} churn_case_t;

#define SR_LISTS "segment-list 1 weight 10 mpls 16001", "segment-list 2 weight 20 mpls 16002 16003", \
                 "rt 192.0.2.1:100"

static const churn_case_t k_cases[] = {
    {
        .name = "vpn4 VRFs",
        .base = {
            "prefix 10.20.0.0/24 x 300",
            "rd rotate 65551:1 x 10",
            "label rotate 24001 x 10",
            "rt-set [65551:1,65551:1001] x 10",
            "community [65000:1,no-export] 65000:100 x 9",
            "large-community [65551:1:1] x 10",
            "next-hop 192.0.2.1 x 2",
            "med range(1,5)",
            "localpref rand(1000)",
            "as-path 65001 65002",
            NULL,
        },
        .edits = {
            // key lists: plain multiplies, rotate goes one per path
            "rd 65551:1 x {1-4}",
            "rd rotate 65551:1 x {1-12}",
            "label 24001 x {1-3}",
            "label rotate 24001 x {1-12}",
            "prefix 10.20.0.0/24 x {1-400}",
            // appended lines: added, cleared, replaced, reordered
            "rt-set [65551:7] x {1-12}",
            "no rt-set",
            "no rt-set; rt-set [65551:1,65551:1001] x 10",
            "community 65000:{1-9}",
            "community [65000:9,no-export] [65000:10]",
            "no community",
            "no community; community 65000:100 x 9; community [65000:1,no-export]",
            "large-community [65551:2:2,65551:3:3]",
            "no large-community",
            // attribute rotators
            "next-hop 192.0.2.9",
            "next-hop 192.0.2.1 x {1-12}",
            "med {1-9}",
            "no med",
            "localpref range(1,{1-5})",
            "as-path 65009",
            "rotate-every {1-12}",
            "no rotate-every",
            "rotate-period 10",
            "no rotate-period",
            // rejected
            "community 70000:1",
            "community [65000:1,65000:1]",
            "next-hop 192.0.2.1 x 0",
            "next-hop 192.0.2.1 x -1",
            "next-hop 192.0.2.1 junk",
            "label +100",
            "as-path 65001 junk",
            "med +5",
            "rd rotate",
            "label rotate x 3",
            "rt-set [65551:1",
            "rotate-every 0",
            "large-community 1:2",
            NULL,
        },
    },
    {
        .name = "SR Policy",
        .base = {
            "distinguisher 1 x 3",
            "color rotate 100 x 4",
            "endpoint 10.0.0.1 x 50",
            "path-id rotate 7 x 2",
            SR_LISTS,
            "preference range(100,104)",
            "priority 3",
            "community 65000:1 x 4",
            "as-path 65001",
            NULL,
        },
        .edits = {
            "color 100 x {1-4}",
            "color rotate 100 x {1-8}",
            "distinguisher rotate 1 x {1-6}",
            "distinguisher 1 x {1-5}",
            "endpoint rotate 10.0.0.1 x {1-6}",
            "endpoint 10.0.0.1 x {1-60}",
            "path-id 7 x {1-3}",
            "path-id rotate 1 x {1-4}",
            "no path-id",
            "community [65000:2,no-advertise]",
            "no community",
            "large-community 65551:{1-9}:1 x {1-4}",
            "no large-community",
            "preference {100-200}",
            "rotate-every {1-6}",
            "no rotate-every",
            "rotate-period 4",
            "no rotate-period",
            // rejected
            "color rotate",
            "endpoint rotate",
            "distinguisher rotate x",
            "path-id 1 rotate",
            "endpoint 10.0.0.1 x 0",
            "endpoint 10.0.0.1 junk",
            "color +1",
            "segment-list 3 weight 10 mpls 4294967297",
            NULL,
        },
    },
    {
        .name = "EVPN Type 2 dual stack",
        .base = {
            "rd rotate 65551:1 x 4",
            "mac 02:00:00:00:00:01 x 40",
            "ip rotate 172.20.0.1 x 40",
            "ip rotate 2001:db8:20::1 x 40",
            "label 40001 x 4",
            "label2 30001 x 4",
            "ethernet-tag rotate 100 x 4",
            "rt-set [65551:1,65551:1001] x 4",
            "next-hop 192.0.2.20",
            "rotate-every 2",
            "large-community 65551:9:1 x 4",
            "as-path 65001",
            NULL,
        },
        .edits = {
            "ethernet-tag 100 x {1-3}",
            "ethernet-tag rotate 100 x {1-6}",
            "no ethernet-tag",
            "ip 172.20.0.1 x {1-3}",
            "ip rotate 172.20.0.1 x {1-50}",
            "mac 02:00:00:00:00:01 x {1-60}",
            "rd 65551:1 x {1-3}",
            "rd rotate 65551:1 x {1-6}",
            "label 40001",
            "label 40001 x {1-6}",
            "esi 1",
            "no esi",
            "rt-set [65551:5]",
            "no rt-set; rt-set [65551:1,65551:1001] x {1-6}",
            "community 65000:{1-9} x 2",
            "no community",
            "rotate-every {1-4}",
            "no rotate-every",
            "rotate-period 4",
            "no rotate-period",
            // rejected
            "ethernet-tag rotate",
            "mac zz",
            "mac 02:00:00:00:00:01 x -1",
            "ip 172.20.0.1 junk",
            "ip 172.20.0.1 x 0",
            "esi +1",
            NULL,
        },
    },
    {
        .name = "EVPN Type 5",
        .base = {
            "prefix 172.16.0.0/24 x 60",
            "rd rotate 65551:5 x 6",
            "ethernet-tag rotate 0 x 6",
            "label rotate 30000 x 6",
            "encap vxlan",
            "router-mac 02:aa:bb:cc:dd:ee",
            "rt-set [65551:5] x 6",
            "next-hop 192.0.2.10",
            "community [65000:5,no-export]",
            "rotate-period 6",
            "as-path 65001",
            NULL,
        },
        .edits = {
            "ethernet-tag 0 x {1-3}",
            "ethernet-tag rotate 0 x {1-8}",
            "ethernet-tag rotate 0 x 6",
            "no ethernet-tag",
            "rd rotate 65551:5 x {1-8}",
            "rd rotate 65551:5 x 6",
            "rd 65551:5 x {1-2}",
            "label rotate 30000 x {1-8}",
            "label rotate 30000 x 6",
            "label 30000",
            "prefix 172.16.0.0/24 x {1-80}",
            "no rt-set; rt-set [65551:6] x {1-8}",
            "no rt-set; rt-set [65551:6] x 6",
            "community 65000:{1-9}",
            "no community",
            "router-mac 02:aa:bb:cc:dd:01",
            "rotate-every {1-10}",
            "no rotate-every",
            "rotate-period 6",
            "no rotate-period",
            // rejected
            "ethernet-tag rotate x 2",
            "rotate-period 0",
            "ethernet-tag 4294967296",
            "origin igp junk",
            "gateway-ip 10.9.9.1 x -1",
            NULL,
        },
    },
    {
        .name = "FlowSpec",
        .base = {
            "address-family ipv4 flowspec",
            "prefix 10.60.0.0/24 x 4",
            "protocol rotate each(6, 17)",
            "dst-port rotate 80 x 3",
            "src-port each(1, 2)",
            "action traffic-rate bytes 0",
            "action mark 0 x 4",
            "community 65000:7 x 2",
            "as-path 65001",
            NULL,
        },
        .edits = {
            "protocol each(6, 17)",
            "protocol rotate each(6, 17, 1)",
            "protocol 6",
            "dst-port 80 x {1-4}",
            "dst-port rotate 80 x {1-6}",
            "dst-port rotate each(80, 443)",
            "no dst-port",
            "src-port rotate each(1, 2)",
            "src-port each(1, 2, 3)",
            "dscp rotate 0 x {1-4}",
            "no dscp",
            "prefix 10.60.0.0/24 x {1-8}",
            "no action; action mark 0 x 4",
            "community [65000:7,no-export]",
            "no community",
            "rotate-every {1-4}",
            "no rotate-every",
            "rotate-period 2",
            "no rotate-period",
            // rejected
            "dst-port rotate",
            "protocol rotate each(6)",
            "action traffic-rate bytes +0",
            "action traffic-rate bytes 0x10",
            "dst-port +80",
            NULL,
        },
    },
    {
        .name = "unicast with path IDs",
        .base = {
            "prefix 100.64.0.0/24 x 200",
            "path-id rotate 1 x 4",
            "next-hop 192.0.2.2 x 4",
            "med range(1,10)",
            "localpref rand(500)",
            "community 65000:1 x 5",
            "large-community [65551:1:1,65551:2:2] x 2",
            "color 1 x 3",
            "as-path 65001",
            NULL,
        },
        .edits = {
            "path-id 1 x {1-4}",
            "path-id rotate 1 x {1-8}",
            "path-id rotate 1 x 4",
            "path-id rotate range(4,{4-9})",
            "no path-id",
            "prefix 100.64.0.0/24 x {1-300}",
            "next-hop 192.0.2.2 x {1-8}",
            "color rotate 1 x {1-4}",
            "color 1 x {1-4}",
            "no color",
            "community 65000:{1-9} x {1-5}",
            "no community; community 65000:1 x 5",
            "no community; community 65000:1 x 4",
            "large-community 65551:3:{1-9}",
            "no large-community",
            "localpref {1-900}",
            "rotate-every {1-10}",
            "no rotate-every",
            "rotate-period 4",
            "no rotate-period",
            // rejected
            "path-id rotate",
            "community 1:2:3",
            "path-id +1",
            "rotate-every +2",
            "as-path [rand(-1) x 2]",
            NULL,
        },
    },
};

/*
 * xorshift64: the same seed picks the same edits and numbers, so a failure reproduces with its CHURN_SEED.
 */
static uint64_t g_state;

static uint32_t churn_random(uint32_t bound) {
    g_state ^= g_state << 13;
    g_state ^= g_state >> 7;
    g_state ^= g_state << 17;
    return (uint32_t)(g_state % bound);
}

/*
 * Replace each "{a-b}" with a random number in [a, b].
 */
static void expand(const char *template, char *out, size_t size) {
    size_t used = 0;

    for (const char *p = template; *p && used + 1 < size;) {
        unsigned lo, hi;
        int consumed = 0;

        if (*p == '{' && sscanf(p, "{%u-%u}%n", &lo, &hi, &consumed) == 2 && consumed > 0 && hi >= lo) {
            used += (size_t)snprintf(out + used, size - used, "%u", lo + churn_random(hi - lo + 1));
            p += consumed;
        } else {
            out[used++] = *p++;
        }
    }
    out[used < size ? used : size - 1] = '\0';
}

/*
 * Apply one line ("keyword value" or "no keyword"); returns bgp_ribout_edit()'s result. keyword gets the keyword.
 */
static int apply_line(bgp_ribout_config_t *block, const char *line, char *keyword, size_t keyword_size) {
    int         clear = strncmp(line, "no ", 3) == 0;
    const char *text = clear ? line + 3 : line;
    const char *value = strchr(text, ' ');

    snprintf(keyword, keyword_size, "%.*s", value ? (int)(value - text) : (int)strlen(text), text);
    if (!clear && !value) {
        return -1;
    }
    return bgp_ribout_edit(block, keyword, clear ? "-" : value + 1, clear);
}

/*
 * Apply every line; 0 when all of them apply.
 */
static int apply_lines(bgp_ribout_config_t *block, const char *const *lines) {
    char keyword[32];

    for (; *lines; lines++) {
        if (apply_line(block, *lines, keyword, sizeof(keyword)) != 0) {
            return -1;
        }
    }
    return 0;
}

/*
 * Two UPDATE lists hold the same messages, byte for byte, in the same order.
 */
static int msgs_equal(const bgp_msg_t *a, const bgp_msg_t *b) {
    for (; a && b; a = a->next, b = b->next) {
        if (a->length != b->length || memcmp(a->data, b->data, a->length) != 0) {
            return 0;
        }
    }
    return a == NULL && b == NULL;
}

/*
 * A private copy of an UPDATE list: the block's own list goes with its next snapshot.
 */
static bgp_msg_t *msgs_copy(const bgp_msg_t *msgs) {
    bgp_msg_t *head = NULL, **tail = &head;

    for (; msgs; msgs = msgs->next) {
        bgp_msg_t *copy = calloc(1, sizeof(*copy));

        copy->data = malloc(msgs->length);
        memcpy(copy->data, msgs->data, msgs->length);
        copy->length = msgs->length;
        *tail = copy;
        tail = &copy->next;
    }
    return head;
}

static void msgs_free(bgp_msg_t *msgs) {
    while (msgs) {
        bgp_msg_t *next = msgs->next;

        free(msgs->data);
        free(msgs);
        msgs = next;
    }
}

/*
 * Paths that repeat a route key: plain lists that multiply the paths but are not part of the key (labels outside
 * EVPN Type 2, which rotates them; ESIs and gateway IPs of the prefix families).
 */
static uint64_t non_key_multiplier(const bgp_ribout_config_t *block, bgp_ribout_family_t family) {
    uint64_t m = 1;

    if (family == BGP_RIBOUT_FAMILY_EVPN_TYPE2 || family == BGP_RIBOUT_FAMILY_SR_POLICY_IPV4 ||
        family == BGP_RIBOUT_FAMILY_SR_POLICY_IPV6 || block->flowspec) {
        return 1;
    }
    if (!block->label_rotate && block->label_count > 1) {
        m *= block->label_count;
    }
    if (block->esi_count > 1) {
        m *= block->esi_count;
    }
    if (block->gateway_ip_spec.count > 1) {
        m *= block->gateway_ip_spec.count;
    }
    return m;
}

/*
 * Every path once on the wire, and the distinct keys the dimensions say.
 */
static int keys_check(const bgp_ribout_config_t *block, char *why, size_t why_size) {
    const bgp_tx_profile_t *p = &block->snapshot->profile;
    uint64_t                total = bgp_ribout_total_paths(block);
    uint64_t                m = non_key_multiplier(block, bgp_ribout_resolve_family(block));
    key_set_t               set;
    size_t                  nlri = 0;
    int                     ok;

    if (!route_key_set(block->messages, p->afi, p->safi, p->add_path, &set, &nlri)) {
        snprintf(why, why_size, "the UPDATEs do not decode");
        free(set.keys);
        return 0;
    }
    /*
     * With multipliers that are not keys, a rotating key list can still tell the copies of a key apart (rd rotate
     * and a plain label list: the copies of a prefix take different RDs), so the distinct keys are at least
     * total / m. With none, every path is a key of its own.
     */
    ok = nlri == total && (m == 1 ? set.count == total : set.count >= total / m && set.count <= total);
    snprintf(why, why_size, "%zu NLRIs, %zu distinct keys; total paths %llu, non-key multiplier %llu", nlri, set.count,
             (unsigned long long)total, (unsigned long long)m);
    free(set.keys);
    return ok;
}

/*
 * An output that drops everything: the config loader's messages for each round trip.
 */
static void discard_write(void *opaque, output_stream_t stream, const char *data, size_t len) {
    (void)opaque;
    (void)stream;
    (void)data;
    (void)len;
}

extern void cli_show_config(bgp_sim_t *sim);  /* The running-config printer, as test_cli_config uses it */

static void show_config_call(void *arg) {
    cli_show_config((bgp_sim_t *)arg);
}

/*
 * The running-config of sim, loaded into a new simulator, generates the same bytes as sim's block.
 */
static int roundtrip_check(bgp_sim_t *sim, char *why, size_t why_size) {
    static char text[1 << 17];
    static const output_t silent = {discard_write, NULL};
    char path[] = "/tmp/bgpsim-churn-XXXXXX";
    bgp_sim_t loaded;
    int fd, ok = 0;

    if (test_capture_output(show_config_call, sim, text, sizeof(text), NULL, 0) < 0 || (fd = mkstemp(path)) < 0) {
        snprintf(why, why_size, "running-config not captured");
        return 0;
    }
    ok = write(fd, text, strlen(text)) == (ssize_t)strlen(text);
    close(fd);
    bgp_init_simulator(&loaded);
    ok = ok && parse_config_file_with_output(path, &loaded, &silent) >= 0 && loaded.ribout_count == 1 &&
         bgp_ribout_generate(loaded.ribouts[0]) == BGP_RIBOUT_GENERATED &&
         msgs_equal(loaded.ribouts[0]->messages, sim->ribouts[0]->messages);
    if (!ok) {
        snprintf(why, why_size, "running-config does not load back to the same UPDATEs:\n%s", text);
    }
    bgp_shutdown_sim(&loaded);
    unlink(path);
    return ok;
}

/*
 * keyword is among the first count entries of seen.
 */
static int seen_keyword(char seen[][32], int count, const char *keyword) {
    for (int i = 0; i < count; i++) {
        if (strcmp(seen[i], keyword) == 0) {
            return 1;
        }
    }
    return 0;
}

/*
 * One case: the base generates (and round-trips); then rounds random edits, each checked as the file comment says;
 * then every touched keyword is cleared and its base lines applied again, in base order, and the UPDATEs must be the
 * original ones.
 */
static void churn(const churn_case_t *cc, uint64_t seed, int rounds) {
    static char why[1 << 17];
    char title[3][160];
    char touched[64][32];
    int                    touched_count = 0, rejected = 0, generated = 0, failed_generates = 0;
    bgp_sim_t              sim;
    bgp_ribout_config_t   *block;
    bgp_ribout_config_t    fresh;
    bgp_ribout_snapshot_t *original_snapshot;
    bgp_msg_t             *original;
    int                    edits = 0;

    while (cc->edits[edits]) {
        edits++;
    }
    g_state = seed ? seed : 1;
    snprintf(title[0], sizeof(title[0]), "%s: base configuration generates", cc->name);
    TEST(title[0]);
    bgp_init_simulator(&sim);
    block = bgp_sim_add_ribout(&sim, "churn");
    ASSERT(block != NULL, "ribout allocation succeeds");
    ASSERT(apply_lines(block, cc->base) == 0 && bgp_ribout_generate(block) == BGP_RIBOUT_GENERATED, title[0]);
    ASSERT(keys_check(block, why, sizeof(why)), why);
    ASSERT(roundtrip_check(&sim, why, sizeof(why)), why);
    original = msgs_copy(block->messages);
    original_snapshot = bgp_ribout_snapshot_ref(block->snapshot);
    PASS();

    snprintf(title[1], sizeof(title[1]), "%s: %d edits keep every generated state sound", cc->name, rounds);
    TEST(title[1]);
    for (int round = 0; round < rounds; round++) {
        char edit[256], line[256], keyword[32];
        char *save = NULL;
        static uint8_t before[sizeof(bgp_ribout_config_t)];
        bgp_ribout_flowspec_t before_fs;
        int                   ok = 1;

        expand(cc->edits[churn_random((uint32_t)edits)], edit, sizeof(edit));
        for (char *part = strtok_r(edit, ";", &save); part; part = strtok_r(NULL, ";", &save)) {
            while (*part == ' ') {
                part++;
            }
            snprintf(line, sizeof(line), "%s", part);
            memcpy(before, block, BGP_RIBOUT_CONFIG_SIZE);
            if (block->flowspec) {
                before_fs = *block->flowspec;
            }
            if (apply_line(block, line, keyword, sizeof(keyword)) != 0) {
                // A rejected edit changes nothing (bgp_ribout_edit() works on a copy).
                snprintf(why, sizeof(why), "%s round %d: rejected \"%s\" changed the configuration", cc->name, round,
                         line);
                ASSERT(memcmp(before, block, BGP_RIBOUT_CONFIG_SIZE) == 0 &&
                       (!block->flowspec || memcmp(&before_fs, block->flowspec, sizeof(before_fs)) == 0),
                       why);
                rejected++;
                ok = 0;
                break;
            }
            if (!seen_keyword(touched, touched_count, keyword) && touched_count < 64) {
                snprintf(touched[touched_count++], sizeof(touched[0]), "%s", keyword);
            }
        }
        if (!ok) {
            continue;
        }
        if (bgp_ribout_generate(block) != BGP_RIBOUT_GENERATED) {
            failed_generates++;  /* rotate-period mismatches, too many paths, ...: the old snapshot stays */
            continue;
        }
        generated++;
        if (!keys_check(block, line, sizeof(line))) {
            snprintf(why, sizeof(why), "%s round %d after \"%s\": %s", cc->name, round, edit, line);
            ASSERT(0, why);
        }
        if (!roundtrip_check(&sim, why, sizeof(why))) {
            ASSERT(0, why);
        }
    }
    printf("  (%s: %d generated, %d rejected edits, %d configurations that do not generate, %d keywords touched)\n",
           cc->name, generated, rejected, failed_generates, touched_count);
    ASSERT(generated >= rounds / 10 && rejected > 0, "the edits both generate and get rejected");
    PASS();

    snprintf(title[2], sizeof(title[2]), "%s: reverting every edited keyword gives the original UPDATEs", cc->name);
    TEST(title[2]);
    for (int i = 0; i < touched_count; i++) {
        char keyword[32], clear[48];

        snprintf(clear, sizeof(clear), "no %.*s", (int)sizeof(touched[i]) - 1, touched[i]);
        ASSERT(apply_line(block, clear, keyword, sizeof(keyword)) == 0, clear);
    }
    for (const char *const *base = cc->base; *base; base++) {
        char        keyword[32];
        const char *space = strchr(*base, ' ');

        snprintf(keyword, sizeof(keyword), "%.*s", (int)(space - *base), *base);
        if (seen_keyword(touched, touched_count, keyword)) {
            ASSERT(apply_line(block, *base, keyword, sizeof(keyword)) == 0, *base);
        }
    }
    ASSERT(bgp_ribout_generate(block) == BGP_RIBOUT_GENERATED, "the reverted configuration generates");
    ASSERT(msgs_equal(block->messages, original), "byte for byte the original UPDATEs");
    ASSERT(bgp_ribout_snapshot_same_keys(original_snapshot, block->snapshot), "the original keyspace");
    ASSERT(block->snapshot->id != original_snapshot->id, "a new snapshot");
    bgp_ribout_init(&fresh, "churn");
    ASSERT(apply_lines(&fresh, cc->base) == 0 &&
           bgp_ribout_generate(&fresh) == BGP_RIBOUT_GENERATED &&
           msgs_equal(fresh.messages, original),
           "a block built fresh from the base lines generates them too");
    bgp_ribout_destroy(&fresh);
    bgp_ribout_snapshot_unref(original_snapshot);
    msgs_free(original);
    bgp_shutdown_sim(&sim);
    PASS();
}

int main(void) {
    const char *seed_text = getenv("CHURN_SEED"), *rounds_text = getenv("CHURN_ROUNDS");
    uint64_t    seed = seed_text ? strtoull(seed_text, NULL, 0) : 0x5eed2026u;
    int         rounds = rounds_text ? atoi(rounds_text) : 150;
    int         quiet = open("/dev/null", O_WRONLY);

    // Rejected edits and configurations that do not generate print their errors: keep them off the test output.
    if (quiet >= 0 && !getenv("CHURN_VERBOSE")) {
        dup2(quiet, STDERR_FILENO);
    }
    printf("ribout churn: seed 0x%llx, %d edits per case\n", (unsigned long long)seed, rounds);
    for (size_t i = 0; i < sizeof(k_cases) / sizeof(k_cases[0]); i++) {
        churn(&k_cases[i], seed + i, rounds);
    }
    printf("\nTests run: %d, passed: %d, failed: %d\n", tests_run, tests_passed, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
