/*
 * Withdrawal and End-of-RIB streams derived from snapshot bytes. Expected bytes are assembled here by hand and the
 * generated streams are read back with the independent readers in test_wire.h, never with the production encoders.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "test_case.h"
#include "test_wire.h"
#include "bgp_ribout.h"
#include "bgp_ribout_snapshot.h"

// Test-side UPDATE assembly

static size_t put_attr(uint8_t *at, uint8_t flags, uint8_t type, const uint8_t *value, size_t len) {
    size_t off = 0;

    if (len > 255) {
        flags |= 0x10;
    }
    at[off++] = flags;
    at[off++] = type;
    if (flags & 0x10) {
        at[off++] = (uint8_t)(len >> 8);
    }
    at[off++] = (uint8_t)len;
    memcpy(at + off, value, len);
    return off + len;
}

/*
 * An UPDATE with withdrawn routes, attributes and classic NLRI; returns its length.
 */
static size_t make_update(uint8_t *m, const uint8_t *withdrawn, size_t withdrawn_len, const uint8_t *attrs,
                          size_t attrs_len, const uint8_t *nlri, size_t nlri_len) {
    size_t off = 19, total = 19 + 2 + withdrawn_len + 2 + attrs_len + nlri_len;

    memset(m, 0xff, 16);
    m[16] = (uint8_t)(total >> 8);
    m[17] = (uint8_t)total;
    m[18] = 2;
    m[off++] = (uint8_t)(withdrawn_len >> 8);
    m[off++] = (uint8_t)withdrawn_len;
    if (withdrawn_len > 0) {
        memcpy(m + off, withdrawn, withdrawn_len);
    }
    off += withdrawn_len;
    m[off++] = (uint8_t)(attrs_len >> 8);
    m[off++] = (uint8_t)attrs_len;
    if (attrs_len > 0) {
        memcpy(m + off, attrs, attrs_len);
    }
    off += attrs_len;
    if (nlri_len > 0) {
        memcpy(m + off, nlri, nlri_len);
    }
    return total;
}

static const uint8_t k_origin[] = {0x40, 0x01, 0x01, 0x00};
static const uint8_t k_empty_as_path[] = {0x40, 0x02, 0x00};

/*
 * ORIGIN, AS_PATH and MP_REACH_NLRI carrying nlri with a 4-octet next hop.
 */
static size_t make_mp_reach(uint8_t *m, uint16_t afi, uint8_t safi, const uint8_t *nlri, size_t nlri_len) {
    uint8_t attrs[4200], value[4200];
    size_t off = 0, v = 0;

    memcpy(attrs + off, k_origin, sizeof(k_origin));
    off += sizeof(k_origin);
    memcpy(attrs + off, k_empty_as_path, sizeof(k_empty_as_path));
    off += sizeof(k_empty_as_path);
    value[v++] = (uint8_t)(afi >> 8);
    value[v++] = (uint8_t)afi;
    value[v++] = safi;
    value[v++] = 4;
    value[v++] = 192;
    value[v++] = 0;
    value[v++] = 2;
    value[v++] = 1;
    value[v++] = 0;
    memcpy(value + v, nlri, nlri_len);
    off += put_attr(attrs + off, 0x80, 14, value, v + nlri_len);
    return make_update(m, NULL, 0, attrs, off, NULL, 0);
}

static size_t make_mp_unreach(uint8_t *m, uint16_t afi, uint8_t safi, const uint8_t *nlri, size_t nlri_len) {
    uint8_t attrs[4200], value[4200];
    size_t v = 0;

    value[v++] = (uint8_t)(afi >> 8);
    value[v++] = (uint8_t)afi;
    value[v++] = safi;
    memcpy(value + v, nlri, nlri_len);
    return make_update(m, NULL, 0, attrs, put_attr(attrs, 0x80, 15, value, v + nlri_len), NULL, 0);
}

static size_t make_classic_reach(uint8_t *m, const uint8_t *nlri, size_t nlri_len) {
    static const uint8_t attrs[] = {0x40, 0x01, 0x01, 0x00, 0x40, 0x02, 0x00, 0x40, 0x03, 0x04, 192, 0, 2, 1};
    return make_update(m, NULL, 0, attrs, sizeof(attrs), nlri, nlri_len);
}

/*
 * A message list from raw UPDATEs; the stream frees it.
 */
static bgp_msg_t *msg_list(const uint8_t *const *data, const size_t *lens, size_t count, uint64_t *bytes) {
    bgp_msg_t *head = NULL, **tail = &head;

    *bytes = 0;
    for (size_t i = 0; i < count; i++) {
        bgp_msg_t *msg = malloc(sizeof(*msg));

        msg->data = malloc(lens[i]);
        memcpy(msg->data, data[i], lens[i]);
        msg->length = (uint16_t)lens[i];
        msg->next = NULL;
        *bytes += lens[i];
        *tail = msg;
        tail = &msg->next;
    }
    return head;
}

/*
 * A snapshot of the given raw advertisements and profile.
 */
static bgp_ribout_snapshot_t *raw_snapshot(bgp_ribout_config_t *block, bgp_tx_profile_t profile,
                                           const uint8_t *const *data, const size_t *lens, size_t count) {
    uint64_t   bytes;
    bgp_msg_t *msgs = msg_list(data, lens, count, &bytes);

    bgp_ribout_init(block, "raw");
    return bgp_ribout_snapshot_create(block, &profile, msgs, count, bytes);
}

// Literal vectors

typedef struct {
    const char      *name;
    bgp_tx_profile_t profile;
    const uint8_t   *nlri;      /* Advertised NLRI field */
    size_t           nlri_len;
    const uint8_t   *expected;  /* Withdrawn NLRI field  */
} literal_case_t;

static const uint8_t ipv4_nlri[] = {0x10, 10, 1, 0x18, 192, 0, 2};
static const uint8_t ipv4_ap_nlri[] = {0, 0, 0, 1, 0x18, 192, 0, 2, 0, 0, 0, 2, 0x18, 192, 0, 2};
static const uint8_t ipv6_nlri[] = {0x20, 0x20, 0x01, 0x0d, 0xb8, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0};
/*
 * 48 bits: label 1000 (0x003e81 with bottom of stack), 10.0.0/24; then label 16 (0x000101), 10.0.1/24
 */
static const uint8_t lu4_nlri[] = {0x30, 0x00, 0x3e, 0x81, 10, 0, 0, 0x30, 0x00, 0x01, 0x01, 10, 0, 1};
static const uint8_t lu4_withdrawn[] = {0x30, 0x80, 0x00, 0x00, 10, 0, 0, 0x30, 0x80, 0x00, 0x00, 10, 0, 1};
/*
 * Path ID 9, 136 bits: label, RD 65000:1, 2001:db8:1::/48
 */
static const uint8_t vpn6_ap_nlri[] = {0, 0, 0, 9, 0x88, 0x01, 0x86, 0xa1, 0, 0, 0xfd, 0xe8, 0, 0, 0, 1,
                                       0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01};
static const uint8_t vpn6_ap_withdrawn[] = {0, 0, 0, 9, 0x88, 0x80, 0x00, 0x00, 0, 0, 0xfd, 0xe8, 0, 0, 0, 1,
                                            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01};
/*
 * EVPN Type 2: RD, ESI, Ethernet tag, MAC, no IP, one label (33 octets)
 */
static const uint8_t evpn2_nlri[] = {2, 33, 0, 0, 0xfd, 0xe8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                     0, 0, 0, 5, 48, 0, 0x11, 0x22, 0x33, 0x44, 0x55, 0, 0x01, 0xf4, 0x01};
/*
 * SR Policy IPv4, 96 bits: distinguisher 1, color 100, endpoint 10.0.0.1
 */
static const uint8_t sr4_nlri[] = {96, 0, 0, 0, 1, 0, 0, 0, 100, 10, 0, 0, 1};
/*
 * FlowSpec: destination 10.0.0.0/24, protocol 6
 */
static const uint8_t fs4_nlri[] = {0x08, 0x01, 0x18, 10, 0, 0, 0x03, 0x81, 0x06};

static const literal_case_t k_literals[] = {
    {"classic IPv4", {.afi = 1, .safi = 1, .family = BGP_RIBOUT_FAMILY_IPV4_UNICAST, .classic = 1,
                      .next_hop_af = AF_INET}, ipv4_nlri, sizeof(ipv4_nlri), ipv4_nlri},
    {"classic IPv4 Add-Path", {.afi = 1, .safi = 1, .family = BGP_RIBOUT_FAMILY_IPV4_UNICAST, .classic = 1,
                               .add_path = 1, .next_hop_af = AF_INET},
     ipv4_ap_nlri, sizeof(ipv4_ap_nlri), ipv4_ap_nlri},
    {"IPv6", {.afi = 2, .safi = 1, .family = BGP_RIBOUT_FAMILY_IPV6_UNICAST, .next_hop_af = AF_INET6},
     ipv6_nlri, sizeof(ipv6_nlri), ipv6_nlri},
    {"IPv4 labeled-unicast", {.afi = 1, .safi = 4, .family = BGP_RIBOUT_FAMILY_LABELED_IPV4,
                              .next_hop_af = AF_INET}, lu4_nlri, sizeof(lu4_nlri), lu4_withdrawn},
    {"VPNv6 Add-Path", {.afi = 2, .safi = 128, .family = BGP_RIBOUT_FAMILY_VPNV6, .add_path = 1,
                        .next_hop_af = AF_INET}, vpn6_ap_nlri, sizeof(vpn6_ap_nlri), vpn6_ap_withdrawn},
    {"EVPN Type 2", {.afi = 25, .safi = 70, .family = BGP_RIBOUT_FAMILY_EVPN_TYPE2, .next_hop_af = AF_INET},
     evpn2_nlri, sizeof(evpn2_nlri), evpn2_nlri},
    {"SR Policy IPv4", {.afi = 1, .safi = 73, .family = BGP_RIBOUT_FAMILY_SR_POLICY_IPV4, .next_hop_af = AF_INET},
     sr4_nlri, sizeof(sr4_nlri), sr4_nlri},
    {"IPv4 FlowSpec", {.afi = 1, .safi = 133, .family = BGP_RIBOUT_FAMILY_FLOWSPEC_IPV4},
     fs4_nlri, sizeof(fs4_nlri), fs4_nlri},
};

static void test_literal_vectors(void) {
    TEST("Withdrawals of literal advertisements match hand-built bytes per family");
    for (size_t i = 0; i < sizeof(k_literals) / sizeof(k_literals[0]); i++) {
        const literal_case_t *lc = &k_literals[i];
        uint8_t adv[4096], expected[4096];
        size_t adv_len, expected_len;
        const uint8_t         *data[1] = {adv};
        bgp_ribout_config_t    block;
        bgp_ribout_snapshot_t *snapshot;
        bgp_msg_stream_t      *wd;

        if (lc->profile.classic) {
            adv_len = make_classic_reach(adv, lc->nlri, lc->nlri_len);
            expected_len = make_update(expected, lc->expected, lc->nlri_len, NULL, 0, NULL, 0);
        } else {
            adv_len = make_mp_reach(adv, lc->profile.afi, lc->profile.safi, lc->nlri, lc->nlri_len);
            expected_len = make_mp_unreach(expected, lc->profile.afi, lc->profile.safi, lc->expected, lc->nlri_len);
        }
        snapshot = raw_snapshot(&block, lc->profile, data, &adv_len, 1);
        ASSERT(snapshot, lc->name);
        wd = bgp_ribout_snapshot_withdrawal(snapshot);
        ASSERT(wd && wd->count == 1 && wd->bytes == expected_len, lc->name);
        ASSERT(wd->msgs->length == expected_len && memcmp(wd->msgs->data, expected, expected_len) == 0, lc->name);
        bgp_msg_stream_unref(wd);
        bgp_ribout_snapshot_unref(snapshot);
        bgp_ribout_destroy(&block);
    }
    PASS();
}

static void test_long_flowspec_and_split(void) {
    /*
     * Two FlowSpec NLRI with a two-octet length (0xf100: 256 octets of components), and enough of them that the
     * withdrawal needs a second UPDATE.
     */
    enum { RULES = 20, RULE_LEN = 2 + 256 };
    static uint8_t nlri[RULES][RULE_LEN];
    uint8_t adv[RULES][4096];
    size_t                 lens[RULES];
    const uint8_t         *data[RULES];
    bgp_tx_profile_t       profile = {.afi = 2, .safi = 133, .family = BGP_RIBOUT_FAMILY_FLOWSPEC_IPV6};
    bgp_ribout_config_t    block;
    bgp_ribout_snapshot_t *snapshot;
    bgp_msg_stream_t      *wd;
    size_t                 total = 0, rules = 0;

    TEST("Two-octet FlowSpec lengths survive and withdrawals split at 4096 octets");
    for (int i = 0; i < RULES; i++) {
        nlri[i][0] = 0xf1;
        nlri[i][1] = 0x00;
        memset(nlri[i] + 2, i + 1, 256);
        lens[i] = make_mp_reach(adv[i], 2, 133, nlri[i], RULE_LEN);
        data[i] = adv[i];
    }
    snapshot = raw_snapshot(&block, profile, data, lens, RULES);
    wd = bgp_ribout_snapshot_withdrawal(snapshot);
    ASSERT(wd && wd->count == 2, "20 rules of 258 octets need two withdrawal UPDATEs");
    for (const bgp_msg_t *msg = wd->msgs; msg; msg = msg->next) {
        test_wire_update_t view;

        ASSERT(test_wire_update_view(msg->data, msg->length, &view) && view.has_unreach && view.attr_count == 1,
               "MP_UNREACH_NLRI only");
        for (size_t off = 0; off < view.unreach_len; rules++) {
            size_t size = test_wire_nlri_size(2, 133, 0, view.unreach + off, view.unreach_len - off);

            ASSERT(size == RULE_LEN && memcmp(view.unreach + off, nlri[rules], RULE_LEN) == 0, "rule bytes kept");
            off += size;
        }
        total += msg->length;
    }
    ASSERT(rules == RULES && total == wd->bytes, "every rule withdrawn once");
    bgp_msg_stream_unref(wd);
    bgp_ribout_snapshot_unref(snapshot);
    bgp_ribout_destroy(&block);
    PASS();
}

// Generated ribouts at scale

typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
    size_t   keys;
} key_list_t;

static int key_append(key_list_t *list, const uint8_t *key, size_t len) {
    if (list->len + len + 2 > list->cap) {
        size_t   cap = list->cap ? list->cap * 2 : 65536;
        uint8_t *data;

        while (cap < list->len + len + 2) {
            cap *= 2;
        }
        data = realloc(list->data, cap);
        if (!data) {
            return 0;
        }
        list->data = data;
        list->cap = cap;
    }
    list->data[list->len++] = (uint8_t)(len >> 8);
    list->data[list->len++] = (uint8_t)len;
    memcpy(list->data + list->len, key, len);
    list->len += len;
    list->keys++;
    return 1;
}

static int is_labeled(uint8_t safi) {
    return safi == 4 || safi == 128;
}

/*
 * Append every NLRI of region as a key; labels are masked to 0x800000 in advertised keys (want_compat 0) and must
 * already be 0x800000 in withdrawn keys (want_compat 1).
 */
static int collect_keys(key_list_t *keys, uint16_t afi, uint8_t safi, int add_path, const uint8_t *region,
                        size_t len, int want_compat) {
    size_t id = add_path ? 4 : 0;

    for (size_t off = 0; off < len;) {
        uint8_t key[4096];
        size_t  size = test_wire_nlri_size(afi, safi, add_path, region + off, len - off);

        if (size == 0) {
            return 0;
        }
        memcpy(key, region + off, size);
        if (is_labeled(safi)) {
            if (want_compat && (key[id + 1] != 0x80 || key[id + 2] != 0 || key[id + 3] != 0)) {
                return 0;
            }
            key[id + 1] = 0x80;
            key[id + 2] = 0;
            key[id + 3] = 0;
        }
        if (!key_append(keys, key, size)) {
            return 0;
        }
        off += size;
    }
    return 1;
}

typedef struct {
    const char       *name;
    const char *const lines[10];
} scale_case_t;

#define AS_PATH  "as-path 65010 65020 65030"
#define SR_LINES "segment-list 1 weight 10 mpls 16001 16002", "rt 192.0.2.1:100", AS_PATH

static const scale_case_t k_scale[] = {
    {
        .name = "ipv4",
        .lines = {
            "prefix 10.0.0.0/24 x 20000",
            "next-hop 192.0.2.1",
            AS_PATH,
            "localpref range(100,3999)",
            NULL,
        },
    },
    {
        .name = "ipv4-addpath",
        .lines = {
            "prefix 10.0.0.0/24 x 10000",
            "path-id 1 2",
            "next-hop 192.0.2.1",
            AS_PATH,
            "localpref range(100,3999)",
            NULL,
        },
    },
    {
        .name = "ipv4-v6nh",
        .lines = {
            "prefix 10.0.0.0/24 x 20000",
            "next-hop 2001:db8::1",
            AS_PATH,
            "localpref range(100,3999)",
            NULL,
        },
    },
    {
        .name = "ipv6",
        .lines = {
            "prefix 2001:db8::/64 x 20000",
            "next-hop 2001:db8::1",
            AS_PATH,
            "localpref range(100,3999)",
            NULL,
        },
    },
    {
        .name = "lu4-dup-labels",
        .lines = {
            "prefix 10.0.0.0/24 x 10000",
            "label 100 101",
            "next-hop 192.0.2.1",
            AS_PATH,
            "localpref range(100,3999)",
            NULL,
        },
    },
    {
        .name = "lu6",
        .lines = {
            "prefix 2001:db8::/64 x 20000",
            "label 200",
            "next-hop 2001:db8::1",
            AS_PATH,
            "localpref range(100,3999)",
            NULL,
        },
    },
    {
        .name = "vpn4-addpath",
        .lines = {
            "prefix 10.0.0.0/24 x 2500",
            "rd 65000:1 x 4",
            "label 300",
            "path-id 1 2",
            "next-hop 192.0.2.1",
            "rt 65000:1",
            AS_PATH,
            "localpref range(100,3999)",
            NULL,
        },
    },
    {
        .name = "vpn6",
        .lines = {
            "prefix 2001:db8::/48 x 5000",
            "rd 65000:1 x 4",
            "label 300",
            "next-hop 192.0.2.1",
            "rt 65000:1",
            AS_PATH,
            "localpref range(100,3999)",
            NULL,
        },
    },
    {
        .name = "evpn5-v4",
        .lines = {
            "prefix 10.0.0.0/24 x 5000",
            "rd 65000:1 x 4",
            "label 400",
            "ethernet-tag 0",
            "next-hop 192.0.2.1",
            "rt 65000:1",
            AS_PATH,
            "localpref range(100,3999)",
            NULL,
        },
    },
    {
        .name = "evpn5-v6",
        .lines = {
            "prefix 2001:db8::/64 x 5000",
            "rd 65000:1 x 4",
            "label 400",
            "ethernet-tag 0",
            "next-hop 192.0.2.1",
            "rt 65000:1",
            AS_PATH,
            "localpref range(100,3999)",
            NULL,
        },
    },
    {
        .name = "evpn2-addpath",
        .lines = {
            "rd 65000:1 x 4",
            "mac 00:11:22:00:00:00 x 2500",
            "path-id 3 4",
            "label 500",
            "next-hop 192.0.2.1",
            "rt 65000:1",
            AS_PATH,
            "localpref range(100,3999)",
            NULL,
        },
    },
    {
        .name = "sr4",
        .lines = {
            "distinguisher 1 x 4",
            "color 100 x 16",
            "endpoint 10.0.0.1 x 320",
            SR_LINES,
            "localpref range(100,3999)",
            NULL,
        },
    },
    {
        .name = "sr6-addpath",
        .lines = {
            "distinguisher 1 x 4",
            "color 100 x 16",
            "endpoint 2001:db8::1 x 160",
            "path-id 1 2",
            SR_LINES,
            "localpref range(100,3999)",
            NULL,
        },
    },
    {
        .name = "fs4",
        .lines = {
            "address-family ipv4 flowspec",
            "prefix 10.0.0.0/24 x 160",
            "protocol 6",
            "dst-port 1 x 128",
            AS_PATH,
            "localpref range(100,3999)",
            NULL,
        },
    },
    {
        .name = "fs6-addpath",
        .lines = {
            "address-family ipv6 flowspec",
            "prefix 2001:db8::/64 x 80",
            "dst-port 1 x 128",
            "path-id 1 2",
            AS_PATH,
            "localpref range(100,3999)",
            NULL,
        },
    },
    {
        .name = "fsvpn4",
        .lines = {
            "address-family ipv4 flowspec-vpn",
            "prefix 10.0.0.0/24 x 80",
            "rd 65000:1 x 2",
            "dst-port 1 x 128",
            AS_PATH,
            "localpref range(100,3999)",
            NULL,
        },
    },
    {
        .name = "fsvpn6",
        .lines = {
            "address-family ipv6 flowspec-vpn",
            "prefix 2001:db8::/64 x 80",
            "rd 65000:1 x 2",
            "dst-port 1 x 128",
            AS_PATH,
            "localpref range(100,3999)",
            NULL,
        },
    },
};

static int configure(bgp_ribout_config_t *block, const char *name, const char *const *lines) {
    if (bgp_ribout_init(block, name) != 0) {
        return 0;
    }
    for (; *lines; lines++) {
        char        keyword[32];
        const char *value = strchr(*lines, ' ');

        snprintf(keyword, sizeof(keyword), "%.*s", (int)(value - *lines), *lines);
        if (bgp_ribout_edit(block, keyword, value + 1, 0) != 0) {
            return 0;
        }
    }
    return 1;
}

static void test_generated_families(void) {
    char why[160];

    TEST("Generated ribouts: withdrawn keys equal advertised keys in order, packed greedily");
    for (size_t i = 0; i < sizeof(k_scale) / sizeof(k_scale[0]); i++) {
        const scale_case_t *sc = &k_scale[i];
        bgp_ribout_config_t block;
        bgp_tx_profile_t    p;
        bgp_msg_stream_t   *wd;
        key_list_t          adv_keys = {0}, wd_keys = {0};
        int                 ok = 1;

        snprintf(why, sizeof(why), "%s: configure and generate", sc->name);
        ASSERT(configure(&block, sc->name, sc->lines), why);
        ASSERT(bgp_ribout_generate(&block) == BGP_RIBOUT_GENERATED, why);
        p = block.snapshot->profile;

        for (const bgp_msg_t *msg = block.messages; msg && ok; msg = msg->next) {
            test_wire_update_t view;

            ok = test_wire_update_view(msg->data, msg->length, &view);
            ok = ok && (p.classic ? collect_keys(&adv_keys, p.afi, p.safi, p.add_path, view.nlri, view.nlri_len, 0)
                                  : view.has_reach && collect_keys(&adv_keys, p.afi, p.safi, p.add_path, view.reach,
                                                                   view.reach_len, 0));
        }
        snprintf(why, sizeof(why), "%s: advertisement keys", sc->name);
        ASSERT(ok && adv_keys.keys == bgp_ribout_total_paths(&block), why);

        wd = bgp_ribout_snapshot_withdrawal(block.snapshot);
        snprintf(why, sizeof(why), "%s: withdrawal stream", sc->name);
        ASSERT(wd && wd->count > 0, why);
        for (const bgp_msg_t *msg = wd->msgs; msg && ok; msg = msg->next) {
            test_wire_update_t view, next;

            ok = test_wire_update_view(msg->data, msg->length, &view);
            if (p.classic) {
                ok = ok && view.attr_count == 0 && view.nlri_len == 0 && view.withdrawn_len > 0 &&
                     collect_keys(&wd_keys, p.afi, p.safi, p.add_path, view.withdrawn, view.withdrawn_len, 1);
            } else {
                ok = ok && view.attr_count == 1 && view.has_unreach && view.unreach_afi == p.afi &&
                     view.unreach_safi == p.safi && view.withdrawn_len == 0 && view.nlri_len == 0 &&
                     collect_keys(&wd_keys, p.afi, p.safi, p.add_path, view.unreach, view.unreach_len, 1);
            }
            // Greedy: the first NLRI of the next UPDATE would not have fit in this one.
            if (ok && msg->next) {
                const uint8_t *first;
                size_t         first_len;

                ok = test_wire_update_view(msg->next->data, msg->next->length, &next);
                first = p.classic ? next.withdrawn : next.unreach;
                first_len = p.classic ? next.withdrawn_len : next.unreach_len;
                ok = ok && msg->length + test_wire_nlri_size(p.afi, p.safi, p.add_path, first, first_len) > 4096;
            }
        }
        snprintf(why, sizeof(why), "%s: withdrawal framing, labels or packing", sc->name);
        ASSERT(ok, why);
        snprintf(why, sizeof(why), "%s: %zu advertised keys, %zu withdrawn", sc->name, adv_keys.keys, wd_keys.keys);
        ASSERT(adv_keys.len == wd_keys.len && memcmp(adv_keys.data, wd_keys.data, adv_keys.len) == 0, why);

        free(adv_keys.data);
        free(wd_keys.data);
        bgp_msg_stream_unref(wd);
        bgp_ribout_destroy(&block);
    }
    PASS();
}

// Sharing and End-of-RIB

static void test_withdrawal_cache(void) {
    static const char *const lines[] = {"prefix 10.0.0.0/24 x 50", "next-hop 192.0.2.1", AS_PATH, NULL};
    bgp_ribout_config_t    block;
    bgp_ribout_snapshot_t *snapshot;
    bgp_msg_stream_t *first, *second;

    TEST("Withdrawals of one snapshot are shared while held and outlive the snapshot");
    ASSERT(configure(&block, "cache", lines) && bgp_ribout_generate(&block) == BGP_RIBOUT_GENERATED, "generate");
    snapshot = block.snapshot;
    first = bgp_ribout_snapshot_withdrawal(snapshot);
    second = bgp_ribout_snapshot_withdrawal(snapshot);
    ASSERT(first && first == second && first->refs == 2 && snapshot->withdrawal == first, "one shared stream");
    bgp_msg_stream_unref(second);
    bgp_msg_stream_unref(first);
    ASSERT(snapshot->withdrawal == NULL, "the cache is cleared with the last holder");

    first = bgp_ribout_snapshot_withdrawal(snapshot);
    ASSERT(first && snapshot->withdrawal == first, "derived again on demand");
    bgp_ribout_destroy(&block);
    ASSERT(first->weak_slot == NULL && first->count > 0, "the stream outlives its snapshot");
    bgp_msg_stream_unref(first);
    PASS();
}

static void test_eor(void) {
    static const uint8_t ipv4[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x17, 0x02, 0, 0, 0, 0};
    static const uint8_t vpnv4[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x1d, 0x02, 0, 0, 0, 6,
                                    0x80, 0x0f, 0x03, 0x00, 0x01, 0x80};
    static const bgp_afi_safi_t families[] = {{1, 1}, {1, 128}};
    bgp_msg_stream_t *eor;

    TEST("End-of-RIB: empty UPDATE for IPv4 unicast, empty MP_UNREACH_NLRI otherwise");
    eor = bgp_msg_stream_eor(families, 2);
    ASSERT(eor && eor->count == 2 && eor->bytes == sizeof(ipv4) + sizeof(vpnv4), "two markers");
    ASSERT(eor->msgs->length == sizeof(ipv4) && memcmp(eor->msgs->data, ipv4, sizeof(ipv4)) == 0, "IPv4 marker");
    ASSERT(eor->msgs->next->length == sizeof(vpnv4) &&
           memcmp(eor->msgs->next->data, vpnv4, sizeof(vpnv4)) == 0, "VPNv4 marker");
    bgp_msg_stream_unref(eor);
    PASS();
}

static void test_malformed_advertisement(void) {
    uint8_t                adv[64];
    size_t                 len = make_classic_reach(adv, ipv4_nlri, sizeof(ipv4_nlri));
    const uint8_t         *data[1] = {adv};
    bgp_tx_profile_t       profile = {.afi = 1, .safi = 1, .family = BGP_RIBOUT_FAMILY_IPV4_UNICAST, .classic = 1};
    bgp_ribout_config_t    block;
    bgp_ribout_snapshot_t *snapshot;

    TEST("A truncated NLRI fails the derivation and leaves no cache");
    adv[len - 4] = 0x20;  /* The last prefix, 192.0.2.0/24, claims /32: its bytes run past the message */
    snapshot = raw_snapshot(&block, profile, data, &len, 1);
    ASSERT(snapshot && bgp_ribout_snapshot_withdrawal(snapshot) == NULL && snapshot->withdrawal == NULL,
           "derivation refused");
    bgp_ribout_snapshot_unref(snapshot);
    bgp_ribout_destroy(&block);
    PASS();
}

int main(void) {
    test_literal_vectors();
    test_long_flowspec_and_split();
    test_generated_families();
    test_withdrawal_cache();
    test_eor();
    test_malformed_advertisement();
    printf("\nTests run: %d, passed: %d, failed: %d\n", tests_run, tests_passed, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
