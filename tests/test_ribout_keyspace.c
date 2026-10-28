// Route-key overlap and equality of snapshots, built from generated ribouts.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test_case.h"
#include "test_wire.h"
#include "bgp_ribout.h"
#include "test_route_keys.h"
#include "bgp_ribout_snapshot.h"

/*
 * The sorted, distinct route keys of a snapshot.
 */
static int key_set(const bgp_ribout_snapshot_t *snapshot, key_set_t *set) {
    const bgp_tx_profile_t *p = &snapshot->profile;

    return route_key_set(snapshot->adv->msgs, p->afi, p->safi, p->add_path, set, NULL);
}

/*
 * Keys of a and b intersect (overlap) and are equal (same); keys of different families never meet.
 */
static void key_truth(const bgp_ribout_snapshot_t *a, const bgp_ribout_snapshot_t *b, const key_set_t *ka,
                      const key_set_t *kb, int *overlap, int *same) {
    size_t i = 0, j = 0;
    int    common = 0;

    if (a->profile.afi != b->profile.afi || a->profile.safi != b->profile.safi) {
        *overlap = 0;
        *same = 0;
        return;
    }
    while (i < ka->count && j < kb->count) {
        int cmp = key_compare(&ka->keys[i], &kb->keys[j]);

        if (cmp == 0) {
            common++;
            i++;
            j++;
        } else if (cmp < 0) {
            i++;
        } else {
            j++;
        }
    }
    *overlap = common > 0;
    *same = ka->count == kb->count && (size_t)common == ka->count;
}

/*
 * A snapshot from "keyword value" lines; the block is destroyed, the caller owns the reference.
 */
static bgp_ribout_snapshot_t *snap(const char *const *lines) {
    bgp_ribout_config_t    block;
    bgp_ribout_snapshot_t *snapshot = NULL;

    if (bgp_ribout_init(&block, "keys") != 0) {
        return NULL;
    }
    for (; *lines; lines++) {
        char        keyword[32];
        const char *value = strchr(*lines, ' ');

        snprintf(keyword, sizeof(keyword), "%.*s", (int)(value - *lines), *lines);
        if (bgp_ribout_edit(&block, keyword, value + 1, 0) != 0) {
            fprintf(stderr, "bad line: %s\n", *lines);
            bgp_ribout_destroy(&block);
            return NULL;
        }
    }
    if (bgp_ribout_generate(&block) == BGP_RIBOUT_GENERATED) {
        snapshot = bgp_ribout_snapshot_ref(block.snapshot);
    }
    bgp_ribout_destroy(&block);
    return snapshot;
}

/*
 * overlap and same are the truth on the wire. A rotating key list is checked as its whole list, a superset of the
 * values its paths take: sound, but it can answer "overlap" where the keys do not meet (approx_overlap).
 */
typedef struct {
    const char       *name;
    const char *const a[10];
    const char *const b[10];
    int               overlap;
    int               same;
    int               approx_overlap;
} key_case_t;

#define V4(p) "prefix " p, "next-hop 192.0.2.1"
#define SR(e, c) "distinguisher 1 x 4", "color " c, "endpoint " e, "segment-list 1 weight 1 mpls 16001", \
                 "rt 192.0.2.1:1"
#define FS4(...) "address-family ipv4 flowspec", "prefix 10.0.0.0/24", __VA_ARGS__
/*
 * An SR Policy ribout of distinguisher, color and endpoint lines (each may rotate), and an EVPN Type 5 ribout of 6
 * prefixes over 3 rotating RDs with the given Ethernet tag line.
 */
#define SRR(d, c, e) "distinguisher " d, "color " c, "endpoint " e, "segment-list 1 weight 1 mpls 16001", \
                     "rt 192.0.2.1:1"
#define T5(tag) V4("10.0.0.0/24 x 6"), "rd rotate 65000:1 x 3", "ethernet-tag " tag, "label 1"

static const key_case_t k_cases[] = {
    {
        .name = "2560 rotating RDs and 1000 labels preserve every wire key under attribute replacement",
        .a = {V4("10.0.0.0/24 x 2560"), "rd rotate 65000:1 x 2560", "label rotate 16000 x 1000", NULL},
        .b = {V4("10.0.0.0/24 x 2560"), "rd rotate 65000:1 x 2560", "label rotate 17000 x 1000", NULL},
        .overlap = 1, .same = 1,
    },
    {
        .name = "Compact and explicit route-key inventories compare by values, not representation",
        .a = {V4("10.0.0.0/24"), "rd 65000:1 x 3", "label 16000", "path-id 10 x 3", NULL},
        .b = {V4("10.0.0.0/24"), "rd 65000:1 65000:2 65000:3", "label 16000", "path-id 10 11 12", NULL},
        .overlap = 1, .same = 1,
    },
    {
        .name = "RTC assigned-number ranges carry",
        .a = {"nlri rtc origin-as 65000 target 65000:255 x 3", NULL},
        .b = {"nlri rtc origin-as 65000 target 65000:256 x 3", NULL},
        .overlap = 1,
    },
    {
        .name = "RTC different origin AS",
        .a = {"nlri rtc origin-as 65000 target 65000:1 x 3", NULL},
        .b = {"nlri rtc origin-as 65001 target 65000:1 x 3", NULL},
    },
    {
        .name = "RTC same keys and different attributes",
        .a = {"nlri rtc origin-as 65000 target 65000:1 x 3", NULL},
        .b = {"nlri rtc origin-as 65000 target 65000:1 x 3", "med 10", NULL},
        .overlap = 1, .same = 1,
    },
    {
        .name = "RTC default and membership have different identities",
        .a = {"nlri rtc default", NULL},
        .b = {"nlri rtc origin-as 0 target 0:0", NULL},
    },
    {
        .name = "VPLS label base and size are not keys",
        .a = {"nlri vpls rd 65000:1 ve-id 1 offset 0 size 8 label-base 1000 x 3", NULL},
        .b = {"nlri vpls rd 65000:1 ve-id 1 offset 0 size 16 label-base 2000 x 3", NULL},
        .overlap = 1, .same = 1,
    },
    {
        .name = "EVPN1 forwarding label is not a key",
        .a = {"nlri evpn type1 rd 65000:1 esi 0 ethernet-tag 1 label 1000 x 3", NULL},
        .b = {"nlri evpn type1 rd 65000:1 esi 0 ethernet-tag 1 label 2000 x 3", NULL},
        .overlap = 1, .same = 1,
    },
    {
        .name = "EVPN3 IPv6 router range carries",
        .a = {"nlri evpn type3 rd 65000:1 ethernet-tag 1 router 2001:db8::ff x 3", NULL},
        .b = {"nlri evpn type3 rd 65000:1 ethernet-tag 1 router 2001:db8::100", NULL},
        .overlap = 1,
    },
    {
        .name = "EVPN3 adjacent router ranges do not overlap",
        .a = {"nlri evpn type3 rd 65000:1 ethernet-tag 1 router 192.0.2.1 x 3", NULL},
        .b = {"nlri evpn type3 rd 65000:1 ethernet-tag 1 router 192.0.2.4 x 3", NULL},
    },
    {
        .name = "EVPN4 different scale axes intersect",
        .a = {"nlri evpn type4 rd 65000:1 esi 0 router 192.0.2.1 x 3", NULL},
        .b = {"nlri evpn type4 rd 65000:1 esi 0 router 192.0.2.2 step rd x 3", NULL},
        .overlap = 1,
    },
    {
        .name = "MVPN route types are distinct",
        .a = {"nlri mvpn4 type6 rd 65000:1 source-as 65001 source 192.0.2.1 group 239.1.1.1", NULL},
        .b = {"nlri mvpn4 type7 rd 65000:1 source-as 65001 source 192.0.2.1 group 239.1.1.1", NULL},
    },
    {
        .name = "BGP-LS different local nodes are distinct",
        .a = {"nlri bgp-ls node protocol 3 identifier 1 local-as 65000 local-router 1.2.3.4 x 3", NULL},
        .b = {"nlri bgp-ls node protocol 3 identifier 1 local-as 65001 local-router 1.2.3.4 x 3", NULL},
    },
    {
        .name = "BGP-LS identifiers are keys",
        .a = {"nlri bgp-ls node protocol 3 identifier 1 local-as 65000 local-router 1.2.3.4 x 3", NULL},
        .b = {"nlri bgp-ls node protocol 3 identifier 3 local-as 65000 local-router 1.2.3.4 x 3", NULL},
        .overlap = 1,
    },
    {
        .name = "identical unicast",
        .a = {
            V4("10.0.0.0/24 x 10"),
            NULL,
        },
        .b = {
            V4("10.0.0.0/24 x 10"),
            NULL,
        },
        .overlap = 1,
        .same = 1,
    },
    {
        .name = "attributes are not keys",
        .a = {
            V4("10.0.0.0/24 x 10"),
            "localpref 300",
            NULL,
        },
        .b = {
            "prefix 10.0.0.0/24 x 10",
            "next-hop 192.0.2.9",
            "med 7",
            NULL,
        },
        .overlap = 1,
        .same = 1,
    },
    {
        .name = "intersecting prefix ranges",
        .a = {
            V4("10.0.0.0/24 x 10"),
            NULL,
        },
        .b = {
            V4("10.0.5.0/24 x 10"),
            NULL,
        },
        .overlap = 1,
        .same = 0,
    },
    {
        .name = "adjacent prefix ranges",
        .a = {
            V4("10.0.0.0/24 x 10"),
            NULL,
        },
        .b = {
            V4("10.0.10.0/24 x 5"),
            NULL,
        },
        .overlap = 0,
        .same = 0,
    },
    {
        .name = "different prefix length",
        .a = {
            V4("10.0.0.0/24"),
            NULL,
        },
        .b = {
            V4("10.0.0.0/25"),
            NULL,
        },
        .overlap = 0,
        .same = 0,
    },
    {
        .name = "host bits are masked",
        .a = {
            V4("10.0.0.1/24"),
            NULL,
        },
        .b = {
            V4("10.0.0.0/24"),
            NULL,
        },
        .overlap = 1,
        .same = 1,
    },
    {
        .name = "IPv4 and IPv6 unicast",
        .a = {
            V4("10.0.0.0/24"),
            NULL,
        },
        .b = {
            "prefix 2001:db8::/64",
            "next-hop 2001:db8::1",
            NULL,
        },
        .overlap = 0,
        .same = 0,
    },
    {
        .name = "IPv6 ranges",
        .a = {
            "prefix 2001:db8::/64 x 100",
            "next-hop 2001:db8::1",
            NULL,
        },
        .b = {
            "prefix 2001:db8:0:63::/64 x 3",
            "next-hop 2001:db8::1",
            NULL,
        },
        .overlap = 1,
        .same = 0,
    },
    {
        .name = "labels are not keys",
        .a = {
            V4("10.0.0.0/24 x 4"),
            "label 100",
            NULL,
        },
        .b = {
            V4("10.0.0.0/24 x 4"),
            "label 200 201",
            NULL,
        },
        .overlap = 1,
        .same = 1,
    },
    {
        .name = "disjoint RDs",
        .a = {
            V4("10.0.0.0/24"),
            "rd 65000:1",
            "label 1",
            NULL,
        },
        .b = {
            V4("10.0.0.0/24"),
            "rd 65000:2",
            "label 1",
            NULL,
        },
        .overlap = 0,
        .same = 0,
    },
    {
        .name = "shared RD",
        .a = {
            V4("10.0.0.0/24"),
            "rd 65000:1 65000:2",
            "label 1",
            NULL,
        },
        .b = {
            V4("10.0.0.0/24"),
            "rd 65000:2 65000:3",
            "label 1",
            NULL,
        },
        .overlap = 1,
        .same = 0,
    },
    {
        .name = "VPN and unicast",
        .a = {
            V4("10.0.0.0/24"),
            "rd 65000:1",
            "label 1",
            NULL,
        },
        .b = {
            V4("10.0.0.0/24"),
            NULL,
        },
        .overlap = 0,
        .same = 0,
    },
    {
        .name = "disjoint path IDs",
        .a = {
            V4("10.0.0.0/24"),
            "path-id 1 2",
            NULL,
        },
        .b = {
            V4("10.0.0.0/24"),
            "path-id 3",
            NULL,
        },
        .overlap = 0,
        .same = 0,
    },
    {
        .name = "shared path ID",
        .a = {
            V4("10.0.0.0/24"),
            "path-id 1 2",
            NULL,
        },
        .b = {
            V4("10.0.0.0/24"),
            "path-id 2 3",
            NULL,
        },
        .overlap = 1,
        .same = 0,
    },
    {
        .name = "EVPN T5 ESI and gateway are not keys",
        .a = {
            V4("10.0.0.0/24"),
            "rd 65000:1",
            "ethernet-tag 0",
            "label 1",
            "esi 1",
            NULL,
        },
        .b = {
            V4("10.0.0.0/24"),
            "rd 65000:1",
            "ethernet-tag 0",
            "label 2",
            "gateway-ip 10.9.9.9",
            NULL,
        },
        .overlap = 1,
        .same = 1,
    },
    {
        .name = "EVPN T5 Ethernet tags",
        .a = {
            V4("10.0.0.0/24"),
            "rd 65000:1",
            "ethernet-tag 0",
            "label 1",
            NULL,
        },
        .b = {
            V4("10.0.0.0/24"),
            "rd 65000:1",
            "ethernet-tag 100",
            "label 1",
            NULL,
        },
        .overlap = 0,
        .same = 0,
    },
    {
        .name = "EVPN T5 default tag is 0",
        .a = {
            V4("10.0.0.0/24"),
            "rd 65000:1",
            "ethernet-tag 0",
            "label 1",
            NULL,
        },
        .b = {
            V4("10.0.0.0/24"),
            "rd 65000:1",
            "esi 1",
            "label 1",
            NULL,
        },
        .overlap = 1,
        .same = 1,
    },
    {
        .name = "EVPN T2 labels are not keys",
        .a = {
            "rd 65000:1",
            "mac 1 x 10",
            "label 10",
            NULL,
        },
        .b = {
            "rd 65000:1",
            "mac 5 x 10",
            "label 20",
            "esi 3",
            NULL,
        },
        .overlap = 1,
        .same = 0,
    },
    {
        .name = "EVPN T2 same keys",
        .a = {
            "rd 65000:1",
            "mac 1 x 10",
            "label 10",
            NULL,
        },
        .b = {
            "rd 65000:1",
            "mac 1 x 10",
            "label 20",
            "esi 3",
            NULL,
        },
        .overlap = 1,
        .same = 1,
    },
    {
        .name = "EVPN T2 disjoint MACs",
        .a = {
            "rd 65000:1",
            "mac 1 x 10",
            "label 1",
            NULL,
        },
        .b = {
            "rd 65000:1",
            "mac 11 x 10",
            "label 1",
            NULL,
        },
        .overlap = 0,
        .same = 0,
    },
    {
        .name = "EVPN T2 MAC only and MAC+IP",
        .a = {
            "rd 65000:1",
            "mac 1",
            "label 1",
            NULL,
        },
        .b = {
            "rd 65000:1",
            "mac 1",
            "ip 10.0.0.1",
            "label 1",
            NULL,
        },
        .overlap = 0,
        .same = 0,
    },
    {
        .name = "EVPN T2 and T5",
        .a = {
            "rd 65000:1",
            "mac 1",
            "label 1",
            NULL,
        },
        .b = {
            V4("10.0.0.0/24"),
            "rd 65000:1",
            "ethernet-tag 0",
            "label 1",
            NULL,
        },
        .overlap = 0,
        .same = 0,
    },
    {
        .name = "SR Policy disjoint colors",
        .a = {
            SR("10.0.0.1 x 4", "100"),
            NULL,
        },
        .b = {
            SR("10.0.0.1 x 4", "200"),
            NULL,
        },
        .overlap = 0,
        .same = 0,
    },
    {
        .name = "SR Policy endpoint ranges",
        .a = {
            SR("10.0.0.1 x 4", "100"),
            NULL,
        },
        .b = {
            SR("10.0.0.4 x 4", "100 200"),
            NULL,
        },
        .overlap = 1,
        .same = 0,
    },
    {
        .name = "SR Policy disjoint endpoints",
        .a = {
            SR("10.0.0.1 x 4", "100"),
            NULL,
        },
        .b = {
            SR("10.0.0.5 x 4", "100"),
            NULL,
        },
        .overlap = 0,
        .same = 0,
    },
    {
        .name = "FlowSpec stepped ports meet",
        .a = {
            FS4("dst-port 1 x 100"),
            NULL,
        },
        .b = {
            FS4("dst-port 50 x 10"),
            NULL,
        },
        .overlap = 1,
        .same = 0,
    },
    {
        .name = "FlowSpec stepped ports apart",
        .a = {
            FS4("dst-port 1 x 100"),
            NULL,
        },
        .b = {
            FS4("dst-port 200 x 10"),
            NULL,
        },
        .overlap = 0,
        .same = 0,
    },
    {
        .name = "FlowSpec component in one rule only",
        .a = {
            FS4("dst-port 80"),
            NULL,
        },
        .b = {
            FS4("dst-port 80", "protocol 6"),
            NULL,
        },
        .overlap = 0,
        .same = 0,
    },
    {
        .name = "FlowSpec alternatives",
        .a = {
            FS4("protocol each(6, 17)"),
            NULL,
        },
        .b = {
            FS4("protocol 17"),
            NULL,
        },
        .overlap = 1,
        .same = 0,
    },
    {
        .name = "FlowSpec disjoint alternatives",
        .a = {
            FS4("protocol each(6, 17)"),
            NULL,
        },
        .b = {
            FS4("protocol 1"),
            NULL,
        },
        .overlap = 0,
        .same = 0,
    },
    {
        .name = "FlowSpec step meets an alternative",
        .a = {
            FS4("dst-port 1000 x 10"),
            NULL,
        },
        .b = {
            FS4("dst-port each(80, 1005)"),
            NULL,
        },
        .overlap = 1,
        .same = 0,
    },
    {
        .name = "FlowSpec operators differ",
        .a = {
            FS4("dst-port 80"),
            NULL,
        },
        .b = {
            FS4("dst-port >=80"),
            NULL,
        },
        .overlap = 0,
        .same = 0,
    },
    {
        .name = "FlowSpec actions are not keys",
        .a = {
            FS4("dst-port 80", "action traffic-rate bytes 0"),
            NULL,
        },
        .b = {
            FS4("dst-port 80", "action mark 10"),
            NULL,
        },
        .overlap = 1,
        .same = 1,
    },
    {
        .name = "FlowSpec VPN RDs",
        .a = {
            "address-family ipv4 flowspec-vpn",
            "prefix 10.0.0.0/24",
            "rd 65000:1",
            "dst-port 80",
            NULL,
        },
        .b = {
            "address-family ipv4 flowspec-vpn",
            "prefix 10.0.0.0/24",
            "rd 65000:2",
            "dst-port 80",
            NULL,
        },
        .overlap = 0,
        .same = 0,
    },
    {
        .name = "IPv6 FlowSpec destination bits before offset are not keys",
        .a = {
            "address-family ipv6 flowspec",
            "prefix 2001:db8:1::/32-64",
            "dst-port 80",
            NULL,
        },
        .b = {
            "address-family ipv6 flowspec",
            "prefix 3001:db8:1::/32-64",
            "dst-port 80",
            NULL,
        },
        .overlap = 1,
        .same = 1,
    },
    {
        .name = "IPv6 FlowSpec source bits before offset are not keys",
        .a = {
            "address-family ipv6 flowspec",
            "src-prefix 2001:db8:1::/32-64",
            "dst-port 80",
            NULL,
        },
        .b = {
            "address-family ipv6 flowspec",
            "src-prefix 3001:db8:1::/32-64",
            "dst-port 80",
            NULL,
        },
        .overlap = 1,
        .same = 1,
    },
    {
        .name = "IPv6 FlowSpec destination bits after offset are keys",
        .a = {
            "address-family ipv6 flowspec",
            "prefix 2001:db8:1::/32-64",
            "dst-port 80",
            NULL,
        },
        .b = {
            "address-family ipv6 flowspec",
            "prefix 2001:db8:2::/32-64",
            "dst-port 80",
            NULL,
        },
        .overlap = 0,
        .same = 0,
    },
    {
        .name = "IPv6 FlowSpec source bits after offset are keys",
        .a = {
            "address-family ipv6 flowspec",
            "src-prefix 2001:db8:1::/32-64",
            "dst-port 80",
            NULL,
        },
        .b = {
            "address-family ipv6 flowspec",
            "src-prefix 2001:db8:2::/32-64",
            "dst-port 80",
            NULL,
        },
        .overlap = 0,
        .same = 0,
    },
    {
        .name = "IPv6 FlowSpec offset itself is a key",
        .a = {
            "address-family ipv6 flowspec",
            "prefix 2001:db8:1::/32-64",
            "dst-port 80",
            NULL,
        },
        .b = {
            "address-family ipv6 flowspec",
            "prefix 2001:db8:1::/40-64",
            "dst-port 80",
            NULL,
        },
        .overlap = 0,
        .same = 0,
    },
    // Bits 32-63 of ffff:fffe, ffff:ffff, then (carried into bit 31, which is not on the wire) 0000:0000, 0000:0001.
    {
        .name = "IPv6 FlowSpec sequence wraps past the top of its offset bits",
        .a = {
            "address-family ipv6 flowspec",
            "prefix 2001:db8:ffff:fffe::/32-64 x 4",
            "dst-port 80",
            NULL,
        },
        .b = {
            "address-family ipv6 flowspec",
            "prefix 3001:db8:0:1::/32-64",
            "dst-port 80",
            NULL,
        },
        .overlap = 1,
        .same = 0,
    },
    {
        .name = "IPv6 FlowSpec wrapped sequence misses the keys it skips",
        .a = {
            "address-family ipv6 flowspec",
            "prefix 2001:db8:ffff:fffe::/32-64 x 4",
            "dst-port 80",
            NULL,
        },
        .b = {
            "address-family ipv6 flowspec",
            "prefix 3001:db8:0:2::/32-64",
            "dst-port 80",
            NULL,
        },
        .overlap = 0,
        .same = 0,
    },
    /*
     * Rotating key lists: the same configuration gives the same keys; rotate against the plain list gives a subset;
     * the pairing of values with paths (rotate-every, the other dimensions) decides which keys.
     */
    {
        .name = "SR Policy same color rotation",
        .a = {
            SRR("1 x 4", "rotate 100 x 3", "10.0.0.1 x 4"),
            NULL,
        },
        .b = {
            SRR("1 x 4", "rotate 100 x 3", "10.0.0.1 x 4"),
            "preference 200",
            NULL,
        },
        .overlap = 1,
        .same = 1,
    },
    {
        .name = "SR Policy color rotate against the color list",
        .a = {
            SRR("1 x 4", "rotate 100 x 3", "10.0.0.1 x 4"),
            NULL,
        },
        .b = {
            SRR("1 x 4", "100 x 3", "10.0.0.1 x 4"),
            NULL,
        },
        .overlap = 1,
        .same = 0,
    },
    {
        .name = "SR Policy rotation shifted by rotate-every",
        .a = {
            SRR("1 x 4", "rotate 100 x 3", "10.0.0.1 x 4"),
            NULL,
        },
        .b = {
            SRR("1 x 4", "rotate 100 x 3", "10.0.0.1 x 4"),
            "rotate-every 2",
            NULL,
        },
        .overlap = 1,
        .same = 0,
    },
    {
        .name = "SR Policy rotation shifted by another dimension",
        .a = {
            SRR("1 x 4", "rotate 100 x 3", "10.0.0.1 x 4"),
            NULL,
        },
        .b = {
            SRR("1 x 2", "rotate 100 x 3", "10.0.0.1 x 4"),
            NULL,
        },
        .overlap = 1,
        .same = 0,
    },
    {
        .name = "SR Policy rotated colors miss a key the list would have",
        .a = {
            SRR("1", "rotate 100 x 4", "10.0.0.1 x 4"),
            NULL,
        },
        .b = {
            SRR("1", "101", "10.0.0.1"),
            NULL,
        },
        .overlap = 0,
        .same = 0,
        .approx_overlap = 1,
    },
    {
        .name = "SR Policy distinguisher and endpoint rotate",
        .a = {
            SRR("rotate 5 x 4", "7 x 3", "rotate 10.0.0.1 x 4"),
            NULL,
        },
        .b = {
            SRR("rotate 5 x 4", "7 x 3", "rotate 10.0.0.1 x 4"),
            NULL,
        },
        .overlap = 1,
        .same = 1,
    },
    {
        .name = "SR Policy endpoint rotate against endpoints",
        .a = {
            SRR("1 x 3", "7", "rotate 10.0.0.1 x 3"),
            NULL,
        },
        .b = {
            SRR("1 x 3", "7", "10.0.0.1 x 3"),
            NULL,
        },
        .overlap = 1,
        .same = 0,
    },
    {
        .name = "EVPN T5 same tag rotation",
        .a = {
            T5("rotate 100 x 3"),
            NULL,
        },
        .b = {
            T5("rotate 100 x 3"),
            "med 9",
            NULL,
        },
        .overlap = 1,
        .same = 1,
    },
    {
        .name = "EVPN T5 tag rotate against the tag list",
        .a = {
            T5("rotate 100 x 3"),
            NULL,
        },
        .b = {
            T5("100 x 3"),
            NULL,
        },
        .overlap = 1,
        .same = 0,
    },
    {
        .name = "EVPN T5 rotated tags miss",
        .a = {
            T5("rotate 100 x 3"),
            NULL,
        },
        .b = {
            V4("10.0.0.0/24"),
            "rd 65000:1",
            "ethernet-tag 101",
            "label 1",
            NULL,
        },
        .overlap = 0,
        .same = 0,
        .approx_overlap = 1,
    },
    {
        .name = "EVPN T2 tag rotation",
        .a = {
            "rd 65000:1",
            "mac 1 x 4",
            "ethernet-tag rotate 10 x 2",
            "label 1",
            NULL,
        },
        .b = {
            "rd 65000:1",
            "mac 1 x 4",
            "ethernet-tag rotate 10 x 2",
            "label 2",
            NULL,
        },
        .overlap = 1,
        .same = 1,
    },
    {
        .name = "path ID rotation",
        .a = {
            V4("10.0.0.0/24 x 4"),
            "path-id rotate 1 2",
            NULL,
        },
        .b = {
            V4("10.0.0.0/24 x 4"),
            "path-id rotate 1 2",
            "med 5",
            NULL,
        },
        .overlap = 1,
        .same = 1,
    },
    {
        .name = "path-id rotate against the path ID list",
        .a = {
            V4("10.0.0.0/24 x 4"),
            "path-id rotate 1 2",
            NULL,
        },
        .b = {
            V4("10.0.0.0/24 x 4"),
            "path-id 1 2",
            NULL,
        },
        .overlap = 1,
        .same = 0,
    },
    {
        .name = "rotated path IDs miss",
        .a = {
            V4("10.0.0.0/24 x 2"),
            "path-id rotate 1 2",
            NULL,
        },
        .b = {
            V4("10.0.0.0/24"),
            "path-id 2",
            NULL,
        },
        .overlap = 0,
        .same = 0,
        .approx_overlap = 1,
    },
    {
        .name = "FlowSpec same component rotation",
        .a = {
            FS4("protocol each(6, 17)", "dst-port rotate 80 x 3"),
            NULL,
        },
        .b = {
            FS4("protocol each(6, 17)", "dst-port rotate 80 x 3"),
            "action mark 1",
            NULL,
        },
        .overlap = 1,
        .same = 1,
    },
    {
        .name = "FlowSpec component rotate against its values",
        .a = {
            FS4("protocol each(6, 17)", "dst-port rotate 80 x 3"),
            NULL,
        },
        .b = {
            FS4("protocol each(6, 17)", "dst-port 80 x 3"),
            NULL,
        },
        .overlap = 1,
        .same = 0,
    },
    {
        .name = "FlowSpec rotated component misses",
        .a = {
            FS4("protocol each(6, 17)", "dst-port rotate 80 x 2"),
            NULL,
        },
        .b = {
            FS4("protocol 6", "dst-port 81"),
            NULL,
        },
        .overlap = 0,
        .same = 0,
        .approx_overlap = 1,
    },
    {
        .name = "FlowSpec rotation shifted by rotate-every",
        .a = {
            FS4("protocol each(6, 17)", "dst-port rotate 80 x 3"),
            NULL,
        },
        .b = {
            FS4("protocol each(6, 17)", "dst-port rotate 80 x 3"),
            "rotate-every 2",
            NULL,
        },
        .overlap = 1,
        .same = 0,
    },
};

static void test_case(const key_case_t *kc) {
    char                   why[160];
    bgp_ribout_snapshot_t *a = snap(kc->a), *b = snap(kc->b);
    key_set_t              ka = {0}, kb = {0};
    int                    overlap_ab = 0, overlap_ba = 0, same_ab = 0, same_ba = 0, truth_overlap = 0, truth_same = 0;
    int                    generated = a && b, decoded = 0;

    TEST(kc->name);
    if (generated) {
        overlap_ab = bgp_ribout_snapshot_keys_overlap(a, b);
        overlap_ba = bgp_ribout_snapshot_keys_overlap(b, a);
        same_ab = bgp_ribout_snapshot_same_keys(a, b);
        same_ba = bgp_ribout_snapshot_same_keys(b, a);
        // The table must agree with the keys actually on the wire.
        decoded = key_set(a, &ka) && key_set(b, &kb);
        if (decoded) {
            key_truth(a, b, &ka, &kb, &truth_overlap, &truth_same);
        }
    }
    free(ka.keys);
    free(kb.keys);
    bgp_ribout_snapshot_unref(a);
    bgp_ribout_snapshot_unref(b);
    ASSERT(generated, "both configurations generate snapshots");
    ASSERT(decoded, "both advertised route-key sets decode");
    snprintf(why, sizeof(why), "%s: wire keys overlap %d same %d, table %d %d", kc->name, truth_overlap,
             truth_same, kc->overlap, kc->same);
    ASSERT(truth_overlap == kc->overlap && truth_same == kc->same, why);
    snprintf(why, sizeof(why), "%s: overlap %d/%d (want %d), same %d/%d (want %d)", kc->name, overlap_ab,
             overlap_ba, kc->overlap || kc->approx_overlap, same_ab, same_ba, kc->same);
    ASSERT(overlap_ab == (kc->overlap || kc->approx_overlap) && overlap_ba == overlap_ab && same_ab == kc->same &&
           same_ba == kc->same, why);
    PASS();
}

static void test_all_prefix_masks(void) {
    TEST("Every IPv6 prefix offset/length and changed bit agrees with the bit-level key oracle");
    bgp_ribout_config_t ac = {0}, bc = {0};
    ac.prefix_spec.af = bc.prefix_spec.af = AF_INET6;
    ac.prefix_spec.count = bc.prefix_spec.count = 1;
    memset(&ac.prefix_spec.base_addr, 0xa5, 16);
    bgp_ribout_snapshot_t a = {.config = &ac, .profile = {.family = BGP_RIBOUT_FAMILY_FLOWSPEC_IPV6}};
    bgp_ribout_snapshot_t b = {.config = &bc, .profile = {.family = BGP_RIBOUT_FAMILY_FLOWSPEC_IPV6}};
    for (unsigned length = 0; length <= 128; length++) {
        for (unsigned offset = 0; offset < (length ? length : 1); offset++) {
            ac.prefix_spec.prefix_len = bc.prefix_spec.prefix_len = (uint8_t)length;
            ac.prefix_offset = bc.prefix_offset = (uint8_t)offset;
            for (unsigned bit = 0; bit < 128; bit++) {
                bc.prefix_spec.base_addr = ac.prefix_spec.base_addr;
                bc.prefix_spec.base_addr.ipv6.s6_addr[bit / 8] ^= (uint8_t)(0x80u >> (bit % 8));
                int same = bit < offset || bit >= length;
                ASSERT(bgp_ribout_snapshot_keys_overlap(&a, &b) == same &&
                       bgp_ribout_snapshot_same_keys(&a, &b) == same, "only bits in [offset, length) identify the key");
            }
        }
    }
    PASS();
}

int main(void) {
    test_all_prefix_masks();
    for (size_t i = 0; i < sizeof(k_cases) / sizeof(k_cases[0]); i++) {
        test_case(&k_cases[i]);
    }
    printf("\nTests run: %d, passed: %d, failed: %d\n", tests_run, tests_passed, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
