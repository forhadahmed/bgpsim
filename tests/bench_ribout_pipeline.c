#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "bgp_ribout.h"
#include "bgp_ribout_snapshot.h"

typedef struct {
    const char *name;
    int         prefixes;
    int         repetitions;
    int         prefix_af;
    const char *af_name;
    const char *rds;
    const char *labels;
    const char *ethernet_tags;
    const char *path_ids;
    const char *next_hop;
    const char *gateway_ip;
    const char *esis;
    const char *mac;
    const char *ip;
    const char *label2;
    const char *med;
    const char *rt;
    const char *rt_set;
    const char *soo;
    const char *distinguishers;
    const char *colors;
    const char *endpoint;
    const char *preference;
    const char *binding_sid;
    const char *segment_list;
    const char *randseed;
    const char *as_path;
    const char *localpref;
    const char *enlp;
    const char *priority;
    // FlowSpec: one rule template; prefix_line is its destination, the components are "<keyword> <args>".
    const char *address_family;
    const char *prefix_line;
    const char *flowspec_components[3];
    const char *flowspec_actions[2];
    // Rotation options: a second EVPN Type 2 address family (dual-stack), rotate-every and rotate-period.
    const char *ip2;
    const char *rotate_every;
    const char *rotate_period;
    // community / large-community sets, rotating like rt-set
    const char *community;
    const char *large_community;
} ribout_bench_case_t;

#define RT_SET_16_LINE                                        \
    "rt-set [65000:100] [65000:101] [65000:102] [65000:103] " \
    "[65000:104] [65000:105] [65000:106] [65000:107] "        \
    "[65000:108] [65000:109] [65000:110] [65000:111] "        \
    "[65000:112] [65000:113] [65000:114] [65000:115]"

#define RT_SET_SR_LINE                          \
    "rt-set [192.0.2.30:100] [192.0.2.31:101] " \
    "[192.0.2.32:102] [192.0.2.33:103]"

static const ribout_bench_case_t k_cases[] = {
#if 0
    // single-attr: one attribute bucket, extra UPDATEs only from size limits
    {
        .name = "single-attr-v4-1k",
        .prefixes = 1000,
        .repetitions = 10,
        .prefix_af = AF_INET,
        .af_name = "ipv4",
        .next_hop = "next-hop 192.0.2.1",
    },
    {
        .name = "single-attr-v4-10k",
        .prefixes = 10000,
        .repetitions = 5,
        .prefix_af = AF_INET,
        .af_name = "ipv4",
        .next_hop = "next-hop 192.0.2.1",
    },
    {
        .name = "single-attr-v4-100k",
        .prefixes = 100000,
        .repetitions = 2,
        .prefix_af = AF_INET,
        .af_name = "ipv4",
        .next_hop = "next-hop 192.0.2.1",
    },
    {
        .name = "single-attr-v6-1k",
        .prefixes = 1000,
        .repetitions = 10,
        .prefix_af = AF_INET6,
        .af_name = "ipv6",
        .next_hop = "next-hop 2001:db8::1",
    },
    {
        .name = "single-attr-v6-10k",
        .prefixes = 10000,
        .repetitions = 4,
        .prefix_af = AF_INET6,
        .af_name = "ipv6",
        .next_hop = "next-hop 2001:db8::1",
    },
    {
        .name = "single-attr-v6-100k",
        .prefixes = 100000,
        .repetitions = 2,
        .prefix_af = AF_INET6,
        .af_name = "ipv6",
        .next_hop = "next-hop 2001:db8::1",
    },
    {
        .name = "single-attr-lu4-10k",
        .prefixes = 10000,
        .repetitions = 4,
        .prefix_af = AF_INET,
        .af_name = "lu4",
        .labels = "label 16000",
        .next_hop = "next-hop 192.0.2.1",
    },
    {
        .name = "single-attr-lu4-ext-nh-10k",
        .prefixes = 10000,
        .repetitions = 4,
        .prefix_af = AF_INET,
        .af_name = "lu4",
        .labels = "label 16000",
        .next_hop = "next-hop 2001:db8::1",
    },
    {
        .name = "single-attr-lu6-10k",
        .prefixes = 10000,
        .repetitions = 4,
        .prefix_af = AF_INET6,
        .af_name = "lu6",
        .labels = "label 32000",
        .next_hop = "next-hop 2001:db8::1",
    },
    {
        .name = "single-attr-vpn4-10k",
        .prefixes = 10000,
        .repetitions = 2,
        .prefix_af = AF_INET,
        .af_name = "vpn4",
        .rds = "rd 65000:100",
        .labels = "label 16000",
        .next_hop = "next-hop 192.0.2.1",
        .med = "med 50",
        .rt = "rt 65000:100 65000:101",
        .soo = "soo 65000:9",
    },
    {
        .name = "single-attr-vpn6-v4nh-10k",
        .prefixes = 10000,
        .repetitions = 2,
        .prefix_af = AF_INET6,
        .af_name = "vpn6",
        .rds = "rd 65000:200",
        .labels = "label 24000",
        .next_hop = "next-hop 192.0.2.1",
        .med = "med 50",
        .rt = "rt 65000:200 65000:201",
        .soo = "soo 65000:19",
    },
    {
        .name = "single-attr-evpn4-10k",
        .prefixes = 10000,
        .repetitions = 2,
        .prefix_af = AF_INET,
        .af_name = "evpn4",
        .rds = "rd 65000:300",
        .labels = "label 30000",
        .ethernet_tags = "ethernet-tag 0",
        .next_hop = "next-hop 192.0.2.10",
        .gateway_ip = "gateway-ip 10.255.0.1",
        .med = "med 25",
        .rt = "rt 65000:300",
    },
    /*
     * EVPN Type 2: many host bindings with one effective attribute bucket.
     * This stresses MAC/IP NLRI packing and message-size chopping rather than
     * attribute fanout.
     */
    {
        .name = "single-attr-evpn2-64k",
        .repetitions = 1,
        .prefix_af = AF_INET,
        .af_name = "evpn2",
        .rds = "rd 65000:320",
        .labels = "label 30000",
        .ethernet_tags = "ethernet-tag 10",
        .next_hop = "next-hop 192.0.2.10",
        .mac = "mac 00:11:22:33:00:00 x 32768",
        .ip = "ip 192.0.2.1 x 2",
        .label2 = "label2 40000",
        .med = "med 25",
        .rt = "rt 65000:320",
    },
    /*
     * SRv6 control-plane stress is better modeled by scaling services and
     * keeping a realistic SID depth than by inventing arbitrarily deep
     * segment-lists for every route.
     */
    {
        .name = "single-attr-sr6-64k",
        .repetitions = 1,
        .prefix_af = AF_INET6,
        .af_name = "sr6",
        .next_hop = "next-hop 2001:db8:feed::1",
        .rt = "rt 192.0.2.30:100",
        .distinguishers = "distinguisher 100 x 64",
        .colors = "color 700 701",
        .endpoint = "endpoint 2001:db8:100::1 x 512",
        .preference = "preference 1000",
        .binding_sid = "binding-sid srv6 fc00:0:70::1",
        .segment_list = "segment-list 7 weight 70 srv6 " "2001:db8:7::1 behavior 4660 structure 48 16 16 48 " "2001:db8:7::2 2001:db8:7::3 " "2001:db8:7::4 2001:db8:7::5 2001:db8:7::6",
        .enlp = "enlp 3",
        .priority = "priority 7",
    },
#endif
    // multi-attr: a modest number of grouping-relevant next-hop values
    {
        .name = "multi-attr-v4-25k",
        .prefixes = 25000,
        .repetitions = 2,
        .prefix_af = AF_INET,
        .af_name = "ipv4",
        .path_ids = "path-id 0 1 2 3",
        .next_hop = "next-hop 192.0.2.1 x 16",
    },
    {
        .name = "multi-attr-v6-25k",
        .prefixes = 25000,
        .repetitions = 2,
        .prefix_af = AF_INET6,
        .af_name = "ipv6",
        .path_ids = "path-id 0 1 2 3",
        .next_hop = "next-hop 2001:db8::1 x 16",
    },
    {
        .name = "multi-attr-lu4-10k",
        .prefixes = 10000,
        .repetitions = 2,
        .prefix_af = AF_INET,
        .af_name = "lu4",
        .labels = "label 16000 16001",
        .path_ids = "path-id 0 1 2 3",
        .next_hop = "next-hop 192.0.2.1 x 16",
    },
    {
        .name = "multi-attr-lu6-10k",
        .prefixes = 10000,
        .repetitions = 2,
        .prefix_af = AF_INET6,
        .af_name = "lu6",
        .labels = "label 32000 32001",
        .path_ids = "path-id 0 1 2 3",
        .next_hop = "next-hop 2001:db8::1 x 16",
    },
    {
        .name = "multi-attr-vpn4-10k",
        .prefixes = 10000,
        .repetitions = 1,
        .prefix_af = AF_INET,
        .af_name = "vpn4",
        .rds = "rd 65000:100",
        .labels = "label 16000",
        .path_ids = "path-id 0 1 2 3",
        .next_hop = "next-hop 192.0.2.1",
        .med = "med 50",
        .rt_set = RT_SET_16_LINE,
        .soo = "soo 65000:9 65000:10",
    },
    {
        .name = "multi-attr-vpn6-v4nh-10k",
        .prefixes = 10000,
        .repetitions = 1,
        .prefix_af = AF_INET6,
        .af_name = "vpn6",
        .rds = "rd 65000:200",
        .labels = "label 24000",
        .path_ids = "path-id 0 1 2 3",
        .next_hop = "next-hop 192.0.2.1",
        .med = "med 50",
        .rt_set = RT_SET_16_LINE,
        .soo = "soo 65000:19 65000:20",
    },
    {
        .name = "multi-attr-evpn4-10k",
        .prefixes = 10000,
        .repetitions = 1,
        .prefix_af = AF_INET,
        .af_name = "evpn4",
        .rds = "rd 65000:300",
        .labels = "label 30000",
        .ethernet_tags = "ethernet-tag 0 100",
        .next_hop = "next-hop 192.0.2.10",
        .esis = "esi 00:00:00:00:00:00:00:00:00:00 00:00:00:00:00:00:00:00:00:01",
        .med = "med 25",
        .rt_set = RT_SET_16_LINE,
    },
    /*
     * EVPN Type 2: controlled next-hop / RT-set spread while keeping one
     * host-binding shape. This measures how quickly grouping degrades once
     * MAC/IP fanout is combined with modest attribute diversity.
     */
    // FlowSpec: a mark that rotates through 64 values, so 64 attribute groups.
    {
        .name = "multi-attr-fs4-64k",
        .repetitions = 2,
        .prefix_af = AF_INET,
        .af_name = "fs4",
        .address_family = "address-family ipv4 flowspec",
        .prefix_line = "prefix 10.0.0.0/24 x 65536",
        .flowspec_components = {
            "protocol 6",
            "dst-port 80 443",
        },
        .flowspec_actions = {
            "mark 0 x 64",
        },
    },
    {
        .name = "multi-attr-fs6-64k",
        .repetitions = 2,
        .prefix_af = AF_INET6,
        .af_name = "fs6",
        .address_family = "address-family ipv6 flowspec",
        .prefix_line = "prefix 2001:db8::/64 x 1024",
        .flowspec_components = {
            "protocol 6",
            "flow-label 0 x 64",
        },
        .flowspec_actions = {
            "mark 0 x 64",
        },
    },
    {
        .name = "multi-attr-evpn2-16k",
        .repetitions = 1,
        .prefix_af = AF_INET,
        .af_name = "evpn2",
        .rds = "rd 65000:320",
        .labels = "label 30000 30001",
        .ethernet_tags = "ethernet-tag 10 11",
        .next_hop = "next-hop 192.0.2.10 x 16",
        .esis = "esi 00:00:00:00:00:00:00:00:00:00 00:00:00:00:00:00:00:00:00:01",
        .mac = "mac 00:11:22:34:00:00 x 4096",
        .ip = "ip 192.0.2.1 x 2",
        .label2 = "label2 40000 40001",
        .med = "med 25",
        .rt_set = RT_SET_16_LINE,
    },
    /*
     * vrf: a PE's VPN tables, one VRF per rotation step. rd rotate, an rt-set sequence and label rotate (rotate-period
     * 100) give route i the RD, route target and label of VRF i % 100 + 1, so 100 attribute groups; rotate-every
     * gives each VRF a contiguous block of prefixes instead.
     */
    {
        .name = "vrf-vpn4-100x1M",
        .prefixes = 1000000,
        .repetitions = 1,
        .prefix_af = AF_INET,
        .af_name = "vpn4",
        .rds = "rd rotate 65551:1 x 100",
        .labels = "label rotate 24001 x 100",
        .next_hop = "next-hop 192.0.2.1",
        .med = "med 70",
        .rt_set = "rt-set [65551:1] x 100",
        .rotate_period = "rotate-period 100",
    },
    {
        .name = "vrf-vpn4-blocks-100x1M",
        .prefixes = 1000000,
        .repetitions = 1,
        .prefix_af = AF_INET,
        .af_name = "vpn4",
        .rds = "rd rotate 65551:1 x 100",
        .labels = "label rotate 24001 x 100",
        .next_hop = "next-hop 192.0.2.1",
        .med = "med 70",
        .rt_set = "rt-set [65551:1] x 100",
        .rotate_every = "rotate-every 10000",
        .rotate_period = "rotate-period 100",
    },
    {
        .name = "vrf-vpn6-100x1M",
        .prefixes = 1000000,
        .repetitions = 1,
        .prefix_af = AF_INET6,
        .af_name = "vpn6",
        .rds = "rd rotate 65551:1 x 100",
        .labels = "label rotate 25001 x 100",
        .next_hop = "next-hop 2001:db8:ffff::1",
        .med = "med 80",
        .rt_set = "rt-set [65551:1] x 100",
        .rotate_period = "rotate-period 100",
    },
    {
        .name = "vrf-evpn4-100x1M",
        .prefixes = 1000000,
        .repetitions = 1,
        .prefix_af = AF_INET,
        .af_name = "evpn4",
        .rds = "rd rotate 65551:1 x 100",
        .labels = "label rotate 30001 x 100",
        .ethernet_tags = "ethernet-tag 0",
        .next_hop = "next-hop 192.0.2.10",
        .med = "med 90",
        .rt_set = "rt-set [65551:1] x 100",
        .rotate_period = "rotate-period 100",
    },
    /*
     * Dual-stack hosts: MAC i bound to IPv4 i and IPv6 i (ip rotate per family), rotate-every 2 so both bindings of a
     * host carry its VRF's RD, IP-VRF and MAC-VRF route targets, L2 and L3 labels: 1M routes.
     */
    {
        .name = "vrf-evpn2-dual-100x1M",
        .repetitions = 1,
        .prefix_af = AF_INET,
        .af_name = "evpn2",
        .rds = "rd rotate 65551:1 x 100",
        .labels = "label 40001 x 100",
        .next_hop = "next-hop 192.0.2.20",
        .mac = "mac 02:00:00:00:00:01 x 500000",
        .ip = "ip rotate 172.20.0.1 x 500000",
        .label2 = "label2 30001 x 100",
        .med = "med 95",
        .rt_set = "rt-set [65551:1,65551:1001] x 100",
        .ip2 = "ip rotate 2001:db8:20::1 x 500000",
        .rotate_every = "rotate-every 2",
        .rotate_period = "rotate-period 100",
    },
    /*
     * Tagged VRFs: vrf-vpn4-100x1M plus a community set and a large-community set per VRF (the attribute groups
     * stay 100; the cost is hashing and copying 12 + 24 more octets per path).
     */
    {
        .name = "vrf-vpn4-tagged-100x1M",
        .prefixes = 1000000,
        .repetitions = 1,
        .prefix_af = AF_INET,
        .af_name = "vpn4",
        .rds = "rd rotate 65551:1 x 100",
        .labels = "label rotate 24001 x 100",
        .next_hop = "next-hop 192.0.2.1",
        .med = "med 70",
        .rt_set = "rt-set [65551:1] x 100",
        .rotate_period = "rotate-period 100",
        .community = "community [65000:1,65000:1001,no-export] x 100",
        .large_community = "large-community [65551:1:1,65551:2:1] x 100",
    },
    /*
     * Tagged Internet table: 1M IPv4 prefixes, 1000 community sets of four (origin, region, peer type, a
     * well-known value), so 1000 attribute groups of 1000 prefixes each.
     */
    {
        .name = "tagged-v4-1000x1M",
        .prefixes = 1000000,
        .repetitions = 1,
        .prefix_af = AF_INET,
        .af_name = "ipv4",
        .next_hop = "next-hop 192.0.2.1",
        .med = "med 10",
        .community = "community [65000:1,65100:1,65200:1,no-export] x 1000",
        .large_community = "large-community 65551:100:1 x 1000",
    },
    // scale-attr: high attribute cardinality to force many UPDATE groups
    {
        .name = "scale-attr-v4-250k",
        .prefixes = 250000,
        .repetitions = 1,
        .prefix_af = AF_INET,
        .af_name = "ipv4",
        .path_ids = "path-id 0 1 2 3",
        .next_hop = "next-hop 192.0.2.1 x 1024",
    },
    {
        .name = "scale-attr-v6-250k",
        .prefixes = 250000,
        .repetitions = 1,
        .prefix_af = AF_INET6,
        .af_name = "ipv6",
        .path_ids = "path-id 0 1 2 3",
        .next_hop = "next-hop 2001:db8::1 x 1024",
    },
    {
        .name = "scale-attr-lu4-10k",
        .prefixes = 10000,
        .repetitions = 1,
        .prefix_af = AF_INET,
        .af_name = "lu4",
        .labels = "label 16000 16001",
        .path_ids = "path-id 0 1 2 3",
        .next_hop = "next-hop 192.0.2.1 x 1024",
    },
    {
        .name = "scale-attr-lu6-10k",
        .prefixes = 10000,
        .repetitions = 1,
        .prefix_af = AF_INET6,
        .af_name = "lu6",
        .labels = "label 32000 32001",
        .path_ids = "path-id 0 1 2 3",
        .next_hop = "next-hop 2001:db8::1 x 1024",
    },
    {
        .name = "scale-attr-vpn4-5k",
        .prefixes = 5000,
        .repetitions = 1,
        .prefix_af = AF_INET,
        .af_name = "vpn4",
        .rds = "rd 65000:100 x 4",
        .labels = "label 16000 x 4",
        .path_ids = "path-id 0 1 2 3",
        .next_hop = "next-hop 192.0.2.1 x 1024",
        .med = "med 50",
        .rt = "rt 65000:100 65000:101",
        .soo = "soo 65000:9",
    },
    {
        .name = "scale-attr-vpn6-v4nh-5k",
        .prefixes = 5000,
        .repetitions = 1,
        .prefix_af = AF_INET6,
        .af_name = "vpn6",
        .rds = "rd 65000:200 x 4",
        .labels = "label 24000 x 4",
        .path_ids = "path-id 0 1 2 3",
        .next_hop = "next-hop 192.0.2.1 x 1024",
        .med = "med 50",
        .rt = "rt 65000:200 65000:201",
        .soo = "soo 65000:19",
    },
    {
        .name = "scale-attr-evpn4-5k",
        .prefixes = 5000,
        .repetitions = 1,
        .prefix_af = AF_INET,
        .af_name = "evpn4",
        .rds = "rd 65000:300",
        .labels = "label 30000",
        .ethernet_tags = "ethernet-tag 0 100 200 300",
        .path_ids = "path-id 0 1 2 3",
        .next_hop = "next-hop 192.0.2.10 x 1024",
        .gateway_ip = "gateway-ip 10.255.0.1 x 4",
        .med = "med 25",
        .rt = "rt 65000:300",
    },
    /*
     * EVPN Type 2: adversarial static host-binding scale. RD and Ethernet Tag
     * increase NLRI diversity, while next-hop and RT-set spread deliberately
     * fragment attribute buckets. ESI and label variation enlarge the wire
     * payload without relying on dynamic MAC-mobility churn.
     */
    {
        .name = "scale-attr-evpn2-64k",
        .repetitions = 1,
        .prefix_af = AF_INET,
        .af_name = "evpn2",
        .rds = "rd 65000:320 x 4",
        .labels = "label 30000 30001 30002 30003",
        .ethernet_tags = "ethernet-tag 10 11 12 13",
        .path_ids = "path-id 7 8",
        .next_hop = "next-hop 192.0.2.10 x 256",
        .esis = "esi 00:00:00:00:00:00:00:00:00:00 " "00:00:00:00:00:00:00:00:00:01 " "00:00:00:00:00:00:00:00:00:02 " "00:00:00:00:00:00:00:00:00:03",
        .mac = "mac 00:11:22:35:00:00 x 4096",
        .ip = "ip 192.0.2.1 x 2",
        .label2 = "label2 40000 40001",
        .med = "med 25",
        .rt_set = RT_SET_16_LINE,
    },
    /*
     * FlowSpec redirect to SR-TE: the redirect and the color rotate together through 64 policies (endpoint + color
     * with CO bits); ADD-PATH doubles each NLRI.
     */
    {
        .name = "scale-attr-fs4-srte-128k",
        .repetitions = 1,
        .prefix_af = AF_INET,
        .af_name = "fs4",
        .path_ids = "path-id 7 8",
        .colors = "color 100 x 64 co 01",
        .address_family = "address-family ipv4 flowspec",
        .prefix_line = "prefix 10.0.0.0/26 x 65536",
        .flowspec_components = {
            "protocol 6 17",
            "dst-port >=1024&<=65535",
            "packet-length <=1500",
        },
        .flowspec_actions = {
            "redirect-ip 192.0.2.0 x 64",
        },
    },
    /*
     * rotate on key lists: one SR Policy per (distinguisher, endpoint) with the color and path ID of its rotation
     * step, 64 colors; and FlowSpec rules whose destination port and protocol rotate through 64 and 2 values
     * instead of multiplying the rules.
     */
    {
        .name = "rotate-sr4-color-200k",
        .repetitions = 1,
        .prefix_af = AF_INET,
        .af_name = "sr4",
        .path_ids = "path-id rotate 7 8",
        .next_hop = "next-hop 192.0.2.1",
        .rt = "rt 192.0.2.10:100",
        .distinguishers = "distinguisher 100 x 64",
        .colors = "color rotate 200 x 64",
        .endpoint = "endpoint 10.0.0.1 x 3200",
        .preference = "preference 300",
        .segment_list = "segment-list 1 weight 10 mpls 16010 16011 16012",
    },
    {
        .name = "rotate-fs4-port-128k",
        .repetitions = 1,
        .prefix_af = AF_INET,
        .af_name = "fs4",
        .address_family = "address-family ipv4 flowspec",
        .prefix_line = "prefix 10.0.0.0/26 x 131072",
        .flowspec_components = {
            "protocol rotate each(6, 17)",
            "dst-port rotate 1024 x 64",
            "packet-length <=1500",
        },
        .flowspec_actions = {
            "traffic-rate bytes 0",
        },
    },
    /*
     * VPN FlowSpec IPv6 with RFC 8956 prefix offsets and flow labels; redirect-to-next-hop with a next hop and a
     * color that rotate together through 64 policies.
     */
    {
        .name = "scale-attr-fsv6-srte-64k",
        .repetitions = 1,
        .prefix_af = AF_INET6,
        .af_name = "fsv6",
        .rds = "rd 65000:1 x 4",
        .path_ids = "path-id 7 8",
        .next_hop = "next-hop 2001:db8:feed:: x 64",
        .colors = "color 200 x 64 co 10",
        .address_family = "address-family ipv6 flowspec-vpn",
        .prefix_line = "prefix 2001:db8::/8-64 x 8192",
        .flowspec_components = {
            "protocol 6",
            "flow-label >=1&<=1048575",
            "fragment any(isf)",
        },
        .flowspec_actions = {
            "redirect-next-hop",
            "redirect-vrf 2001:db8::1:300",
        },
    },
    {
        .name = "scale-attr-sr4-200k",
        .repetitions = 1,
        .prefix_af = AF_INET,
        .af_name = "sr4",
        .path_ids = "path-id 7 8",
        .next_hop = "next-hop 192.0.2.1 x 256",
        .rt = "rt 192.0.2.10:100",
        .distinguishers = "distinguisher 100 x 64",
        .colors = "color 200 201 202 203",
        .endpoint = "endpoint 10.0.0.1 x 400",
        .preference = "preference 300 400",
        .binding_sid = "binding-sid mpls 16000 16001",
        .segment_list = "segment-list 1 weight 10 mpls 16010 16011 16012",
        .enlp = "enlp 1 2",
        .priority = "priority 7 8",
    },
    /*
     * This case follows the SRv6 scale guidance more closely than a naive
     * "deep SID stack everywhere" benchmark: many services/endpoints, modest
     * ADD-PATH width, and deliberate attribute diversity that defeats
     * grouping, while keeping the SRv6 segment-list to 6 SIDs.
     */
    {
        .name = "scale-attr-sr6-128k",
        .repetitions = 1,
        .prefix_af = AF_INET6,
        .af_name = "sr6",
        .path_ids = "path-id 11 12",
        .next_hop = "next-hop 2001:db8:feed::1 x 128",
        .rt_set = RT_SET_SR_LINE,
        .distinguishers = "distinguisher 500 x 64",
        .colors = "color 900 901 902 903",
        .endpoint = "endpoint 2001:db8:200::1 x 256",
        .preference = "preference 1100 1101 1102 1103",
        .binding_sid = "binding-sid srv6 fc00:0:88::1 x 64",
        .segment_list = "segment-list 9 weight 90 srv6 " "2001:db8:9::1 behavior 4660 structure 48 16 16 48 " "2001:db8:9::2 2001:db8:9::3 " "2001:db8:9::4 2001:db8:9::5 2001:db8:9::6",
        .enlp = "enlp 1 2 3 4",
        .priority = "priority 7 8 9 10",
    },
    /*
     * Put the randomized high-cardinality cases at the end so the slower
     * runs do not interrupt the quicker deterministic profiles.
     */
    /*
     * EVPN Type 2: keep the host-binding workload fixed, but use deterministic
     * random scalar attributes to collapse attribute reuse and approach a
     * one-NLRI-per-group packing pattern.
     */
    {
        .name = "scale-attr-evpn2-rand-64k",
        .repetitions = 1,
        .prefix_af = AF_INET,
        .af_name = "evpn2",
        .rds = "rd 65000:320 x 4",
        .labels = "label 30000 30001 30002 30003",
        .ethernet_tags = "ethernet-tag 10 11 12 13",
        .path_ids = "path-id 7 8",
        .next_hop = "next-hop 192.0.2.10 x 256",
        .esis = "esi 00:00:00:00:00:00:00:00:00:00 " "00:00:00:00:00:00:00:00:00:01 " "00:00:00:00:00:00:00:00:00:02 " "00:00:00:00:00:00:00:00:00:03",
        .mac = "mac 00:11:22:36:00:00 x 4096",
        .ip = "ip 192.0.2.1 x 2",
        .label2 = "label2 40000 40001",
        .med = "med rand(1024)",
        .rt_set = RT_SET_16_LINE,
        .randseed = "3202",
        .as_path = "as-path 65001 [rand(64512) x 3]",
        .localpref = "localpref rand(512)",
    },
    /*
     * SR Policy IPv4: deterministic random ENLP, priority, preference,
     * binding SID, AS-path, and LOCAL_PREF keep the service set fixed while
     * defeating grouping. The binding-SID uses randrange(16,...) so strict
     * mode stays inside the valid SR-MPLS BSID label domain instead of
     * drifting into reserved labels 0..15.
     */
    {
        .name = "scale-attr-sr4-rand-200k",
        .repetitions = 1,
        .prefix_af = AF_INET,
        .af_name = "sr4",
        .path_ids = "path-id 7 8",
        .next_hop = "next-hop 192.0.2.1 x 256",
        .rt = "rt 192.0.2.10:100",
        .distinguishers = "distinguisher 100 x 64",
        .colors = "color 200 201 202 203",
        .endpoint = "endpoint 10.1.0.1 x 400",
        .preference = "preference rand(4096)",
        .binding_sid = "binding-sid mpls randrange(16,1048575)",
        .segment_list = "segment-list 1 weight 10 mpls 16010 16011 16012",
        .randseed = "4001",
        .as_path = "as-path 65001 [rand(64512) x 3]",
        .localpref = "localpref rand(512)",
        .enlp = "enlp randrange(1,4)",
        .priority = "priority randrange(0,255)",
    },
    /*
     * SRv6: add deterministic random ENLP, priority, preference, generic
     * attributes, and a wide SRv6 Binding-SID spray without inventing
     * unrealistic SID depth or dynamic locator churn.
     */
    {
        .name = "scale-attr-sr6-rand-128k",
        .repetitions = 1,
        .prefix_af = AF_INET6,
        .af_name = "sr6",
        .path_ids = "path-id 11 12",
        .next_hop = "next-hop 2001:db8:feed::1 x 128",
        .rt_set = RT_SET_SR_LINE,
        .distinguishers = "distinguisher 500 x 64",
        .colors = "color 900 901 902 903",
        .endpoint = "endpoint 2001:db8:201::1 x 256",
        .preference = "preference rand(8192)",
        .binding_sid = "binding-sid srv6 fc00:0:99::1 x 128",
        .segment_list = "segment-list 9 weight 90 srv6 " "2001:db8:9::1 behavior 4660 structure 48 16 16 48 " "2001:db8:9::2 2001:db8:9::3 " "2001:db8:9::4 2001:db8:9::5 2001:db8:9::6",
        .randseed = "6001",
        .as_path = "as-path 65001 [rand(64512) x 3]",
        .localpref = "localpref rand(512)",
        .enlp = "enlp randrange(1,4)",
        .priority = "priority randrange(0,255)",
    },
};

static double now_ms(void) {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

/*
 * The process's resident size now or at its peak (VmRSS, VmHWM of /proc/self/status), in bytes; 0 if unknown.
 */
static double proc_status_bytes(const char *key) {
    char   line[256];
    double kb = 0.0;
    size_t key_len = strlen(key);
    FILE  *f = fopen("/proc/self/status", "r");

    if (!f) {
        return 0.0;
    }
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, key, key_len) == 0 && line[key_len] == ':') {
            kb = strtod(line + key_len + 1, NULL);
            break;
        }
    }
    fclose(f);
    return kb * 1024.0;
}

/*
 * Reset the peak resident size to the current one (Linux: "5" to /proc/self/clear_refs); 0 if it cannot. The peak
 * column is how far the resident size rose above it during a run: generation, the UPDATEs and the withdrawal
 * derivation, all held at once.
 */
static int peak_rss_reset(void) {
    FILE *f = fopen("/proc/self/clear_refs", "w");
    int   written;

    if (!f) {
        return 0;
    }
    written = fputs("5", f) >= 0;
    return fclose(f) == 0 && written;
}

static void format_size_cell(double bytes, char *buf, size_t buf_len) {
    if (bytes >= (1024.0 * 1024.0)) {
        snprintf(buf, buf_len, "%.2fmb", bytes / (1024.0 * 1024.0));
    } else {
        snprintf(buf, buf_len, "%.2fkb", bytes / 1024.0);
    }
}

static void format_paths_cell(uint64_t paths, char *buf, size_t buf_len) {
    snprintf(buf, buf_len, "%.1fk", (double)paths / 1000.0);
}

static void format_rate_cell(double paths_per_sec, char *buf, size_t buf_len) {
    snprintf(buf, buf_len, "%.0fk", paths_per_sec / 1000.0);
}

static void format_messages_cell(size_t messages, char *buf, size_t buf_len) {
    if (messages > 10000u) {
        snprintf(buf, buf_len, "%.1fk", (double)messages / 1000.0);
    } else {
        snprintf(buf, buf_len, "%zu", messages);
    }
}

static void format_time_cell(double ms, char *buf, size_t buf_len) {
    if (ms < 1.0) {
        snprintf(buf, buf_len, "<1ms");
    } else {
        snprintf(buf, buf_len, "%.0fms", ms);
    }
}

static size_t sum_message_list_bytes(const bgp_msg_t *messages) {
    size_t total = 0;

    while (messages) {
        total += sizeof(*messages) + messages->length;
        messages = messages->next;
    }

    return total;
}

static int bench_parse_optional(bgp_ribout_config_t *block,
                                const char *line,
                                int (*parse_fn)(bgp_ribout_config_t *,
                                                const char *)) {
    if (!line) {
        return 1;
    }

    return parse_fn(block, line) == 0;
}

/*
 * The FlowSpec lines of a benchmark case: the family, the destination prefix, the components, the color and the
 * actions. Returns 0 on a parse failure.
 */
static int setup_flowspec(bgp_ribout_config_t *block, const ribout_bench_case_t *bench_case) {
    char text[160];

    if (bgp_ribout_parse_address_family(block, bench_case->address_family) != 0 ||
        bgp_ribout_parse_prefix(block, bench_case->prefix_line) != 0 ||
        !bench_parse_optional(block, bench_case->colors, bgp_ribout_parse_color)) {
        return 0;
    }
    for (size_t c = 0; c < 3 && bench_case->flowspec_components[c]; c++) {
        char *args;

        snprintf(text, sizeof(text), "%s", bench_case->flowspec_components[c]);
        args = strchr(text, ' ');
        if (!args) {
            return 0;
        }
        *args++ = '\0';
        if (bgp_ribout_flowspec_parse_component(block, text, args) != 0) {
            return 0;
        }
    }
    for (size_t a = 0; a < 2 && bench_case->flowspec_actions[a]; a++) {
        if (bgp_ribout_flowspec_parse_action(block, bench_case->flowspec_actions[a]) != 0) {
            return 0;
        }
    }
    return 1;
}

/*
 * Configure a block from a benchmark case: FlowSpec lines, SR Policy, EVPN Type 2 or prefix fields, and then the
 * shared attributes. Returns 0 on a parse failure.
 */
static int setup_block(bgp_ribout_config_t *block, const ribout_bench_case_t *bench_case) {
    char prefix_line[64];

    bgp_ribout_init(block, bench_case->name);

    if (bench_case->prefix_line) {
        if (!setup_flowspec(block, bench_case)) {
            return 0;
        }
    } else if (bench_case->endpoint) {
        if (bgp_ribout_parse_distinguisher(block, bench_case->distinguishers) != 0 ||
            bgp_ribout_parse_color(block, bench_case->colors) != 0 ||
            bgp_ribout_parse_endpoint(block, bench_case->endpoint) != 0) {
            return 0;
        }
    } else if (bench_case->mac) {
        if (bgp_ribout_parse_mac(block, bench_case->mac) != 0) {
            return 0;
        }
        if (bench_parse_optional(block, bench_case->ip, bgp_ribout_parse_ip) == 0 ||
            bench_parse_optional(block, bench_case->ip2, bgp_ribout_parse_ip) == 0) {
            return 0;
        }
    } else {
        if (bench_case->prefix_af == AF_INET) {
            snprintf(prefix_line, sizeof(prefix_line), "prefix 10.0.0.0/24 x %d", bench_case->prefixes);
        } else {
            snprintf(prefix_line, sizeof(prefix_line), "prefix 2001:db8::/64 x %d", bench_case->prefixes);
        }

        if (bgp_ribout_parse_prefix(block, prefix_line) != 0) {
            return 0;
        }
    }

    if (!bench_parse_optional(block, bench_case->rds, bgp_ribout_parse_rd) ||
        !bench_parse_optional(block, bench_case->labels, bgp_ribout_parse_label) ||
        !bench_parse_optional(block, bench_case->ethernet_tags, bgp_ribout_parse_ethernet_tag) ||
        !bench_parse_optional(block, bench_case->path_ids, bgp_ribout_parse_path_ids) ||
        !bench_parse_optional(block, bench_case->next_hop, bgp_ribout_parse_next_hop) ||
        !bench_parse_optional(block, bench_case->gateway_ip, bgp_ribout_parse_gateway_ip) ||
        !bench_parse_optional(block, bench_case->esis, bgp_ribout_parse_esi) ||
        !bench_parse_optional(block, bench_case->label2,
                              bgp_ribout_parse_label2)) {
        return 0;
    }

    if (bench_case->as_path) {
        if (bgp_ribout_parse_aspath(block, bench_case->as_path) != 0) {
            return 0;
        }
    } else if (bgp_ribout_parse_aspath(block, "as-path 65001 65002 65003") != 0) {
        return 0;
    }

    if (bench_case->localpref) {
        if (bgp_ribout_parse_localpref(block, bench_case->localpref) != 0) {
            return 0;
        }
    } else if (bgp_ribout_parse_localpref(block, "localpref 200") != 0) {
        return 0;
    }

    return bench_parse_optional(block, bench_case->med, bgp_ribout_parse_med) &&
           bench_parse_optional(block, bench_case->rt, bgp_ribout_parse_rt) &&
           bench_parse_optional(block, bench_case->rt_set, bgp_ribout_parse_rt_set) &&
           bench_parse_optional(block, bench_case->soo, bgp_ribout_parse_soo) &&
           bench_parse_optional(block, bench_case->enlp, bgp_ribout_parse_enlp) &&
           bench_parse_optional(block, bench_case->priority, bgp_ribout_parse_priority) &&
           bench_parse_optional(block, bench_case->preference, bgp_ribout_parse_preference) &&
           bench_parse_optional(block, bench_case->binding_sid, bgp_ribout_parse_binding_sid) &&
           bench_parse_optional(block, bench_case->segment_list, bgp_ribout_parse_segment_list) &&
           bench_parse_optional(block, bench_case->rotate_every, bgp_ribout_parse_rotate_every) &&
           bench_parse_optional(block, bench_case->rotate_period, bgp_ribout_parse_rotate_period) &&
           bench_parse_optional(block, bench_case->community, bgp_ribout_parse_community) &&
           bench_parse_optional(block, bench_case->large_community, bgp_ribout_parse_large_community) &&
           bgp_ribout_parse_origin(block, "origin igp") == 0;
}

static void bench_restore_randseed(const char *saved, int was_set) {
    if (was_set) {
        setenv("RANDSEED", saved, 1);
    } else {
        unsetenv("RANDSEED");
    }
}

/*
 * Configure, generate the map and generate the messages for a case, repetitions times, and print one table row with
 * the averages. The withdrawal stream a withdraw would send is then derived from the snapshot bytes; its time is
 * reported separately and is not part of the total.
 */
static void run_case(const ribout_bench_case_t *bench_case) {
    double      attr_groups = 0.0;
    double      map_bytes = 0.0;
    double      msg_list_bytes = 0.0;
    double      parse_ms = 0.0;
    double      map_ms = 0.0;
    double      message_ms = 0.0;
    double      withdrawal_ms = 0.0;
    double      peak_bytes = -1.0;
    double      avg_msg_list_bytes;
    double      avg_map_bytes;
    double      avg_map_ms;
    double      avg_message_ms;
    double      avg_total_ms;
    size_t      messages = 0;
    uint64_t    paths = 0;
    int         repetition;
    const char *saved_randseed = getenv("RANDSEED");
    char        saved_randseed_buf[128];
    int         had_randseed = 0;
    char        msg_cell[16];
    char        map_cell[16];
    char        path_cell[16];
    char        groups_cell[16];
    char        messages_cell[16];
    char        rate_cell[16];
    char        map_ms_cell[12];
    char        msg_ms_cell[12];
    char        wdr_ms_cell[12];
    char        total_ms_cell[12];
    char        peak_cell[16];

    if (saved_randseed) {
        had_randseed = 1;
        strncpy(saved_randseed_buf, saved_randseed, sizeof(saved_randseed_buf) - 1);
        saved_randseed_buf[sizeof(saved_randseed_buf) - 1] = '\0';
    }

    for (repetition = 0; repetition < bench_case->repetitions; repetition++) {
        bgp_ribout_config_t block;
        bgp_msg_stream_t   *withdrawal;
        double              t0;
        double              t1;
        double              t2;
        double              t3;
        double              t4;

        if (bench_case->randseed) {
            setenv("RANDSEED", bench_case->randseed, 1);
        } else {
            unsetenv("RANDSEED");
        }

        double rss_start = peak_rss_reset() ? proc_status_bytes("VmRSS") : -1.0;

        t0 = now_ms();
        if (!setup_block(&block, bench_case)) {
            fprintf(stderr, "failed to set up ribout benchmark case %s\n", bench_case->name);
            bench_restore_randseed(saved_randseed_buf, had_randseed);
            exit(1);
        }
        paths = bgp_ribout_total_paths(&block);
        t1 = now_ms();

        if (bgp_ribout_generate_map(&block) != 0) {
            fprintf(stderr, "map generation failed for %s\n", bench_case->name);
            bgp_ribout_destroy(&block);
            bench_restore_randseed(saved_randseed_buf, had_randseed);
            exit(1);
        }
        /*
         * entry_count is the effective attribute-group cardinality that
         * ultimately drives UPDATE packing opportunities.
         */
        attr_groups += (double)block.ribout->entry_count;
        /*
         * The map is the more canonical grouped representation, so snapshot
         * its tracked footprint before message generation consumes it.
         */
        map_bytes += (double)bgp_ribout_map_get_memory_usage(block.ribout);
        t2 = now_ms();

        if (bgp_ribout_generate_messages(&block) != 0) {
            fprintf(stderr, "message generation failed for %s\n", bench_case->name);
            bgp_ribout_destroy(&block);
            bench_restore_randseed(saved_randseed_buf, had_randseed);
            exit(1);
        }
        t3 = now_ms();

        withdrawal = bgp_ribout_snapshot_withdrawal(block.snapshot);
        t4 = now_ms();
        if (!withdrawal) {
            fprintf(stderr, "withdrawal derivation failed for %s\n", bench_case->name);
            bgp_ribout_destroy(&block);
            bench_restore_randseed(saved_randseed_buf, had_randseed);
            exit(1);
        }
        bgp_msg_stream_unref(withdrawal);

        parse_ms += (t1 - t0);
        map_ms += (t2 - t1);
        message_ms += (t3 - t2);
        withdrawal_ms += (t4 - t3);
        messages = block.message_count;
        msg_list_bytes += (double)sum_message_list_bytes(block.messages);
        if (rss_start >= 0.0 && proc_status_bytes("VmHWM") - rss_start > peak_bytes) {
            // the case's own peak: generation, the messages and the withdrawal derivation
            peak_bytes = proc_status_bytes("VmHWM") - rss_start;
        }
        bgp_ribout_destroy(&block);
    }

    bench_restore_randseed(saved_randseed_buf, had_randseed);

    avg_msg_list_bytes = msg_list_bytes / (double)bench_case->repetitions;
    avg_map_bytes = map_bytes / (double)bench_case->repetitions;
    avg_map_ms = map_ms / (double)bench_case->repetitions;
    avg_message_ms = message_ms / (double)bench_case->repetitions;
    avg_total_ms = (parse_ms + map_ms + message_ms) /
                   (double)bench_case->repetitions;

    format_paths_cell(paths, path_cell, sizeof(path_cell));
    format_messages_cell((size_t)(attr_groups / (double)bench_case->repetitions), groups_cell, sizeof(groups_cell));
    format_messages_cell(messages, messages_cell, sizeof(messages_cell));
    format_size_cell(avg_msg_list_bytes, msg_cell, sizeof(msg_cell));
    format_size_cell(avg_map_bytes, map_cell, sizeof(map_cell));
    format_time_cell(avg_map_ms, map_ms_cell, sizeof(map_ms_cell));
    format_time_cell(avg_message_ms, msg_ms_cell, sizeof(msg_ms_cell));
    format_time_cell(withdrawal_ms / (double)bench_case->repetitions, wdr_ms_cell, sizeof(wdr_ms_cell));
    format_time_cell(avg_total_ms, total_ms_cell, sizeof(total_ms_cell));
    format_rate_cell((double)paths * 1000.0 / avg_total_ms, rate_cell, sizeof(rate_cell));
    if (peak_bytes >= 0.0) {
        format_size_cell(peak_bytes, peak_cell, sizeof(peak_cell));
    } else {
        snprintf(peak_cell, sizeof(peak_cell), "-");
    }

    printf("%-26s %-5s %7s %4d %7s %7s %8.1f %8s %8s %8s %7s %7s %6s %7s %7s\n",
           bench_case->name,
           bench_case->af_name,
           path_cell,
           bench_case->repetitions,
           groups_cell,
           messages_cell,
           messages ? ((double)paths / (double)messages) : 0.0,
           msg_cell,
           map_cell,
           peak_cell,
           map_ms_cell,
           msg_ms_cell,
           total_ms_cell,
           rate_cell,
           wdr_ms_cell);
}

int main(void) {
    size_t i;

    printf("Ribout Pipeline\n\n");
    printf("%-26s %-5s %7s %4s %7s %7s %8s %8s %8s %8s %7s %7s %6s %7s %7s\n",
           "case",
           "af",
           "paths",
           "runs",
           "groups",
           "msgs",
           "nlri/msg",
           "msg(mem)",
           "map(mem)",
           "peak(+)",
           "map(ms)",
           "msg(ms)",
           "total",
           "paths/s",
           "wdr(ms)");
    printf("%-26s %-5s %7s %4s %7s %7s %8s %8s %8s %8s %7s %7s %6s %7s %7s\n",
           "--------------------------",
           "-----",
           "-------",
           "----",
           "-------",
           "-------",
           "--------",
           "--------",
           "--------",
           "--------",
           "-------",
           "-------",
           "------",
           "-------",
           "-------");

    /*
     * Each case runs in a child of its own, so its peak resident size starts from the same small baseline and no
     * case reuses memory an earlier one left in the allocator.
     */
    for (i = 0; i < sizeof(k_cases) / sizeof(k_cases[0]); i++) {
        pid_t child;
        int   status = 0;

        fflush(stdout);
        child = fork();
        if (child == 0) {
            run_case(&k_cases[i]);
            fflush(stdout);
            _exit(0);
        }
        if (child < 0) {
            run_case(&k_cases[i]);
        } else if (waitpid(child, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "benchmark case %s failed\n", k_cases[i].name);
            return 1;
        }
    }

    return 0;
}
