#ifndef TEST_NLRI_TEMPLATES_H
#define TEST_NLRI_TEMPLATES_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/*
 * Independent RFC vectors, shared by pipeline and socket tests. No production encoder constructs expectations.
 */
typedef struct {
    const char *name, *command, *hex;
    uint16_t    afi;
    uint8_t     safi, step_octet, count;
    const char *attrs[3];  /* Further ribout lines the vector depends on, such as its encapsulation */
} template_vector_t;

#define RD     "0000fde800000001"
#define ESI    "00000000000000000000"
#define R4     "c0000201"
#define R6     "20010db8000000000000000000000001"
#define S4     "c6336401"
#define S6     "20010db8000100000000000000000001"
#define G4     "ef010101"
#define G6     "ff3e0000000000000000000000000001"
#define LOCAL  "01000010020000040000fde80203000401020304"
#define REMOTE "01010010020000040000fde90203000405060708"
#define IDENT  "0000000000000001"
#define K2     "020c" RD "0000fde9"

#define TEMPLATE_LS_NODE_COMMAND "nlri bgp-ls node protocol 3 identifier 1 local-as 65000 local-router 1.2.3.4"

static const template_vector_t template_vectors[] = {
    {"RTC", "nlri rtc origin-as 65000 target 65000:100", "600000fde80002fde800000064", 1, 132, 12, 3},
    {"RTC default", "nlri rtc default", "00", 1, 132, 0, 1},
    {"VPLS", "nlri vpls rd 65000:1 ve-id 1 offset 0 size 8 label-base 1000",
        "0011" RD "000100000008003e81", 25, 65, 11, 3},
    {"EVPN 1", "nlri evpn type1 rd 65000:1 esi 0 ethernet-tag 1 label 1000",
        "0119" RD ESI "00000001003e81", 25, 70, 9, 3},
    {"EVPN 3 IPv4", "nlri evpn type3 rd 65000:1 ethernet-tag 1 router 192.0.2.1",
        "0311" RD "0000000120" R4, 25, 70, 18, 3},
    {"EVPN 3 IPv6", "nlri evpn type3 rd 65000:1 ethernet-tag 1 router 2001:db8::1",
        "031d" RD "0000000180" R6, 25, 70, 30, 3},
    {"EVPN 4 IPv4", "nlri evpn type4 rd 65000:1 esi 0 router 192.0.2.1",
        "0417" RD ESI "20" R4, 25, 70, 24, 3},
    {"EVPN 4 IPv6", "nlri evpn type4 rd 65000:1 esi 0 router 2001:db8::1",
        "0423" RD ESI "80" R6, 25, 70, 36, 3},
    // RFC 8365 section 5.1.3: VXLAN multihoming. The Type 1 label field is a whole 24-bit VNI (16000000 = f42400).
    {"EVPN 1 per-EVI VXLAN", "nlri evpn type1 rd 65000:1 esi 0 ethernet-tag 1 label 16000000",
        "0119" RD ESI "00000001f42400", 25, 70, 9, 3, {"encap vxlan"}},
    {"EVPN 1 per-ES VXLAN", "nlri evpn type1 rd 65000:1 esi 0 ethernet-tag max label 0",
        "0119" RD ESI "ffffffff000000", 25, 70, 9, 3, {"encap vxlan", "esi-label flags 1 label 0"}},
    {"EVPN 3 VXLAN", "nlri evpn type3 rd 65000:1 ethernet-tag 1 router 192.0.2.1",
        "0311" RD "0000000120" R4, 25, 70, 18, 3, {"encap vxlan", "pmsi flags 0 type 6 label 16000000 id c0000201"}},
    {"EVPN 4 VXLAN", "nlri evpn type4 rd 65000:1 esi 0 router 192.0.2.1",
        "0417" RD ESI "20" R4, 25, 70, 24, 3, {"encap vxlan", "es-import mac 00:aa:00:00:00:01"}},
    // One route per Ethernet segment: the template steps the last octet of the ESI (octet 19 of the NLRI).
    {"EVPN 1 per-ES, step esi", "nlri evpn type1 rd 65000:1 esi 0 ethernet-tag max label 0 step esi",
        "0119" RD ESI "ffffffff000001", 25, 70, 19, 3},
    {"EVPN 4, step esi", "nlri evpn type4 rd 65000:1 esi 0 router 192.0.2.1 step esi",
        "0417" RD ESI "20" R4, 25, 70, 19, 3},
    {"MVPN4 1", "nlri mvpn4 type1 rd 65000:1 router 192.0.2.1", "010c" RD R4, 1, 5, 9, 3},
    {"MVPN6 1", "nlri mvpn6 type1 rd 65000:1 router 2001:db8::1", "0118" RD R6, 2, 5, 9, 3},
    {"MVPN4 2", "nlri mvpn4 type2 rd 65000:1 source-as 65001", K2, 1, 5, 9, 3},
    {"MVPN6 2", "nlri mvpn6 type2 rd 65000:1 source-as 65001", K2, 2, 5, 9, 3},
    {"MVPN4 3", "nlri mvpn4 type3 rd 65000:1 source 198.51.100.1 group 239.1.1.1 router 192.0.2.1",
        "0316" RD "20" S4 "20" G4 R4, 1, 5, 9, 3},
    {"MVPN6 3", "nlri mvpn6 type3 rd 65000:1 source 2001:db8:1::1 group ff3e::1 router 2001:db8::1",
        "033a" RD "80" S6 "80" G6 R6, 2, 5, 9, 3},
    {"MVPN4 4", "nlri mvpn4 type4 route-key " K2 " router 192.0.2.1", "0412" K2 R4, 1, 5, 19, 3},
    {"MVPN6 4", "nlri mvpn6 type4 route-key " K2 " router 2001:db8::1", "041e" K2 R6, 2, 5, 31, 3},
    {"MVPN4 5", "nlri mvpn4 type5 rd 65000:1 source 198.51.100.1 group 239.1.1.1",
        "0512" RD "20" S4 "20" G4, 1, 5, 9, 3},
    {"MVPN6 5", "nlri mvpn6 type5 rd 65000:1 source 2001:db8:1::1 group ff3e::1",
        "052a" RD "80" S6 "80" G6, 2, 5, 9, 3},
    {"MVPN4 6", "nlri mvpn4 type6 rd 65000:1 source-as 65001 source 198.51.100.1 group 239.1.1.1",
        "0616" RD "0000fde920" S4 "20" G4, 1, 5, 9, 3},
    {"MVPN6 6", "nlri mvpn6 type6 rd 65000:1 source-as 65001 source 2001:db8:1::1 group ff3e::1",
        "062e" RD "0000fde980" S6 "80" G6, 2, 5, 9, 3},
    {"MVPN4 7", "nlri mvpn4 type7 rd 65000:1 source-as 65001 source 198.51.100.1 group 239.1.1.1",
        "0716" RD "0000fde920" S4 "20" G4, 1, 5, 9, 3},
    {"MVPN6 7", "nlri mvpn6 type7 rd 65000:1 source-as 65001 source 2001:db8:1::1 group ff3e::1",
        "072e" RD "0000fde980" S6 "80" G6, 2, 5, 9, 3},
    {"BGP-LS node", TEMPLATE_LS_NODE_COMMAND,
        "0001001d03" IDENT LOCAL, 16388, 71, 12, 3},
    {"BGP-LS link", "nlri bgp-ls link protocol 3 identifier 1 local-as 65000 local-router 1.2.3.4 "
                      "remote-as 65001 remote-router 5.6.7.8 local-id 10 remote-id 20",
        "0002003d03" IDENT LOCAL REMOTE "010200080000000a00000014", 16388, 71, 12, 3},
    {"BGP-LS IPv4 prefix", "nlri bgp-ls ipv4-prefix protocol 3 identifier 1 local-as 65000 local-router 1.2.3.4 "
                             "prefix 10.0.0.0/24", "0003002503" IDENT LOCAL "01090004180a0000", 16388, 71, 12, 3},
    {"BGP-LS IPv6 prefix", "nlri bgp-ls ipv6-prefix protocol 3 identifier 1 local-as 65000 local-router 1.2.3.4 "
                             "prefix 2001:db8::/64", "0004002a03" IDENT LOCAL "010900094020010db800000000",
        16388, 71, 12, 3},
    // BGP-LS identity axes and descriptors (RFC 9552 section 5.2, RFC 9514 section 6). Offsets: the NLRI header,
    // Protocol-ID and Identifier take 13 octets; LOCAL takes 20, so its Router-ID ends at octet 32.
    {"BGP-LS node, step node", TEMPLATE_LS_NODE_COMMAND " step node", "0001001d03" IDENT LOCAL, 16388, 71, 32, 3,
        {"ls node-name r1", "ls sr-algorithm 0 1"}},
    {"BGP-LS link by address", "nlri bgp-ls link protocol 3 identifier 1 local-as 65000 local-router 1.2.3.4 "
                                 "remote-as 65001 remote-router 5.6.7.8 local-ip 10.0.0.1 remote-ip 10.0.0.2 mt-id 2",
        "0002004703" IDENT LOCAL REMOTE "010300040a000001" "010400040a000002" "010700020002", 16388, 71, 12, 3,
        {"ls te-metric 100", "ls adj-sid flags v,l label 24001", "ls max-bandwidth 10g"}},
    {"BGP-LS prefix, step prefix", "nlri bgp-ls ipv4-prefix protocol 3 identifier 1 local-as 65000 local-router 1.2.3.4 "
                                     "mt-id 2 ospf-route-type 1 prefix 10.0.0.0/24 step prefix",
        "0003003003" IDENT LOCAL "010700020002" "0108000101" "01090004180a0000", 16388, 71, 51, 3,
        {"ls prefix-sid flags np index 100", "ls prefix-metric 20"}},
    {"BGP-LS SRv6 SID, step sid", "nlri bgp-ls srv6-sid protocol isis-l2 identifier 1 local-as 65000 "
                                    "local-router 0000.0000.0001 sid fc00:0:1:1::/64 step sid",
        "0006003302" IDENT "01000012020000040000fde802030006000000000001"
        "02060010fc000000000100010000000000000000", 16388, 71, 46, 3,
        {"ls srv6-endpoint-behavior end", "ls srv6-sid-structure 32 16 16 0"}},
    // RFC 9086: a BGP peering link. Both nodes are named by AS and BGP Router-ID (TLV 516); the local one also has
    // its BGP-LS Identifier and confederation Member-AS. The remote node descriptor ends at octet 68.
    {"BGP-LS EPE link, step remote",
        "nlri bgp-ls link protocol bgp identifier 1 local-as 65000 local-bgp-ls-id 1 local-router 10.0.0.1 "
        "local-member-as 65010 remote-as 65001 remote-router 10.0.0.2 local-ip 192.0.2.1 remote-ip 192.0.2.2 step remote",
        "0002005107" IDENT "01000020" "020000040000fde8" "0201000400000001" "020400040a000001" "020500040000fdf2"
        "01010010" "020000040000fde9" "020400040a000002" "01030004c0000201" "01040004c0000202", 16388, 71, 68, 3,
        {"ls peer-node-sid flags v,l label 30001", "ls peer-adj-sid flags v,l,b label 30100", "ls peer-set-sid index 5"}},
    // RFC 9857: an SR Policy candidate path. The headend is named by AS, BGP Router-ID and TE Router-ID; the
    // descriptor (TLV 554) holds origin, flags, endpoint, color, originator and discriminator. The color ends at
    // octet 56.
    {"BGP-LS SR Policy candidate path, step color",
        "nlri bgp-ls sr-policy protocol sr identifier 1 local-as 65000 local-router 10.0.0.1 "
        "local-te-router-id 10.0.0.1 origin bgp endpoint 192.0.2.9 color 100 originator-as 65000 originator 10.0.0.1 "
        "discriminator 1 step color",
        "0005004109" IDENT "01000018" "020000040000fde8" "020400040a000001" "040400040a000001"
        "022a0018" "02000000" "c0000209" "00000064" "0000fde8" "0a000001" "00000001", 16388, 71, 56, 3,
        {"ls cp-state priority 1 flags a,e,v preference 100", "ls sr-binding-sid flags b,l label 15000",
         "ls policy-name gold"}},
    {"MVPN4 4 S-PMSI key", "nlri mvpn4 type4 route-key 0316" RD "20" S4 "20" G4 R4 " router 192.0.2.1",
        "041c0316" RD "20" S4 "20" G4 R4 R4, 1, 5, 29, 3},
    {"MVPN6 4 S-PMSI key", "nlri mvpn6 type4 route-key 033a" RD "80" S6 "80" G6 R6 " router 2001:db8::1",
        "044c033a" RD "80" S6 "80" G6 R6 R6, 2, 5, 77, 3},
};
#undef RD
#undef ESI
#undef R4
#undef R6
#undef S4
#undef S6
#undef G4
#undef G6
#undef LOCAL
#undef REMOTE
#undef IDENT
#undef K2

static inline size_t template_expected(const template_vector_t *v, unsigned instance, int add_path, unsigned path_id,
                                        uint8_t *out) {
    size_t ap = add_path ? 4 : 0, len = strlen(v->hex) / 2;
    if (add_path) {
        out[0] = (uint8_t)(path_id >> 24);
        out[1] = (uint8_t)(path_id >> 16);
        out[2] = (uint8_t)(path_id >> 8);
        out[3] = (uint8_t)path_id;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned byte;
        if (sscanf(v->hex + 2 * i, "%2x", &byte) != 1) return 0;
        out[ap + i] = (uint8_t)byte;
    }
    for (size_t at = ap + v->step_octet + 1; instance && at > ap;) {
        at--;
        instance += out[at];
        out[at] = (uint8_t)instance;
        instance >>= 8;
    }
    return len + ap;
}

#endif
