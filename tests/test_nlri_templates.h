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
