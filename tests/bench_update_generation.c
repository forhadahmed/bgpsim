#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "bgp.h"
#include "bgp_update.h"
#include "test_helpers.h"

typedef struct {
    int prefixes;
    int repetitions;
} bench_scale_t;

static const bench_scale_t k_scales[] = {
    {10000, 10},
    {50000, 3},
};

static double now_ms(void) {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

static uint64_t sum_message_bytes(const bgp_update_result_t *result) {
    uint64_t total = 0;
    int      i;

    for (i = 0; i < result->num_messages; i++) {
        total += result->message_lens[i];
    }

    return total;
}

static bgp_path_attr_t *make_ipv4_attrs(void) {
    bgp_path_attr_t *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    bgp_path_attr_t *as_path;
    bgp_path_attr_t *next_hop_attr;
    bgp_path_attr_t *local_pref;
    bgp_next_hop_t   next_hop = make_ipv4_next_hop("192.0.2.1");
    uint32_t asns[] = {65001, 65002, 65003};
    as_path_segment_t segment = {BGP_AS_SEQUENCE, 3, asns};

    if (!origin) {
        return NULL;
    }

    as_path = bgp_attr_create_as_path(&segment, 1);
    next_hop_attr = bgp_attr_create_next_hop(&next_hop);
    local_pref = bgp_attr_create_local_pref(200);
    if (!as_path || !next_hop_attr || !local_pref) {
        bgp_path_attr_free(origin);
        bgp_path_attr_free(as_path);
        bgp_path_attr_free(next_hop_attr);
        bgp_path_attr_free(local_pref);
        return NULL;
    }

    origin->next = as_path;
    as_path->next = next_hop_attr;
    next_hop_attr->next = local_pref;
    return origin;
}

static bgp_path_attr_t *make_mp_attrs(void) {
    bgp_path_attr_t *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    bgp_path_attr_t *as_path;
    bgp_path_attr_t *local_pref;
    uint32_t asns[] = {65001, 65002, 65003};
    as_path_segment_t segment = {BGP_AS_SEQUENCE, 3, asns};

    if (!origin) {
        return NULL;
    }

    as_path = bgp_attr_create_as_path(&segment, 1);
    local_pref = bgp_attr_create_local_pref(200);
    if (!as_path || !local_pref) {
        bgp_path_attr_free(origin);
        bgp_path_attr_free(as_path);
        bgp_path_attr_free(local_pref);
        return NULL;
    }

    origin->next = as_path;
    as_path->next = local_pref;
    return origin;
}

static ipv4_nlri_list_t *build_ipv4_nlri(int prefixes) {
    ipv4_nlri_list_t *list = NULL;
    ipv4_nlri_list_t *tail = NULL;
    int               i;

    for (i = 0; i < prefixes; i++) {
        char prefix[32];

        snprintf(prefix,
                 sizeof(prefix),
                 "10.%u.%u.%u",
                 (unsigned int)((i >> 16) & 0xFF),
                 (unsigned int)((i >> 8) & 0xFF),
                 (unsigned int)(i & 0xFF));
        ipv4_nlri_add_tail(&list, &tail, prefix, 24);
    }

    return list;
}

static ipv6_nlri_list_t *build_ipv6_nlri(int prefixes) {
    ipv6_nlri_list_t *list = NULL;
    ipv6_nlri_list_t *tail = NULL;
    int               i;

    for (i = 0; i < prefixes; i++) {
        char prefix[64];

        snprintf(prefix,
                 sizeof(prefix),
                 "2001:db8:%x:%x::",
                 (unsigned int)((i >> 16) & 0xFFFF),
                 (unsigned int)(i & 0xFFFF));
        ipv6_nlri_add_tail(&list, &tail, prefix, 64);
    }

    return list;
}

static vpnv4_nlri_list_t *build_vpnv4_nlri(int prefixes) {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    vpnv4_nlri_list_t    *list = NULL;
    vpnv4_nlri_list_t    *tail = NULL;
    int                   i;

    for (i = 0; i < prefixes; i++) {
        char prefix[32];

        snprintf(prefix,
                 sizeof(prefix),
                 "10.%u.%u.%u",
                 (unsigned int)((i >> 16) & 0xFF),
                 (unsigned int)((i >> 8) & 0xFF),
                 (unsigned int)(i & 0xFF));
        vpnv4_nlri_add_tail(&list, &tail, prefix, 24, 16000U + (uint32_t)(i & 0x3FF), rd);
    }

    return list;
}

static vpnv6_nlri_list_t *build_vpnv6_nlri(int prefixes) {
    route_distinguisher_t rd = rd_create_type1(0x0A000001U, 1);
    vpnv6_nlri_list_t    *list = NULL;
    vpnv6_nlri_list_t    *tail = NULL;
    int                   i;

    for (i = 0; i < prefixes; i++) {
        char prefix[64];

        snprintf(prefix,
                 sizeof(prefix),
                 "2001:db8:%x:%x::",
                 (unsigned int)((i >> 16) & 0xFFFF),
                 (unsigned int)(i & 0xFFFF));
        vpnv6_nlri_add_tail(&list, &tail, prefix, 64, 20000U + (uint32_t)(i & 0x3FF), rd);
    }

    return list;
}

static labeled_ipv4_nlri_t *build_labeled_ipv4_nlri(int prefixes) {
    labeled_ipv4_nlri_t *list = NULL;
    labeled_ipv4_nlri_t *tail = NULL;
    int                  i;

    for (i = 0; i < prefixes; i++) {
        char prefix[32];

        snprintf(prefix,
                 sizeof(prefix),
                 "10.%u.%u.%u",
                 (unsigned int)((i >> 16) & 0xFF),
                 (unsigned int)((i >> 8) & 0xFF),
                 (unsigned int)(i & 0xFF));
        labeled_ipv4_nlri_add_tail(&list, &tail, prefix, 24, 16000U + (uint32_t)(i & 0x3FF));
    }

    return list;
}

static labeled_ipv6_nlri_t *build_labeled_ipv6_nlri(int prefixes) {
    labeled_ipv6_nlri_t *list = NULL;
    labeled_ipv6_nlri_t *tail = NULL;
    int                  i;

    for (i = 0; i < prefixes; i++) {
        char prefix[64];

        snprintf(prefix,
                 sizeof(prefix),
                 "2001:db8:%x:%x::",
                 (unsigned int)((i >> 16) & 0xFFFF),
                 (unsigned int)(i & 0xFFFF));
        labeled_ipv6_nlri_add_tail(&list, &tail, prefix, 64, 32000U + (uint32_t)(i & 0x3FF));
    }

    return list;
}

static void format_case_name(char *buf, size_t buflen, const char *family, int prefixes) {
    if (prefixes >= 1000 && (prefixes % 1000) == 0) {
        snprintf(buf, buflen, "%s-%dk", family, prefixes / 1000);
    } else {
        snprintf(buf, buflen, "%s-%d", family, prefixes);
    }
}

static void format_size(double bytes, char *buf, size_t buf_len) {
    if (bytes >= (1024.0 * 1024.0)) {
        snprintf(buf, buf_len, "%.2fmb", bytes / (1024.0 * 1024.0));
    } else {
        snprintf(buf, buf_len, "%.2fkb", bytes / 1024.0);
    }
}

static void format_time(double ms, char *buf, size_t buf_len) {
    if (ms < 1.0) {
        snprintf(buf, buf_len, "<1ms");
    } else {
        snprintf(buf, buf_len, "%.0fms", ms);
    }
}

static void format_rate(double paths_per_sec, char *buf, size_t buf_len) {
    snprintf(buf, buf_len, "%.0fk", paths_per_sec / 1000.0);
}

static void print_result(const char *family,
                         int prefixes,
                         int repetitions,
                         int messages,
                         uint64_t bytes,
                         double total_ms) {
    char case_name[32];
    char paths_cell[16], wire_cell[16], time_cell[16], rate_cell[16];
    double avg_ms = total_ms / (double)repetitions;
    double nlri_per_msg = messages ? ((double)prefixes / (double)messages) : 0.0;
    double prefixes_per_sec = ((double)prefixes * 1000.0) / avg_ms;

    format_case_name(case_name, sizeof(case_name), family, prefixes);
    snprintf(paths_cell, sizeof(paths_cell), "%.1fk", (double)prefixes / 1000.0);
    format_size((double)bytes, wire_cell, sizeof(wire_cell));
    format_time(avg_ms, time_cell, sizeof(time_cell));
    format_rate(prefixes_per_sec, rate_cell, sizeof(rate_cell));

    printf("%-20s %8s %4d %8d %8.1f %9s %6s %9s\n",
           case_name,
           paths_cell,
           repetitions,
           messages,
           nlri_per_msg,
           wire_cell,
           time_cell,
           rate_cell);
}

static void bench_ipv4_updates(void) {
    bgp_path_attr_t *attrs = make_ipv4_attrs();
    size_t           i;

    if (!attrs) {
        fprintf(stderr, "failed to build IPv4 path attributes\n");
        exit(1);
    }

    for (i = 0; i < sizeof(k_scales) / sizeof(k_scales[0]); i++) {
        ipv4_nlri_list_t *nlri = build_ipv4_nlri(k_scales[i].prefixes);
        double            start_ms;
        double            total_ms;
        int               repetition;
        int               messages = 0;
        uint64_t          bytes = 0;

        if (!nlri) {
            fprintf(stderr, "failed to build IPv4 NLRI list\n");
            exit(1);
        }

        start_ms = now_ms();
        for (repetition = 0; repetition < k_scales[i].repetitions; repetition++) {
            bgp_update_result_t *result =
                bgp_generate_update_ipv4(nlri, attrs, NULL, BGP_MAX_PDU_SIZE);

            if (!result) {
                fprintf(stderr, "IPv4 UPDATE generation failed\n");
                exit(1);
            }

            messages = result->num_messages;
            bytes = sum_message_bytes(result);
            bgp_update_result_free(result);
        }
        total_ms = now_ms() - start_ms;

        print_result("ipv4", k_scales[i].prefixes, k_scales[i].repetitions, messages, bytes, total_ms);
        ipv4_nlri_list_free(nlri);
    }

    bgp_path_attr_list_free(attrs);
}

static void bench_ipv6_updates(void) {
    bgp_path_attr_t *attrs = make_mp_attrs();
    bgp_next_hop_t   next_hop = make_ipv6_next_hop("2001:db8::1");
    size_t           i;

    if (!attrs) {
        fprintf(stderr, "failed to build IPv6 path attributes\n");
        exit(1);
    }

    for (i = 0; i < sizeof(k_scales) / sizeof(k_scales[0]); i++) {
        ipv6_nlri_list_t *nlri = build_ipv6_nlri(k_scales[i].prefixes);
        double            start_ms;
        double            total_ms;
        int               repetition;
        int               messages = 0;
        uint64_t          bytes = 0;

        if (!nlri) {
            fprintf(stderr, "failed to build IPv6 NLRI list\n");
            exit(1);
        }

        start_ms = now_ms();
        for (repetition = 0; repetition < k_scales[i].repetitions; repetition++) {
            bgp_update_result_t *result =
                bgp_generate_update_ipv6(nlri, attrs, NULL, BGP_MAX_PDU_SIZE, &next_hop);

            if (!result) {
                fprintf(stderr, "IPv6 UPDATE generation failed\n");
                exit(1);
            }

            messages = result->num_messages;
            bytes = sum_message_bytes(result);
            bgp_update_result_free(result);
        }
        total_ms = now_ms() - start_ms;

        print_result("ipv6", k_scales[i].prefixes, k_scales[i].repetitions, messages, bytes, total_ms);
        ipv6_nlri_list_free(nlri);
    }

    bgp_path_attr_list_free(attrs);
}

static void bench_vpnv4_updates(void) {
    bgp_path_attr_t *attrs = make_mp_attrs();
    bgp_next_hop_t   next_hop = make_ipv4_next_hop("198.51.100.1");
    size_t           i;

    if (!attrs) {
        fprintf(stderr, "failed to build VPNv4 path attributes\n");
        exit(1);
    }

    for (i = 0; i < sizeof(k_scales) / sizeof(k_scales[0]); i++) {
        vpnv4_nlri_list_t *nlri = build_vpnv4_nlri(k_scales[i].prefixes);
        double             start_ms;
        double             total_ms;
        int                repetition;
        int                messages = 0;
        uint64_t           bytes = 0;

        if (!nlri) {
            fprintf(stderr, "failed to build VPNv4 NLRI list\n");
            exit(1);
        }

        start_ms = now_ms();
        for (repetition = 0; repetition < k_scales[i].repetitions; repetition++) {
            bgp_update_result_t *result =
                bgp_generate_update_vpnv4(nlri, attrs, NULL, BGP_MAX_PDU_SIZE, BGP_VPN_TRANSPORT_IPV4, &next_hop);

            if (!result) {
                fprintf(stderr, "VPNv4 UPDATE generation failed\n");
                exit(1);
            }

            messages = result->num_messages;
            bytes = sum_message_bytes(result);
            bgp_update_result_free(result);
        }
        total_ms = now_ms() - start_ms;

        print_result("vpnv4", k_scales[i].prefixes, k_scales[i].repetitions, messages, bytes, total_ms);
        vpnv4_nlri_list_free(nlri);
    }

    bgp_path_attr_list_free(attrs);
}

static void bench_vpnv6_updates(void) {
    bgp_path_attr_t *attrs = make_mp_attrs();
    bgp_next_hop_t   next_hop = make_ipv6_next_hop("2001:db8::2");
    size_t           i;

    if (!attrs) {
        fprintf(stderr, "failed to build VPNv6 path attributes\n");
        exit(1);
    }

    for (i = 0; i < sizeof(k_scales) / sizeof(k_scales[0]); i++) {
        vpnv6_nlri_list_t *nlri = build_vpnv6_nlri(k_scales[i].prefixes);
        double             start_ms;
        double             total_ms;
        int                repetition;
        int                messages = 0;
        uint64_t           bytes = 0;

        if (!nlri) {
            fprintf(stderr, "failed to build VPNv6 NLRI list\n");
            exit(1);
        }

        start_ms = now_ms();
        for (repetition = 0; repetition < k_scales[i].repetitions; repetition++) {
            bgp_update_result_t *result =
                bgp_generate_update_vpnv6(nlri, attrs, NULL, BGP_MAX_PDU_SIZE, BGP_VPN_TRANSPORT_IPV6, &next_hop);

            if (!result) {
                fprintf(stderr, "VPNv6 UPDATE generation failed\n");
                exit(1);
            }

            messages = result->num_messages;
            bytes = sum_message_bytes(result);
            bgp_update_result_free(result);
        }
        total_ms = now_ms() - start_ms;

        print_result("vpnv6", k_scales[i].prefixes, k_scales[i].repetitions, messages, bytes, total_ms);
        vpnv6_nlri_list_free(nlri);
    }

    bgp_path_attr_list_free(attrs);
}

static void bench_labeled_ipv4_updates(void) {
    bgp_path_attr_t *attrs = make_mp_attrs();
    bgp_next_hop_t   next_hop = make_ipv4_next_hop("192.0.2.1");
    size_t           i;

    if (!attrs) {
        fprintf(stderr, "failed to build labeled IPv4 path attributes\n");
        exit(1);
    }

    for (i = 0; i < sizeof(k_scales) / sizeof(k_scales[0]); i++) {
        labeled_ipv4_nlri_t *nlri = build_labeled_ipv4_nlri(k_scales[i].prefixes);
        double               start_ms;
        double               total_ms;
        int                  repetition;
        int                  messages = 0;
        uint64_t             bytes = 0;

        if (!nlri) {
            fprintf(stderr, "failed to build labeled IPv4 NLRI list\n");
            exit(1);
        }

        start_ms = now_ms();
        for (repetition = 0; repetition < k_scales[i].repetitions; repetition++) {
            bgp_update_result_t *result =
                bgp_generate_update_labeled_ipv4(nlri, attrs, NULL, BGP_MAX_PDU_SIZE, &next_hop);

            if (!result) {
                fprintf(stderr, "labeled IPv4 UPDATE generation failed\n");
                exit(1);
            }

            messages = result->num_messages;
            bytes = sum_message_bytes(result);
            bgp_update_result_free(result);
        }
        total_ms = now_ms() - start_ms;

        print_result("lu4", k_scales[i].prefixes, k_scales[i].repetitions, messages, bytes, total_ms);
        labeled_ipv4_nlri_list_free(nlri);
    }

    bgp_path_attr_list_free(attrs);
}

static void bench_labeled_ipv4_ext_nh_updates(void) {
    bgp_path_attr_t *attrs = make_mp_attrs();
    bgp_next_hop_t   next_hop = make_ipv6_next_hop("2001:db8::1");
    size_t           i;

    if (!attrs) {
        fprintf(stderr, "failed to build labeled IPv4 ext-nh path attributes\n");
        exit(1);
    }

    for (i = 0; i < sizeof(k_scales) / sizeof(k_scales[0]); i++) {
        labeled_ipv4_nlri_t *nlri = build_labeled_ipv4_nlri(k_scales[i].prefixes);
        double               start_ms;
        double               total_ms;
        int                  repetition;
        int                  messages = 0;
        uint64_t             bytes = 0;

        if (!nlri) {
            fprintf(stderr, "failed to build labeled IPv4 ext-nh NLRI list\n");
            exit(1);
        }

        start_ms = now_ms();
        for (repetition = 0; repetition < k_scales[i].repetitions; repetition++) {
            bgp_update_result_t *result =
                bgp_generate_update_labeled_ipv4(nlri, attrs, NULL, BGP_MAX_PDU_SIZE, &next_hop);

            if (!result) {
                fprintf(stderr, "labeled IPv4 ext-nh UPDATE generation failed\n");
                exit(1);
            }

            messages = result->num_messages;
            bytes = sum_message_bytes(result);
            bgp_update_result_free(result);
        }
        total_ms = now_ms() - start_ms;

        print_result("lu4-ext-nh", k_scales[i].prefixes, k_scales[i].repetitions, messages, bytes, total_ms);
        labeled_ipv4_nlri_list_free(nlri);
    }

    bgp_path_attr_list_free(attrs);
}

static void bench_labeled_ipv6_updates(void) {
    bgp_path_attr_t *attrs = make_mp_attrs();
    bgp_next_hop_t   next_hop = make_ipv6_next_hop("2001:db8::2");
    size_t           i;

    if (!attrs) {
        fprintf(stderr, "failed to build labeled IPv6 path attributes\n");
        exit(1);
    }

    for (i = 0; i < sizeof(k_scales) / sizeof(k_scales[0]); i++) {
        labeled_ipv6_nlri_t *nlri = build_labeled_ipv6_nlri(k_scales[i].prefixes);
        double               start_ms;
        double               total_ms;
        int                  repetition;
        int                  messages = 0;
        uint64_t             bytes = 0;

        if (!nlri) {
            fprintf(stderr, "failed to build labeled IPv6 NLRI list\n");
            exit(1);
        }

        start_ms = now_ms();
        for (repetition = 0; repetition < k_scales[i].repetitions; repetition++) {
            bgp_update_result_t *result =
                bgp_generate_update_labeled_ipv6(nlri, attrs, NULL, BGP_MAX_PDU_SIZE, &next_hop);

            if (!result) {
                fprintf(stderr, "labeled IPv6 UPDATE generation failed\n");
                exit(1);
            }

            messages = result->num_messages;
            bytes = sum_message_bytes(result);
            bgp_update_result_free(result);
        }
        total_ms = now_ms() - start_ms;

        print_result("lu6", k_scales[i].prefixes, k_scales[i].repetitions, messages, bytes, total_ms);
        labeled_ipv6_nlri_list_free(nlri);
    }

    bgp_path_attr_list_free(attrs);
}

/*
 * FlowSpec: one rule per path, "dst-prefix <n>/32 protocol =6 dst-port =80 =443".
 */
static flowspec_nlri_t *build_flowspec_nlri(int rules, uint16_t afi, int vpn) {
    flowspec_op_value_t protocol[] = {{FLOWSPEC_OP_END | FLOWSPEC_OP_EQ, 6}};
    flowspec_op_value_t ports[] = {
        {FLOWSPEC_OP_EQ, 80},
        {FLOWSPEC_OP_END | FLOWSPEC_OP_LEN_2 | FLOWSPEC_OP_EQ, 443},
    };
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    flowspec_nlri_t      *list = NULL;
    flowspec_nlri_t      *tail = NULL;
    int                   i;

    for (i = 0; i < rules; i++) {
        flowspec_component_t comps[3];
        flowspec_rule_t      rule = {comps, 3};
        flowspec_nlri_t     *nlri;

        memset(comps, 0, sizeof(comps));
        comps[0].type = FLOWSPEC_DEST_PREFIX;
        if (afi == AFI_IPV4) {
            comps[0].prefix_len = 32;
            comps[0].prefix[0] = 10;
            comps[0].prefix[1] = (uint8_t)(i >> 16);
            comps[0].prefix[2] = (uint8_t)(i >> 8);
            comps[0].prefix[3] = (uint8_t)i;
        } else {
            comps[0].prefix_len = 128;
            comps[0].prefix[0] = 0x20;
            comps[0].prefix[1] = 0x01;
            comps[0].prefix[2] = 0x0d;
            comps[0].prefix[3] = 0xb8;
            comps[0].prefix[13] = (uint8_t)(i >> 16);
            comps[0].prefix[14] = (uint8_t)(i >> 8);
            comps[0].prefix[15] = (uint8_t)i;
        }
        comps[1].type = FLOWSPEC_IP_PROTOCOL;
        comps[1].values = protocol;
        comps[1].num_values = 1;
        comps[2].type = FLOWSPEC_DEST_PORT;
        comps[2].values = ports;
        comps[2].num_values = 2;

        nlri = vpn ? flowspec_nlri_create_vpn(&rule, rd) : flowspec_nlri_create(&rule);
        if (!nlri) {
            flowspec_nlri_list_free(list);
            return NULL;
        }
        flowspec_nlri_append(&list, &tail, nlri);
    }

    return list;
}

/*
 * Time UPDATE generation for a FlowSpec family (traffic-rate 0 action) at every k_scales size.
 */
static void bench_flowspec_updates(const char *family, uint16_t afi, uint8_t safi) {
    bgp_path_attr_t           *attrs = make_mp_attrs();
    bgp_path_attr_t           *tail = attrs;
    bgp_flowspec_update_opts_t opts;
    size_t                     i;

    while (tail && tail->next) {
        tail = tail->next;
    }
    if (!tail || !(tail->next = bgp_attr_create_flowspec_rate(0, 0.0f))) {
        fprintf(stderr, "failed to build %s path attributes\n", family);
        exit(1);
    }

    memset(&opts, 0, sizeof(opts));
    opts.afi = afi;
    opts.safi = safi;
    opts.max_pdu_size = BGP_MAX_PDU_SIZE;

    for (i = 0; i < sizeof(k_scales) / sizeof(k_scales[0]); i++) {
        flowspec_nlri_t *nlri = build_flowspec_nlri(k_scales[i].prefixes, afi, safi == SAFI_FLOWSPEC_VPN);
        double           start_ms;
        double           total_ms;
        int              repetition;
        int              messages = 0;
        uint64_t         bytes = 0;

        if (!nlri) {
            fprintf(stderr, "failed to build %s NLRI list\n", family);
            exit(1);
        }

        start_ms = now_ms();
        for (repetition = 0; repetition < k_scales[i].repetitions; repetition++) {
            bgp_update_result_t *result =
                bgp_generate_update_flowspec(nlri, attrs, NULL, &opts);

            if (!result) {
                fprintf(stderr, "%s UPDATE generation failed\n", family);
                exit(1);
            }

            messages = result->num_messages;
            bytes = sum_message_bytes(result);
            bgp_update_result_free(result);
        }
        total_ms = now_ms() - start_ms;

        print_result(family, k_scales[i].prefixes, k_scales[i].repetitions, messages, bytes, total_ms);
        flowspec_nlri_list_free(nlri);
    }

    bgp_path_attr_list_free(attrs);
}

int main(void) {
    printf("BGP UPDATE Encoder\n\n");
    printf("%-20s %8s %4s %8s %8s %9s %6s %9s\n",
           "case", "paths", "runs", "msgs", "nlri/msg",
           "wire", "total", "paths/s");
    printf("%-20s %8s %4s %8s %8s %9s %6s %9s\n",
           "--------------------", "--------", "----", "--------",
           "--------", "---------", "------", "---------");

    bench_ipv4_updates();
    bench_ipv6_updates();
    bench_labeled_ipv4_updates();
    bench_labeled_ipv4_ext_nh_updates();
    bench_labeled_ipv6_updates();
    bench_vpnv4_updates();
    bench_vpnv6_updates();
    bench_flowspec_updates("flowspec4", AFI_IPV4, SAFI_FLOWSPEC);
    bench_flowspec_updates("flowspec6", AFI_IPV6, SAFI_FLOWSPEC);
    bench_flowspec_updates("flowspec-vpn4", AFI_IPV4, SAFI_FLOWSPEC_VPN);

    return 0;
}
