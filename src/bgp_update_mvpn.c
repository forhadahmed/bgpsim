// BGP UPDATE Message Generation - MVPN (RFC 6514)

#define OUTPUT_STDIO_REMAP

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "bgp.h"
#include "output.h"
#include "bgp_update.h"

static int mvpn_ip_len_from_af(int af) {
    return (af == AF_INET6) ? 16 : 4;
}

static int mvpn_af_valid(int af) {
    return af == AF_INET || af == AF_INET6;
}

static int mvpn_address_lengths_valid(int af, uint8_t source_len, uint8_t group_len) {
    return mvpn_af_valid(af) && source_len == mvpn_ip_len_from_af(af) * 8 && group_len == source_len;
}

// MVPN Type 1 NLRI Functions (RFC 6514)

static mvpn_type1_nlri_t* mvpn_type1_nlri_create_internal(
    route_distinguisher_t rd,
    int af,
    const char *orig_router_ip,
    int add_path,
    uint32_t path_id) {

    mvpn_type1_nlri_t *nlri = calloc(1, sizeof(mvpn_type1_nlri_t));

    if (!nlri) {
        return NULL;
    }

    memset(nlri, 0, sizeof(*nlri));

    nlri->prefix.route_type = MVPN_RT_INTRA_AS_IPMSI_AD;
    nlri->prefix.af = (af == AF_INET6) ? AF_INET6 : AF_INET;
    nlri->prefix.rd = rd;

    memset(nlri->prefix.orig_router_ip, 0, 16);
    if (orig_router_ip && inet_pton(af, orig_router_ip, nlri->prefix.orig_router_ip) != 1) {
        free(nlri);
        return NULL;
    }

    nlri->path_id = path_id;
    nlri->add_path = (uint8_t)(add_path ? 1 : 0);
    nlri->next = NULL;

    return nlri;
}

mvpn_type1_nlri_t* mvpn_type1_nlri_create_ipv4(route_distinguisher_t rd, const char *orig_router_ip) {
    return mvpn_type1_nlri_create_internal(rd, AF_INET, orig_router_ip, 0, 0);
}

mvpn_type1_nlri_t* mvpn_type1_nlri_create_ipv4_path_id(
    route_distinguisher_t rd,
    const char *orig_router_ip,
    uint32_t path_id) {
    return mvpn_type1_nlri_create_internal(rd, AF_INET, orig_router_ip, 1, path_id);
}

mvpn_type1_nlri_t* mvpn_type1_nlri_create_ipv6(route_distinguisher_t rd, const char *orig_router_ip) {
    return mvpn_type1_nlri_create_internal(rd, AF_INET6, orig_router_ip, 0, 0);
}

mvpn_type1_nlri_t* mvpn_type1_nlri_create_ipv6_path_id(
    route_distinguisher_t rd,
    const char *orig_router_ip,
    uint32_t path_id) {
    return mvpn_type1_nlri_create_internal(rd, AF_INET6, orig_router_ip, 1, path_id);
}

DEFINE_NLRI_LIST_UTILS(mvpn_type1_nlri_t, mvpn_type1_nlri)

/*
 * Encode an MVPN Type 1 prefix into the wire format per RFC 6514.
 * Returns the number of bytes written.
 */
int bgp_encode_mvpn_type1_prefix(uint8_t *buffer, mvpn_type1_prefix_t *prefix) {
    if (!buffer || !prefix || !mvpn_af_valid(prefix->af) || prefix->rd.type > 2 ||
        prefix->route_type != MVPN_RT_INTRA_AS_IPMSI_AD) return -1;
    int offset = 0;
    int is_ipv6 = (prefix->af == AF_INET6);
    int ip_len = is_ipv6 ? 16 : 4;

    // Route Type (1 byte)
    buffer[offset++] = prefix->route_type;

    // Length (1 byte): RD(8) + Originating Router IP (4 or 16)
    buffer[offset++] = (uint8_t)(8 + ip_len);

    // RD (8 bytes)
    bgp_encode_rd(buffer + offset, &prefix->rd);
    offset += 8;

    // Originating Router's IP (4 or 16 bytes)
    memcpy(buffer + offset, prefix->orig_router_ip, ip_len);
    offset += ip_len;

    return offset;
}

// MVPN Type 2 NLRI Functions (RFC 6514)

static mvpn_type2_nlri_t* mvpn_type2_nlri_create_internal(
    route_distinguisher_t rd,
    uint32_t source_as,
    int add_path,
    uint32_t path_id) {
    mvpn_type2_nlri_t *nlri = calloc(1, sizeof(mvpn_type2_nlri_t));

    if (!nlri) {
        return NULL;
    }

    memset(nlri, 0, sizeof(*nlri));
    nlri->prefix.route_type = MVPN_RT_INTER_AS_IPMSI_AD;
    nlri->prefix.rd = rd;
    nlri->prefix.source_as = htonl(source_as);
    nlri->path_id = path_id;
    nlri->add_path = (uint8_t)(add_path ? 1 : 0);
    nlri->next = NULL;

    return nlri;
}

mvpn_type2_nlri_t* mvpn_type2_nlri_create(route_distinguisher_t rd, uint32_t source_as) {
    return mvpn_type2_nlri_create_internal(rd, source_as, 0, 0);
}

mvpn_type2_nlri_t* mvpn_type2_nlri_create_path_id(route_distinguisher_t rd, uint32_t source_as, uint32_t path_id) {
    return mvpn_type2_nlri_create_internal(rd, source_as, 1, path_id);
}

DEFINE_NLRI_LIST_UTILS(mvpn_type2_nlri_t, mvpn_type2_nlri)

int bgp_encode_mvpn_type2_prefix(uint8_t *buffer, mvpn_type2_prefix_t *prefix) {
    if (!buffer || !prefix || prefix->rd.type > 2 || prefix->route_type != MVPN_RT_INTER_AS_IPMSI_AD) return -1;
    int offset = 0;

    buffer[offset++] = prefix->route_type;
    buffer[offset++] = 12; /* RD(8) + Source AS(4) */
    bgp_encode_rd(buffer + offset, &prefix->rd);
    offset += 8;
    memcpy(buffer + offset, &prefix->source_as, 4);
    offset += 4;

    return offset;
}

// MVPN Type 3 NLRI Functions (RFC 6514)

static mvpn_type3_nlri_t* mvpn_type3_nlri_create_internal(
    route_distinguisher_t rd,
    int af,
    const char *mcast_src,
    const char *mcast_grp,
    const char *orig_router_ip,
    int add_path,
    uint32_t path_id) {

    mvpn_type3_nlri_t *nlri = calloc(1, sizeof(mvpn_type3_nlri_t));

    if (!nlri) {
        return NULL;
    }

    memset(nlri, 0, sizeof(*nlri));

    nlri->prefix.route_type = MVPN_RT_SPMSI_AD;
    nlri->prefix.af = (af == AF_INET6) ? AF_INET6 : AF_INET;
    nlri->prefix.rd = rd;

    // Multicast source and group lengths
    nlri->prefix.mcast_src_len = (af == AF_INET6) ? 128 : 32;
    nlri->prefix.mcast_grp_len = (af == AF_INET6) ? 128 : 32;

    // Parse multicast source
    memset(nlri->prefix.mcast_src, 0, 16);
    if (mcast_src && inet_pton(af, mcast_src, nlri->prefix.mcast_src) != 1) {
        free(nlri);
        return NULL;
    }

    // Parse multicast group
    memset(nlri->prefix.mcast_grp, 0, 16);
    if (mcast_grp && inet_pton(af, mcast_grp, nlri->prefix.mcast_grp) != 1) {
        free(nlri);
        return NULL;
    }

    // Parse originating router IP
    memset(nlri->prefix.orig_router_ip, 0, 16);
    if (orig_router_ip && inet_pton(af, orig_router_ip, nlri->prefix.orig_router_ip) != 1) {
        free(nlri);
        return NULL;
    }

    nlri->path_id = path_id;
    nlri->add_path = (uint8_t)(add_path ? 1 : 0);
    nlri->next = NULL;

    return nlri;
}

mvpn_type3_nlri_t* mvpn_type3_nlri_create_ipv4(route_distinguisher_t rd,
                                               const char *mcast_src,
                                               const char *mcast_grp,
                                               const char *orig_router_ip) {
    return mvpn_type3_nlri_create_internal(rd, AF_INET, mcast_src, mcast_grp, orig_router_ip, 0, 0);
}

mvpn_type3_nlri_t* mvpn_type3_nlri_create_ipv4_path_id(
    route_distinguisher_t rd,
    const char *mcast_src,
    const char *mcast_grp,
    const char *orig_router_ip,
    uint32_t path_id) {
    return mvpn_type3_nlri_create_internal(rd, AF_INET, mcast_src, mcast_grp, orig_router_ip, 1, path_id);
}

mvpn_type3_nlri_t* mvpn_type3_nlri_create_ipv6(route_distinguisher_t rd,
                                               const char *mcast_src,
                                               const char *mcast_grp,
                                               const char *orig_router_ip) {
    return mvpn_type3_nlri_create_internal(rd, AF_INET6, mcast_src, mcast_grp, orig_router_ip, 0, 0);
}

mvpn_type3_nlri_t* mvpn_type3_nlri_create_ipv6_path_id(
    route_distinguisher_t rd,
    const char *mcast_src,
    const char *mcast_grp,
    const char *orig_router_ip,
    uint32_t path_id) {
    return mvpn_type3_nlri_create_internal(rd, AF_INET6, mcast_src, mcast_grp, orig_router_ip, 1, path_id);
}

DEFINE_NLRI_LIST_UTILS(mvpn_type3_nlri_t, mvpn_type3_nlri)

/*
 * Encode an MVPN Type 3 prefix into the wire format per RFC 6514.
 * Returns the number of bytes written.
 */
int bgp_encode_mvpn_type3_prefix(uint8_t *buffer, mvpn_type3_prefix_t *prefix) {
    if (!buffer || !prefix || prefix->rd.type > 2 || prefix->route_type != MVPN_RT_SPMSI_AD ||
        !mvpn_address_lengths_valid(prefix->af, prefix->mcast_src_len, prefix->mcast_grp_len)) return -1;
    int offset = 0;
    int is_ipv6 = (prefix->af == AF_INET6);
    int ip_len = is_ipv6 ? 16 : 4;

    // Route Type (1 byte)
    buffer[offset++] = prefix->route_type;

    /*
     * Length (1 byte):
     * RD(8) + mcast_src_len(1) + mcast_src(4/16) +
     * mcast_grp_len(1) + mcast_grp(4/16) + orig_router_ip(4/16)
     */
    buffer[offset++] = (uint8_t)(8 + 1 + ip_len + 1 + ip_len + ip_len);

    // RD (8 bytes)
    bgp_encode_rd(buffer + offset, &prefix->rd);
    offset += 8;

    // Multicast Source Length (1 byte)
    buffer[offset++] = prefix->mcast_src_len;

    // Multicast Source (4 or 16 bytes)
    memcpy(buffer + offset, prefix->mcast_src, ip_len);
    offset += ip_len;

    // Multicast Group Length (1 byte)
    buffer[offset++] = prefix->mcast_grp_len;

    // Multicast Group (4 or 16 bytes)
    memcpy(buffer + offset, prefix->mcast_grp, ip_len);
    offset += ip_len;

    // Originating Router's IP (4 or 16 bytes)
    memcpy(buffer + offset, prefix->orig_router_ip, ip_len);
    offset += ip_len;

    return offset;
}

// MVPN Type 4 NLRI Functions (RFC 6514)

static int mvpn_route_key_valid(const uint8_t *key, unsigned len, int af) {
    if (!key || len < 4 || key[1] + 2U != len || key[2] != 0 || key[3] > 2) return 0;
    if (key[0] == MVPN_RT_INTER_AS_IPMSI_AD) return len == 14;
    if (key[0] != MVPN_RT_SPMSI_AD || (af != AF_INET && af != AF_INET6)) return 0;
    unsigned ip_len = (unsigned)mvpn_ip_len_from_af(af);
    return len == 12U + 3U * ip_len && key[10] == ip_len * 8 && key[11 + ip_len] == ip_len * 8;
}

static mvpn_type4_nlri_t* mvpn_type4_nlri_create_internal(
    route_distinguisher_t rd,
    int af,
    const uint8_t *route_key,
    uint8_t route_key_len,
    const char *orig_router_ip,
    int add_path,
    uint32_t path_id) {
    mvpn_type4_nlri_t *nlri;

    if (!mvpn_route_key_valid(route_key, route_key_len, af) ||
        route_key_len > 255 - mvpn_ip_len_from_af(af)) {
        return NULL;
    }
    /*
     * Leaf A-D carries the received Route Key plus Originating Router IP.
     * It does not carry a standalone RD field, so the helper keeps the `rd`
     * parameter only for API symmetry with the other MVPN constructors.
     */
    (void)rd;

    nlri = calloc(1, sizeof(mvpn_type4_nlri_t));
    if (!nlri) {
        return NULL;
    }

    memset(nlri, 0, sizeof(*nlri));
    nlri->prefix.route_type = MVPN_RT_LEAF_AD;
    nlri->prefix.af = (af == AF_INET6) ? AF_INET6 : AF_INET;
    nlri->prefix.route_key_len = route_key_len;
    memcpy(nlri->prefix.route_key, route_key, route_key_len);
    if (orig_router_ip && inet_pton(af, orig_router_ip, nlri->prefix.orig_router_ip) != 1) {
        free(nlri);
        return NULL;
    }
    nlri->path_id = path_id;
    nlri->add_path = (uint8_t)(add_path ? 1 : 0);
    nlri->next = NULL;

    return nlri;
}

mvpn_type4_nlri_t* mvpn_type4_nlri_create_ipv4(route_distinguisher_t rd,
                                               const uint8_t *route_key,
                                               uint8_t route_key_len,
                                               const char *orig_router_ip) {
    return mvpn_type4_nlri_create_internal(rd, AF_INET, route_key, route_key_len, orig_router_ip, 0, 0);
}

mvpn_type4_nlri_t* mvpn_type4_nlri_create_ipv4_path_id(
    route_distinguisher_t rd,
    const uint8_t *route_key,
    uint8_t route_key_len,
    const char *orig_router_ip,
    uint32_t path_id) {
    return mvpn_type4_nlri_create_internal(rd, AF_INET, route_key, route_key_len, orig_router_ip, 1, path_id);
}

mvpn_type4_nlri_t* mvpn_type4_nlri_create_ipv6(route_distinguisher_t rd,
                                               const uint8_t *route_key,
                                               uint8_t route_key_len,
                                               const char *orig_router_ip) {
    return mvpn_type4_nlri_create_internal(rd, AF_INET6, route_key, route_key_len, orig_router_ip, 0, 0);
}

mvpn_type4_nlri_t* mvpn_type4_nlri_create_ipv6_path_id(
    route_distinguisher_t rd,
    const uint8_t *route_key,
    uint8_t route_key_len,
    const char *orig_router_ip,
    uint32_t path_id) {
    return mvpn_type4_nlri_create_internal(rd, AF_INET6, route_key, route_key_len, orig_router_ip, 1, path_id);
}

DEFINE_NLRI_LIST_UTILS(mvpn_type4_nlri_t, mvpn_type4_nlri)

int bgp_encode_mvpn_type4_prefix(uint8_t *buffer, mvpn_type4_prefix_t *prefix) {
    if (!buffer || !prefix || prefix->route_type != MVPN_RT_LEAF_AD ||
        (prefix->af != AF_INET && prefix->af != AF_INET6) ||
        !mvpn_route_key_valid(prefix->route_key, prefix->route_key_len, prefix->af) ||
        prefix->route_key_len > 255 - mvpn_ip_len_from_af(prefix->af)) return -1;
    int offset = 0;
    int ip_len = mvpn_ip_len_from_af(prefix->af);

    buffer[offset++] = prefix->route_type;
    // Route Key (variable) + Originating Router IP (4 or 16 octets).
    buffer[offset++] = (uint8_t)(prefix->route_key_len + ip_len);
    memcpy(buffer + offset, prefix->route_key, prefix->route_key_len);
    offset += prefix->route_key_len;
    memcpy(buffer + offset, prefix->orig_router_ip, ip_len);
    offset += ip_len;

    return offset;
}

// MVPN Type 5 NLRI Functions (RFC 6514)

static mvpn_type5_nlri_t* mvpn_type5_nlri_create_internal(
    route_distinguisher_t rd,
    int af,
    const char *mcast_src,
    const char *mcast_grp,
    int add_path,
    uint32_t path_id) {
    mvpn_type5_nlri_t *nlri = calloc(1, sizeof(mvpn_type5_nlri_t));

    if (!nlri) {
        return NULL;
    }

    memset(nlri, 0, sizeof(*nlri));
    nlri->prefix.route_type = MVPN_RT_SOURCE_ACTIVE_AD;
    nlri->prefix.af = (af == AF_INET6) ? AF_INET6 : AF_INET;
    nlri->prefix.rd = rd;
    nlri->prefix.mcast_src_len = (af == AF_INET6) ? 128 : 32;
    nlri->prefix.mcast_grp_len = (af == AF_INET6) ? 128 : 32;
    if (mcast_src && inet_pton(af, mcast_src, nlri->prefix.mcast_src) != 1) {
        free(nlri);
        return NULL;
    }
    if (mcast_grp && inet_pton(af, mcast_grp, nlri->prefix.mcast_grp) != 1) {
        free(nlri);
        return NULL;
    }
    nlri->path_id = path_id;
    nlri->add_path = (uint8_t)(add_path ? 1 : 0);
    nlri->next = NULL;

    return nlri;
}

mvpn_type5_nlri_t* mvpn_type5_nlri_create_ipv4(route_distinguisher_t rd, const char *mcast_src, const char *mcast_grp) {
    return mvpn_type5_nlri_create_internal(rd, AF_INET, mcast_src, mcast_grp, 0, 0);
}

mvpn_type5_nlri_t* mvpn_type5_nlri_create_ipv4_path_id(
    route_distinguisher_t rd,
    const char *mcast_src,
    const char *mcast_grp,
    uint32_t path_id) {
    return mvpn_type5_nlri_create_internal(rd, AF_INET, mcast_src, mcast_grp, 1, path_id);
}

mvpn_type5_nlri_t* mvpn_type5_nlri_create_ipv6(route_distinguisher_t rd, const char *mcast_src, const char *mcast_grp) {
    return mvpn_type5_nlri_create_internal(rd, AF_INET6, mcast_src, mcast_grp, 0, 0);
}

mvpn_type5_nlri_t* mvpn_type5_nlri_create_ipv6_path_id(
    route_distinguisher_t rd,
    const char *mcast_src,
    const char *mcast_grp,
    uint32_t path_id) {
    return mvpn_type5_nlri_create_internal(rd, AF_INET6, mcast_src, mcast_grp, 1, path_id);
}

DEFINE_NLRI_LIST_UTILS(mvpn_type5_nlri_t, mvpn_type5_nlri)

int bgp_encode_mvpn_type5_prefix(uint8_t *buffer, mvpn_type5_prefix_t *prefix) {
    if (!buffer || !prefix || prefix->rd.type > 2 || prefix->route_type != MVPN_RT_SOURCE_ACTIVE_AD ||
        !mvpn_address_lengths_valid(prefix->af, prefix->mcast_src_len, prefix->mcast_grp_len)) return -1;
    int offset = 0;
    int ip_len = mvpn_ip_len_from_af(prefix->af);

    buffer[offset++] = prefix->route_type;
    // RD (8) + source length (1) + source + group length (1) + group.
    buffer[offset++] = (uint8_t)(8 + 1 + ip_len + 1 + ip_len);
    bgp_encode_rd(buffer + offset, &prefix->rd);
    offset += 8;
    buffer[offset++] = prefix->mcast_src_len;
    memcpy(buffer + offset, prefix->mcast_src, ip_len);
    offset += ip_len;
    buffer[offset++] = prefix->mcast_grp_len;
    memcpy(buffer + offset, prefix->mcast_grp, ip_len);
    offset += ip_len;

    return offset;
}

// MVPN Type 6/7 NLRI Functions (RFC 6514)

static int mvpn_cmulticast_init_prefix(mvpn_cmulticast_prefix_t *prefix,
                                        uint8_t route_type,
                                        route_distinguisher_t rd,
                                        int af,
                                        uint32_t source_as,
                                        const char *mcast_src,
                                        const char *mcast_grp) {
    memset(prefix, 0, sizeof(*prefix));
    prefix->route_type = route_type;
    prefix->af = (af == AF_INET6) ? AF_INET6 : AF_INET;
    prefix->rd = rd;
    prefix->source_as = htonl(source_as);
    prefix->mcast_src_len = (af == AF_INET6) ? 128 : 32;
    prefix->mcast_grp_len = (af == AF_INET6) ? 128 : 32;
    if (mcast_src && inet_pton(af, mcast_src, prefix->mcast_src) != 1) return -1;
    if (mcast_grp && inet_pton(af, mcast_grp, prefix->mcast_grp) != 1) return -1;
    return 0;
}

static mvpn_type6_nlri_t* mvpn_type6_nlri_create_internal(
    route_distinguisher_t rd,
    int af,
    uint32_t source_as,
    const char *mcast_src,
    const char *mcast_grp,
    int add_path,
    uint32_t path_id) {
    mvpn_type6_nlri_t *nlri = calloc(1, sizeof(mvpn_type6_nlri_t));

    if (!nlri) {
        return NULL;
    }

    if (mvpn_cmulticast_init_prefix(&nlri->prefix, MVPN_RT_SHARED_TREE_JOIN, rd, af, source_as, mcast_src, mcast_grp) < 0) {
        free(nlri);
        return NULL;
    }
    nlri->path_id = path_id;
    nlri->add_path = (uint8_t)(add_path ? 1 : 0);
    nlri->next = NULL;

    return nlri;
}

static mvpn_type7_nlri_t* mvpn_type7_nlri_create_internal(
    route_distinguisher_t rd,
    int af,
    uint32_t source_as,
    const char *mcast_src,
    const char *mcast_grp,
    int add_path,
    uint32_t path_id) {
    mvpn_type7_nlri_t *nlri = calloc(1, sizeof(mvpn_type7_nlri_t));

    if (!nlri) {
        return NULL;
    }

    if (mvpn_cmulticast_init_prefix(&nlri->prefix, MVPN_RT_SOURCE_TREE_JOIN, rd, af, source_as, mcast_src, mcast_grp) < 0) {
        free(nlri);
        return NULL;
    }
    nlri->path_id = path_id;
    nlri->add_path = (uint8_t)(add_path ? 1 : 0);
    nlri->next = NULL;

    return nlri;
}

mvpn_type6_nlri_t* mvpn_type6_nlri_create_ipv4(route_distinguisher_t rd,
                                               uint32_t source_as,
                                               const char *mcast_src,
                                               const char *mcast_grp) {
    return mvpn_type6_nlri_create_internal(rd, AF_INET, source_as, mcast_src, mcast_grp, 0, 0);
}

mvpn_type6_nlri_t* mvpn_type6_nlri_create_ipv4_path_id(
    route_distinguisher_t rd,
    uint32_t source_as,
    const char *mcast_src,
    const char *mcast_grp,
    uint32_t path_id) {
    return mvpn_type6_nlri_create_internal(rd, AF_INET, source_as, mcast_src, mcast_grp, 1, path_id);
}

mvpn_type6_nlri_t* mvpn_type6_nlri_create_ipv6(route_distinguisher_t rd,
                                               uint32_t source_as,
                                               const char *mcast_src,
                                               const char *mcast_grp) {
    return mvpn_type6_nlri_create_internal(rd, AF_INET6, source_as, mcast_src, mcast_grp, 0, 0);
}

mvpn_type6_nlri_t* mvpn_type6_nlri_create_ipv6_path_id(
    route_distinguisher_t rd,
    uint32_t source_as,
    const char *mcast_src,
    const char *mcast_grp,
    uint32_t path_id) {
    return mvpn_type6_nlri_create_internal(rd, AF_INET6, source_as, mcast_src, mcast_grp, 1, path_id);
}

mvpn_type7_nlri_t* mvpn_type7_nlri_create_ipv4(route_distinguisher_t rd,
                                               uint32_t source_as,
                                               const char *mcast_src,
                                               const char *mcast_grp) {
    return mvpn_type7_nlri_create_internal(rd, AF_INET, source_as, mcast_src, mcast_grp, 0, 0);
}

mvpn_type7_nlri_t* mvpn_type7_nlri_create_ipv4_path_id(
    route_distinguisher_t rd,
    uint32_t source_as,
    const char *mcast_src,
    const char *mcast_grp,
    uint32_t path_id) {
    return mvpn_type7_nlri_create_internal(rd, AF_INET, source_as, mcast_src, mcast_grp, 1, path_id);
}

mvpn_type7_nlri_t* mvpn_type7_nlri_create_ipv6(route_distinguisher_t rd,
                                               uint32_t source_as,
                                               const char *mcast_src,
                                               const char *mcast_grp) {
    return mvpn_type7_nlri_create_internal(rd, AF_INET6, source_as, mcast_src, mcast_grp, 0, 0);
}

mvpn_type7_nlri_t* mvpn_type7_nlri_create_ipv6_path_id(
    route_distinguisher_t rd,
    uint32_t source_as,
    const char *mcast_src,
    const char *mcast_grp,
    uint32_t path_id) {
    return mvpn_type7_nlri_create_internal(rd, AF_INET6, source_as, mcast_src, mcast_grp, 1, path_id);
}

DEFINE_NLRI_LIST_UTILS(mvpn_type6_nlri_t, mvpn_type6_nlri)
DEFINE_NLRI_LIST_UTILS(mvpn_type7_nlri_t, mvpn_type7_nlri)

static int mvpn_encode_cmulticast_prefix(uint8_t *buffer, mvpn_cmulticast_prefix_t *prefix) {
    if (!buffer || !prefix || prefix->rd.type > 2 ||
        !mvpn_address_lengths_valid(prefix->af, prefix->mcast_src_len, prefix->mcast_grp_len)) return -1;
    int offset = 0;
    int ip_len = mvpn_ip_len_from_af(prefix->af);

    buffer[offset++] = prefix->route_type;
    /*
     * RD (8) + Source AS (4) + source length (1) + source +
     * group length (1) + group.
     */
    buffer[offset++] = (uint8_t)(8 + 4 + 1 + ip_len + 1 + ip_len);
    bgp_encode_rd(buffer + offset, &prefix->rd);
    offset += 8;
    memcpy(buffer + offset, &prefix->source_as, 4);
    offset += 4;
    buffer[offset++] = prefix->mcast_src_len;
    memcpy(buffer + offset, prefix->mcast_src, ip_len);
    offset += ip_len;
    buffer[offset++] = prefix->mcast_grp_len;
    memcpy(buffer + offset, prefix->mcast_grp, ip_len);
    offset += ip_len;

    return offset;
}

int bgp_encode_mvpn_type6_prefix(uint8_t *buffer, mvpn_cmulticast_prefix_t *prefix) {
    if (!prefix || prefix->route_type != MVPN_RT_SHARED_TREE_JOIN) return -1;
    return mvpn_encode_cmulticast_prefix(buffer, prefix);
}

int bgp_encode_mvpn_type7_prefix(uint8_t *buffer, mvpn_cmulticast_prefix_t *prefix) {
    if (!prefix || prefix->route_type != MVPN_RT_SOURCE_TREE_JOIN) return -1;
    return mvpn_encode_cmulticast_prefix(buffer, prefix);
}

// PMSI Tunnel Attribute Helper

/*
 * Create a PMSI Tunnel attribute (RFC 6514).
 * flags: attribute flags (bit 0 = leaf-info-required)
 * tunnel_type: Ingress Replication = 6, mLDP = 2, etc.
 * label: MPLS label (20-bit value)
 * tunnel_id: tunnel identifier data (variable length)
 * tunnel_id_len: length of tunnel_id in bytes
 *
 * This helper intentionally stays generic over Tunnel Type and Tunnel
 * Identifier payload so the test tool can exercise the valid RFC 6514 tunnel
 * variants without a constructor per tunnel type.
 */
bgp_path_attr_t* bgp_attr_create_pmsi_tunnel(uint8_t flags,
                                             uint8_t tunnel_type,
                                             uint32_t label,
                                             const uint8_t *tunnel_id,
                                             uint16_t tunnel_id_len) {
    /*
     * PMSI Tunnel attribute value:
     * Flags (1) + Tunnel Type (1) + MPLS Label (3) + Tunnel Identifier (var)
     */
    if (tunnel_id_len > UINT16_MAX - 5 || (tunnel_id_len && !tunnel_id) || label > 0xFFFFF) return NULL;
    uint16_t value_len = (uint16_t)(5 + tunnel_id_len);
    bgp_path_attr_t *attr = bgp_attr_alloc(
        BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE,
        BGP_ATTR_PMSI_TUNNEL, value_len);

    if (!attr) {
        return NULL;
    }

    // Flags
    attr->value[0] = flags;

    // Tunnel Type
    attr->value[1] = tunnel_type;

    /*
     * RFC 6514 section 5: the high 20 bits carry the label; no label is an
     * entirely zero field, not an MPLS stack entry with the S bit set.
     */
    mpls_label_t mpls;
    mpls.label = label;
    mpls.tc = 0;
    mpls.s = 0;
    mpls.ttl = 0;
    bgp_encode_mpls_label(attr->value + 2, &mpls);

    // Tunnel Identifier
    if (tunnel_id && tunnel_id_len > 0) {
        memcpy(attr->value + 5, tunnel_id, tunnel_id_len);
    }

    return attr;
}

// ADD-PATH Detectors

DEFINE_ADD_PATH_DETECTOR(bgp_detect_mvpn_type1_add_path, mvpn_type1_nlri_t, do { } while (0))

DEFINE_ADD_PATH_DETECTOR(bgp_detect_mvpn_type2_add_path, mvpn_type2_nlri_t, do { } while (0))

DEFINE_ADD_PATH_DETECTOR(bgp_detect_mvpn_type3_add_path, mvpn_type3_nlri_t, do { } while (0))

DEFINE_ADD_PATH_DETECTOR(bgp_detect_mvpn_type4_add_path, mvpn_type4_nlri_t, do { } while (0))

DEFINE_ADD_PATH_DETECTOR(bgp_detect_mvpn_type5_add_path, mvpn_type5_nlri_t, do { } while (0))

DEFINE_ADD_PATH_DETECTOR(bgp_detect_mvpn_type6_add_path, mvpn_type6_nlri_t, do { } while (0))

DEFINE_ADD_PATH_DETECTOR(bgp_detect_mvpn_type7_add_path, mvpn_type7_nlri_t, do { } while (0))

// Per-NLRI Wire Encoders

static int bgp_encode_mvpn_type1_nlri(uint8_t *buffer, const mvpn_type1_nlri_t *nlri, int add_path) {
    int offset = 0;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    int len = bgp_encode_mvpn_type1_prefix(buffer + offset, (mvpn_type1_prefix_t *)&nlri->prefix);
    return len < 0 ? -1 : offset + len;
}

static int bgp_encode_mvpn_type2_nlri(uint8_t *buffer, const mvpn_type2_nlri_t *nlri, int add_path) {
    int offset = 0;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    int len = bgp_encode_mvpn_type2_prefix(buffer + offset, (mvpn_type2_prefix_t *)&nlri->prefix);
    return len < 0 ? -1 : offset + len;
}

static int bgp_encode_mvpn_type3_nlri(uint8_t *buffer, const mvpn_type3_nlri_t *nlri, int add_path) {
    int offset = 0;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    int len = bgp_encode_mvpn_type3_prefix(buffer + offset, (mvpn_type3_prefix_t *)&nlri->prefix);
    return len < 0 ? -1 : offset + len;
}

static int bgp_encode_mvpn_type4_nlri(uint8_t *buffer, const mvpn_type4_nlri_t *nlri, int add_path) {
    int offset = 0;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    int len = bgp_encode_mvpn_type4_prefix(buffer + offset, (mvpn_type4_prefix_t *)&nlri->prefix);
    return len < 0 ? -1 : offset + len;
}

static int bgp_encode_mvpn_type5_nlri(uint8_t *buffer, const mvpn_type5_nlri_t *nlri, int add_path) {
    int offset = 0;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    int len = bgp_encode_mvpn_type5_prefix(buffer + offset, (mvpn_type5_prefix_t *)&nlri->prefix);
    return len < 0 ? -1 : offset + len;
}

static int bgp_encode_mvpn_type6_nlri(uint8_t *buffer, const mvpn_type6_nlri_t *nlri, int add_path) {
    int offset = 0;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    int len = bgp_encode_mvpn_type6_prefix(buffer + offset, (mvpn_cmulticast_prefix_t *)&nlri->prefix);
    return len < 0 ? -1 : offset + len;
}

static int bgp_encode_mvpn_type7_nlri(uint8_t *buffer, const mvpn_type7_nlri_t *nlri, int add_path) {
    int offset = 0;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    int len = bgp_encode_mvpn_type7_prefix(buffer + offset, (mvpn_cmulticast_prefix_t *)&nlri->prefix);
    return len < 0 ? -1 : offset + len;
}

// Chunk Encoders

static int encode_mvpn_type1_chunk(mvpn_type1_nlri_t **cursor,
                                   uint8_t *buffer,
                                   int max_bytes,
                                   int add_path,
                                   uint16_t afi) {
    int written = 0;

    while (*cursor) {
        int is_ipv6 = ((*cursor)->prefix.af == AF_INET6);
        // route_type(1) + length(1) + RD(8) + IP(4 or 16)
        int needed = 2 + 8 + (is_ipv6 ? 16 : 4);

        if ((afi == AFI_IPV4 && is_ipv6) ||
            (afi == AFI_IPV6 && !is_ipv6)) {
            return -1;
        }

        if ((int)(*cursor)->add_path != add_path) {
            return -1;
        }
        if (add_path) {
            needed += 4;
        }

        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        int encoded = bgp_encode_mvpn_type1_nlri(buffer + written, *cursor, add_path);
        if (encoded <= 0) {
            return -1;
        }
        written += encoded;
        *cursor = (*cursor)->next;
    }

    return written;
}

static int encode_mvpn_type2_chunk(mvpn_type2_nlri_t **cursor, uint8_t *buffer, int max_bytes, int add_path) {
    int written = 0;

    while (*cursor) {
        // Route type (1) + length (1) + RD (8) + Source AS (4).
        int needed = 2 + 8 + 4;

        if ((int)(*cursor)->add_path != add_path) {
            return -1;
        }
        if (add_path) {
            needed += 4;
        }

        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        int encoded = bgp_encode_mvpn_type2_nlri(buffer + written, *cursor, add_path);
        if (encoded <= 0) {
            return -1;
        }
        written += encoded;
        *cursor = (*cursor)->next;
    }

    return written;
}

static int encode_mvpn_type3_chunk(mvpn_type3_nlri_t **cursor,
                                   uint8_t *buffer,
                                   int max_bytes,
                                   int add_path,
                                   uint16_t afi) {
    int written = 0;

    while (*cursor) {
        int is_ipv6 = ((*cursor)->prefix.af == AF_INET6);
        int ip_len = is_ipv6 ? 16 : 4;
        /*
         * route_type(1) + length(1) + RD(8) + src_len(1) + src(ip_len) +
         * grp_len(1) + grp(ip_len) + orig_ip(ip_len)
         */
        int needed = 2 + 8 + 1 + ip_len + 1 + ip_len + ip_len;

        if ((afi == AFI_IPV4 && is_ipv6) ||
            (afi == AFI_IPV6 && !is_ipv6)) {
            return -1;
        }

        if ((int)(*cursor)->add_path != add_path) {
            return -1;
        }
        if (add_path) {
            needed += 4;
        }

        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        int encoded = bgp_encode_mvpn_type3_nlri(buffer + written, *cursor, add_path);
        if (encoded <= 0) {
            return -1;
        }
        written += encoded;
        *cursor = (*cursor)->next;
    }

    return written;
}

static int encode_mvpn_type4_chunk(mvpn_type4_nlri_t **cursor,
                                   uint8_t *buffer,
                                   int max_bytes,
                                   int add_path,
                                   uint16_t afi) {
    int written = 0;

    while (*cursor) {
        int is_ipv6 = ((*cursor)->prefix.af == AF_INET6);
        /*
         * Route type (1) + length (1) + Route Key (variable) +
         * Originating Router IP (4 or 16).
         */
        int needed = 2 + (*cursor)->prefix.route_key_len + (is_ipv6 ? 16 : 4);

        if ((afi == AFI_IPV4 && is_ipv6) ||
            (afi == AFI_IPV6 && !is_ipv6)) {
            return -1;
        }
        if ((int)(*cursor)->add_path != add_path) {
            return -1;
        }
        if (add_path) {
            needed += 4;
        }
        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        int encoded = bgp_encode_mvpn_type4_nlri(buffer + written, *cursor, add_path);
        if (encoded <= 0) {
            return -1;
        }
        written += encoded;
        *cursor = (*cursor)->next;
    }

    return written;
}

static int encode_mvpn_type5_chunk(mvpn_type5_nlri_t **cursor,
                                   uint8_t *buffer,
                                   int max_bytes,
                                   int add_path,
                                   uint16_t afi) {
    int written = 0;

    while (*cursor) {
        int is_ipv6 = ((*cursor)->prefix.af == AF_INET6);
        int ip_len = is_ipv6 ? 16 : 4;
        /*
         * Route type (1) + length (1) + RD (8) + source length (1) +
         * source + group length (1) + group.
         */
        int needed = 2 + 8 + 1 + ip_len + 1 + ip_len;

        if ((afi == AFI_IPV4 && is_ipv6) ||
            (afi == AFI_IPV6 && !is_ipv6)) {
            return -1;
        }
        if ((int)(*cursor)->add_path != add_path) {
            return -1;
        }
        if (add_path) {
            needed += 4;
        }
        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        int encoded = bgp_encode_mvpn_type5_nlri(buffer + written, *cursor, add_path);
        if (encoded <= 0) {
            return -1;
        }
        written += encoded;
        *cursor = (*cursor)->next;
    }

    return written;
}

static int encode_mvpn_type6_chunk(mvpn_type6_nlri_t **cursor,
                                   uint8_t *buffer,
                                   int max_bytes,
                                   int add_path,
                                   uint16_t afi) {
    int written = 0;

    while (*cursor) {
        int is_ipv6 = ((*cursor)->prefix.af == AF_INET6);
        int ip_len = is_ipv6 ? 16 : 4;
        /*
         * Route type (1) + length (1) + RD (8) + Source AS (4) +
         * source length (1) + source + group length (1) + group.
         */
        int needed = 2 + 8 + 4 + 1 + ip_len + 1 + ip_len;

        if ((afi == AFI_IPV4 && is_ipv6) ||
            (afi == AFI_IPV6 && !is_ipv6)) {
            return -1;
        }
        if ((int)(*cursor)->add_path != add_path) {
            return -1;
        }
        if (add_path) {
            needed += 4;
        }
        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        int encoded = bgp_encode_mvpn_type6_nlri(buffer + written, *cursor, add_path);
        if (encoded <= 0) {
            return -1;
        }
        written += encoded;
        *cursor = (*cursor)->next;
    }

    return written;
}

static int encode_mvpn_type7_chunk(mvpn_type7_nlri_t **cursor,
                                   uint8_t *buffer,
                                   int max_bytes,
                                   int add_path,
                                   uint16_t afi) {
    int written = 0;

    while (*cursor) {
        int is_ipv6 = ((*cursor)->prefix.af == AF_INET6);
        int ip_len = is_ipv6 ? 16 : 4;
        /*
         * Route type (1) + length (1) + RD (8) + Source AS (4) +
         * source length (1) + source + group length (1) + group.
         */
        int needed = 2 + 8 + 4 + 1 + ip_len + 1 + ip_len;

        if ((afi == AFI_IPV4 && is_ipv6) ||
            (afi == AFI_IPV6 && !is_ipv6)) {
            return -1;
        }
        if ((int)(*cursor)->add_path != add_path) {
            return -1;
        }
        if (add_path) {
            needed += 4;
        }
        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        int encoded = bgp_encode_mvpn_type7_nlri(buffer + written, *cursor, add_path);
        if (encoded <= 0) {
            return -1;
        }
        written += encoded;
        *cursor = (*cursor)->next;
    }

    return written;
}

// MESSAGE GENERATION with splitting support

bgp_update_result_t* bgp_generate_update_mvpn_type1(
    mvpn_type1_nlri_t *nlri_list,
    bgp_path_attr_t *attributes,
    mvpn_type1_nlri_t *withdrawn_list,
    uint16_t max_pdu_size,
    uint16_t afi,
    const bgp_next_hop_t *next_hop)
{
    bgp_builder_t      builder = {0};
    uint8_t           *base_attr_data = NULL;
    uint16_t           base_attr_len = 0;
    uint8_t           *nlri_buffer = NULL;
    uint8_t            nh_buf[BGP_STANDARD_NEXT_HOP_BUF_SIZE];
    uint8_t            nh_len = 0;
    int                available_space;
    int                nlri_add_path = 0;
    int                withdrawn_add_path = 0;
    mvpn_type1_nlri_t *curr;

    if (afi != AFI_IPV4 && afi != AFI_IPV6) {
        return NULL;
    }

    if (max_pdu_size == 0) {
        max_pdu_size = BGP_MAX_PDU_SIZE;
    }
    if (max_pdu_size < BGP_UPDATE_MIN_SIZE) {
        return NULL;
    }

    if (bgp_attr_list_contains_type(attributes, BGP_ATTR_MP_REACH_NLRI) ||
        bgp_attr_list_contains_type(attributes, BGP_ATTR_MP_UNREACH_NLRI)) {
        return NULL;
    }

    if (bgp_detect_mvpn_type1_add_path(nlri_list, &nlri_add_path) < 0 ||
        bgp_detect_mvpn_type1_add_path(withdrawn_list, &withdrawn_add_path) < 0) {
        return NULL;
    }

    if (bgp_serialize_path_attributes_alloc(attributes,
                                            &base_attr_data,
                                            &base_attr_len) < 0) {
        return NULL;
    }

    if (nlri_list) {
        if (!bgp_validate_mp_attrs(attributes) ||
            bgp_encode_standard_next_hop(next_hop, nh_buf, &nh_len) < 0) {
            goto fail;
        }
    }

    if (bgp_builder_init(&builder) < 0) {
        goto fail;
    }

    nlri_buffer = malloc(max_pdu_size);
    if (!nlri_buffer) {
        goto fail;
    }

    if (withdrawn_list) {
        available_space = bgp_mp_unreach_payload_budget(max_pdu_size);
        if (available_space <= 0) {
            goto fail;
        }

        curr = withdrawn_list;
        while (curr) {
            int nlri_len = encode_mvpn_type1_chunk(&curr, nlri_buffer, available_space, withdrawn_add_path, afi);
            if (nlri_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .afi         = afi,
                    .safi        = SAFI_MVPN,
                    .mp_nlri     = nlri_buffer,
                    .mp_nlri_len = (uint16_t)nlri_len,
                }) < 0) {
                goto fail;
            }
        }
    }

    if (nlri_list) {
        available_space = bgp_mp_reach_payload_budget(max_pdu_size, base_attr_len, nh_len);
        if (available_space <= 0) {
            goto fail;
        }

        curr = nlri_list;
        while (curr) {
            int nlri_len = encode_mvpn_type1_chunk(&curr, nlri_buffer, available_space, nlri_add_path, afi);
            if (nlri_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .attrs       = base_attr_data,
                    .attrs_len   = base_attr_len,
                    .is_reach    = 1,
                    .afi         = afi,
                    .safi        = SAFI_MVPN,
                    .next_hop    = nh_buf,
                    .nh_len      = nh_len,
                    .mp_nlri     = nlri_buffer,
                    .mp_nlri_len = (uint16_t)nlri_len,
                }) < 0) {
                goto fail;
            }
        }
    } else if (!withdrawn_list) {
        if (bgp_builder_append_attrs_only(&builder,
                                          base_attr_data,
                                          base_attr_len) < 0) {
            goto fail;
        }
    }

    free(base_attr_data);
    free(nlri_buffer);
    return bgp_builder_take(&builder);

fail:
    free(base_attr_data);
    free(nlri_buffer);
    bgp_builder_release(&builder);
    return NULL;
}

bgp_update_result_t* bgp_generate_update_mvpn_type3(
    mvpn_type3_nlri_t *nlri_list,
    bgp_path_attr_t *attributes,
    mvpn_type3_nlri_t *withdrawn_list,
    uint16_t max_pdu_size,
    uint16_t afi,
    const bgp_next_hop_t *next_hop)
{
    bgp_builder_t      builder = {0};
    uint8_t           *base_attr_data = NULL;
    uint16_t           base_attr_len = 0;
    uint8_t           *nlri_buffer = NULL;
    uint8_t            nh_buf[BGP_STANDARD_NEXT_HOP_BUF_SIZE];
    uint8_t            nh_len = 0;
    int                available_space;
    int                nlri_add_path = 0;
    int                withdrawn_add_path = 0;
    mvpn_type3_nlri_t *curr;

    if (afi != AFI_IPV4 && afi != AFI_IPV6) {
        return NULL;
    }

    if (max_pdu_size == 0) {
        max_pdu_size = BGP_MAX_PDU_SIZE;
    }
    if (max_pdu_size < BGP_UPDATE_MIN_SIZE) {
        return NULL;
    }

    if (bgp_attr_list_contains_type(attributes, BGP_ATTR_MP_REACH_NLRI) ||
        bgp_attr_list_contains_type(attributes, BGP_ATTR_MP_UNREACH_NLRI)) {
        return NULL;
    }

    if (bgp_detect_mvpn_type3_add_path(nlri_list, &nlri_add_path) < 0 ||
        bgp_detect_mvpn_type3_add_path(withdrawn_list, &withdrawn_add_path) < 0) {
        return NULL;
    }

    if (bgp_serialize_path_attributes_alloc(attributes,
                                            &base_attr_data,
                                            &base_attr_len) < 0) {
        return NULL;
    }

    if (nlri_list) {
        if (!bgp_validate_mp_attrs(attributes) ||
            bgp_encode_standard_next_hop(next_hop, nh_buf, &nh_len) < 0) {
            goto fail;
        }
    }

    if (bgp_builder_init(&builder) < 0) {
        goto fail;
    }

    nlri_buffer = malloc(max_pdu_size);
    if (!nlri_buffer) {
        goto fail;
    }

    if (withdrawn_list) {
        available_space = bgp_mp_unreach_payload_budget(max_pdu_size);
        if (available_space <= 0) {
            goto fail;
        }

        curr = withdrawn_list;
        while (curr) {
            int nlri_len = encode_mvpn_type3_chunk(&curr, nlri_buffer, available_space, withdrawn_add_path, afi);
            if (nlri_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .afi         = afi,
                    .safi        = SAFI_MVPN,
                    .mp_nlri     = nlri_buffer,
                    .mp_nlri_len = (uint16_t)nlri_len,
                }) < 0) {
                goto fail;
            }
        }
    }

    if (nlri_list) {
        available_space = bgp_mp_reach_payload_budget(max_pdu_size, base_attr_len, nh_len);
        if (available_space <= 0) {
            goto fail;
        }

        curr = nlri_list;
        while (curr) {
            int nlri_len = encode_mvpn_type3_chunk(&curr, nlri_buffer, available_space, nlri_add_path, afi);
            if (nlri_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .attrs       = base_attr_data,
                    .attrs_len   = base_attr_len,
                    .is_reach    = 1,
                    .afi         = afi,
                    .safi        = SAFI_MVPN,
                    .next_hop    = nh_buf,
                    .nh_len      = nh_len,
                    .mp_nlri     = nlri_buffer,
                    .mp_nlri_len = (uint16_t)nlri_len,
                }) < 0) {
                goto fail;
            }
        }
    } else if (!withdrawn_list) {
        if (bgp_builder_append_attrs_only(&builder,
                                          base_attr_data,
                                          base_attr_len) < 0) {
            goto fail;
        }
    }

    free(base_attr_data);
    free(nlri_buffer);
    return bgp_builder_take(&builder);

fail:
    free(base_attr_data);
    free(nlri_buffer);
    bgp_builder_release(&builder);
    return NULL;
}

bgp_update_result_t* bgp_generate_update_mvpn_type2(
    mvpn_type2_nlri_t *nlri_list,
    bgp_path_attr_t *attributes,
    mvpn_type2_nlri_t *withdrawn_list,
    uint16_t max_pdu_size,
    uint16_t afi,
    const bgp_next_hop_t *next_hop)
{
    bgp_builder_t      builder = {0};
    uint8_t           *base_attr_data = NULL;
    uint16_t           base_attr_len = 0;
    uint8_t           *nlri_buffer = NULL;
    uint8_t            nh_buf[BGP_STANDARD_NEXT_HOP_BUF_SIZE];
    uint8_t            nh_len = 0;
    int                available_space;
    int                nlri_add_path = 0;
    int                withdrawn_add_path = 0;
    mvpn_type2_nlri_t *curr;

    if (afi != AFI_IPV4 && afi != AFI_IPV6) {
        return NULL;
    }

    if (max_pdu_size == 0) {
        max_pdu_size = BGP_MAX_PDU_SIZE;
    }
    if (max_pdu_size < BGP_UPDATE_MIN_SIZE) {
        return NULL;
    }

    if (bgp_attr_list_contains_type(attributes, BGP_ATTR_MP_REACH_NLRI) ||
        bgp_attr_list_contains_type(attributes, BGP_ATTR_MP_UNREACH_NLRI)) {
        return NULL;
    }

    if (bgp_detect_mvpn_type2_add_path(nlri_list, &nlri_add_path) < 0 ||
        bgp_detect_mvpn_type2_add_path(withdrawn_list, &withdrawn_add_path) < 0) {
        return NULL;
    }

    if (bgp_serialize_path_attributes_alloc(attributes,
                                            &base_attr_data,
                                            &base_attr_len) < 0) {
        return NULL;
    }

    if (nlri_list) {
        if (!bgp_validate_mp_attrs(attributes) ||
            bgp_encode_standard_next_hop(next_hop, nh_buf, &nh_len) < 0) {
            goto fail;
        }
    }

    if (bgp_builder_init(&builder) < 0) {
        goto fail;
    }

    nlri_buffer = malloc(max_pdu_size);
    if (!nlri_buffer) {
        goto fail;
    }

    if (withdrawn_list) {
        available_space = bgp_mp_unreach_payload_budget(max_pdu_size);
        if (available_space <= 0) {
            goto fail;
        }

        curr = withdrawn_list;
        while (curr) {
            int nlri_len = encode_mvpn_type2_chunk(&curr, nlri_buffer, available_space, withdrawn_add_path);
            if (nlri_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .afi         = afi,
                    .safi        = SAFI_MVPN,
                    .mp_nlri     = nlri_buffer,
                    .mp_nlri_len = (uint16_t)nlri_len,
                }) < 0) {
                goto fail;
            }
        }
    }

    if (nlri_list) {
        available_space = bgp_mp_reach_payload_budget(max_pdu_size, base_attr_len, nh_len);
        if (available_space <= 0) {
            goto fail;
        }

        curr = nlri_list;
        while (curr) {
            int nlri_len = encode_mvpn_type2_chunk(&curr, nlri_buffer, available_space, nlri_add_path);
            if (nlri_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .attrs       = base_attr_data,
                    .attrs_len   = base_attr_len,
                    .is_reach    = 1,
                    .afi         = afi,
                    .safi        = SAFI_MVPN,
                    .next_hop    = nh_buf,
                    .nh_len      = nh_len,
                    .mp_nlri     = nlri_buffer,
                    .mp_nlri_len = (uint16_t)nlri_len,
                }) < 0) {
                goto fail;
            }
        }
    } else if (!withdrawn_list) {
        if (bgp_builder_append_attrs_only(&builder,
                                          base_attr_data,
                                          base_attr_len) < 0) {
            goto fail;
        }
    }

    free(base_attr_data);
    free(nlri_buffer);
    return bgp_builder_take(&builder);

fail:
    free(base_attr_data);
    free(nlri_buffer);
    bgp_builder_release(&builder);
    return NULL;
}

bgp_update_result_t* bgp_generate_update_mvpn_type4(
    mvpn_type4_nlri_t *nlri_list,
    bgp_path_attr_t *attributes,
    mvpn_type4_nlri_t *withdrawn_list,
    uint16_t max_pdu_size,
    uint16_t afi,
    const bgp_next_hop_t *next_hop)
{
    bgp_builder_t      builder = {0};
    uint8_t           *base_attr_data = NULL;
    uint16_t           base_attr_len = 0;
    uint8_t           *nlri_buffer = NULL;
    uint8_t            nh_buf[BGP_STANDARD_NEXT_HOP_BUF_SIZE];
    uint8_t            nh_len = 0;
    int                available_space;
    int                nlri_add_path = 0;
    int                withdrawn_add_path = 0;
    mvpn_type4_nlri_t *curr;

    if (afi != AFI_IPV4 && afi != AFI_IPV6) {
        return NULL;
    }

    if (max_pdu_size == 0) {
        max_pdu_size = BGP_MAX_PDU_SIZE;
    }
    if (max_pdu_size < BGP_UPDATE_MIN_SIZE) {
        return NULL;
    }

    if (bgp_attr_list_contains_type(attributes, BGP_ATTR_MP_REACH_NLRI) ||
        bgp_attr_list_contains_type(attributes, BGP_ATTR_MP_UNREACH_NLRI)) {
        return NULL;
    }

    if (bgp_detect_mvpn_type4_add_path(nlri_list, &nlri_add_path) < 0 ||
        bgp_detect_mvpn_type4_add_path(withdrawn_list, &withdrawn_add_path) < 0) {
        return NULL;
    }

    if (bgp_serialize_path_attributes_alloc(attributes,
                                            &base_attr_data,
                                            &base_attr_len) < 0) {
        return NULL;
    }

    if (nlri_list) {
        if (!bgp_validate_mp_attrs(attributes) ||
            bgp_encode_standard_next_hop(next_hop, nh_buf, &nh_len) < 0) {
            goto fail;
        }
    }

    if (bgp_builder_init(&builder) < 0) {
        goto fail;
    }

    nlri_buffer = malloc(max_pdu_size);
    if (!nlri_buffer) {
        goto fail;
    }

    if (withdrawn_list) {
        available_space = bgp_mp_unreach_payload_budget(max_pdu_size);
        if (available_space <= 0) {
            goto fail;
        }

        curr = withdrawn_list;
        while (curr) {
            int nlri_len = encode_mvpn_type4_chunk(&curr, nlri_buffer, available_space, withdrawn_add_path, afi);
            if (nlri_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .afi         = afi,
                    .safi        = SAFI_MVPN,
                    .mp_nlri     = nlri_buffer,
                    .mp_nlri_len = (uint16_t)nlri_len,
                }) < 0) {
                goto fail;
            }
        }
    }

    if (nlri_list) {
        available_space = bgp_mp_reach_payload_budget(max_pdu_size, base_attr_len, nh_len);
        if (available_space <= 0) {
            goto fail;
        }

        curr = nlri_list;
        while (curr) {
            int nlri_len = encode_mvpn_type4_chunk(&curr, nlri_buffer, available_space, nlri_add_path, afi);
            if (nlri_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .attrs       = base_attr_data,
                    .attrs_len   = base_attr_len,
                    .is_reach    = 1,
                    .afi         = afi,
                    .safi        = SAFI_MVPN,
                    .next_hop    = nh_buf,
                    .nh_len      = nh_len,
                    .mp_nlri     = nlri_buffer,
                    .mp_nlri_len = (uint16_t)nlri_len,
                }) < 0) {
                goto fail;
            }
        }
    } else if (!withdrawn_list) {
        if (bgp_builder_append_attrs_only(&builder,
                                          base_attr_data,
                                          base_attr_len) < 0) {
            goto fail;
        }
    }

    free(base_attr_data);
    free(nlri_buffer);
    return bgp_builder_take(&builder);

fail:
    free(base_attr_data);
    free(nlri_buffer);
    bgp_builder_release(&builder);
    return NULL;
}

bgp_update_result_t* bgp_generate_update_mvpn_type5(
    mvpn_type5_nlri_t *nlri_list,
    bgp_path_attr_t *attributes,
    mvpn_type5_nlri_t *withdrawn_list,
    uint16_t max_pdu_size,
    uint16_t afi,
    const bgp_next_hop_t *next_hop)
{
    bgp_builder_t      builder = {0};
    uint8_t           *base_attr_data = NULL;
    uint16_t           base_attr_len = 0;
    uint8_t           *nlri_buffer = NULL;
    uint8_t            nh_buf[BGP_STANDARD_NEXT_HOP_BUF_SIZE];
    uint8_t            nh_len = 0;
    int                available_space;
    int                nlri_add_path = 0;
    int                withdrawn_add_path = 0;
    mvpn_type5_nlri_t *curr;

    if (afi != AFI_IPV4 && afi != AFI_IPV6) {
        return NULL;
    }

    if (max_pdu_size == 0) {
        max_pdu_size = BGP_MAX_PDU_SIZE;
    }
    if (max_pdu_size < BGP_UPDATE_MIN_SIZE) {
        return NULL;
    }

    if (bgp_attr_list_contains_type(attributes, BGP_ATTR_MP_REACH_NLRI) ||
        bgp_attr_list_contains_type(attributes, BGP_ATTR_MP_UNREACH_NLRI)) {
        return NULL;
    }

    if (bgp_detect_mvpn_type5_add_path(nlri_list, &nlri_add_path) < 0 ||
        bgp_detect_mvpn_type5_add_path(withdrawn_list, &withdrawn_add_path) < 0) {
        return NULL;
    }

    if (bgp_serialize_path_attributes_alloc(attributes,
                                            &base_attr_data,
                                            &base_attr_len) < 0) {
        return NULL;
    }

    if (nlri_list) {
        if (!bgp_validate_mp_attrs(attributes) ||
            bgp_encode_standard_next_hop(next_hop, nh_buf, &nh_len) < 0) {
            goto fail;
        }
    }

    if (bgp_builder_init(&builder) < 0) {
        goto fail;
    }

    nlri_buffer = malloc(max_pdu_size);
    if (!nlri_buffer) {
        goto fail;
    }

    if (withdrawn_list) {
        available_space = bgp_mp_unreach_payload_budget(max_pdu_size);
        if (available_space <= 0) {
            goto fail;
        }

        curr = withdrawn_list;
        while (curr) {
            int nlri_len = encode_mvpn_type5_chunk(&curr, nlri_buffer, available_space, withdrawn_add_path, afi);
            if (nlri_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .afi         = afi,
                    .safi        = SAFI_MVPN,
                    .mp_nlri     = nlri_buffer,
                    .mp_nlri_len = (uint16_t)nlri_len,
                }) < 0) {
                goto fail;
            }
        }
    }

    if (nlri_list) {
        available_space = bgp_mp_reach_payload_budget(max_pdu_size, base_attr_len, nh_len);
        if (available_space <= 0) {
            goto fail;
        }

        curr = nlri_list;
        while (curr) {
            int nlri_len = encode_mvpn_type5_chunk(&curr, nlri_buffer, available_space, nlri_add_path, afi);
            if (nlri_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .attrs       = base_attr_data,
                    .attrs_len   = base_attr_len,
                    .is_reach    = 1,
                    .afi         = afi,
                    .safi        = SAFI_MVPN,
                    .next_hop    = nh_buf,
                    .nh_len      = nh_len,
                    .mp_nlri     = nlri_buffer,
                    .mp_nlri_len = (uint16_t)nlri_len,
                }) < 0) {
                    goto fail;
            }
        }
    } else if (!withdrawn_list) {
        if (bgp_builder_append_attrs_only(&builder,
                                          base_attr_data,
                                          base_attr_len) < 0) {
            goto fail;
        }
    }

    free(base_attr_data);
    free(nlri_buffer);
    return bgp_builder_take(&builder);

fail:
    free(base_attr_data);
    free(nlri_buffer);
    bgp_builder_release(&builder);
    return NULL;
}

bgp_update_result_t* bgp_generate_update_mvpn_type6(
    mvpn_type6_nlri_t *nlri_list,
    bgp_path_attr_t *attributes,
    mvpn_type6_nlri_t *withdrawn_list,
    uint16_t max_pdu_size,
    uint16_t afi,
    const bgp_next_hop_t *next_hop)
{
    bgp_builder_t      builder = {0};
    uint8_t           *base_attr_data = NULL;
    uint16_t           base_attr_len = 0;
    uint8_t           *nlri_buffer = NULL;
    uint8_t            nh_buf[BGP_STANDARD_NEXT_HOP_BUF_SIZE];
    uint8_t            nh_len = 0;
    int                available_space;
    int                nlri_add_path = 0;
    int                withdrawn_add_path = 0;
    mvpn_type6_nlri_t *curr;

    if (afi != AFI_IPV4 && afi != AFI_IPV6) {
        return NULL;
    }

    if (max_pdu_size == 0) {
        max_pdu_size = BGP_MAX_PDU_SIZE;
    }
    if (max_pdu_size < BGP_UPDATE_MIN_SIZE) {
        return NULL;
    }

    if (bgp_attr_list_contains_type(attributes, BGP_ATTR_MP_REACH_NLRI) ||
        bgp_attr_list_contains_type(attributes, BGP_ATTR_MP_UNREACH_NLRI)) {
        return NULL;
    }

    if (bgp_detect_mvpn_type6_add_path(nlri_list, &nlri_add_path) < 0 ||
        bgp_detect_mvpn_type6_add_path(withdrawn_list, &withdrawn_add_path) < 0) {
        return NULL;
    }

    if (bgp_serialize_path_attributes_alloc(attributes,
                                            &base_attr_data,
                                            &base_attr_len) < 0) {
        return NULL;
    }

    if (nlri_list) {
        if (!bgp_validate_mp_attrs(attributes) ||
            bgp_encode_standard_next_hop(next_hop, nh_buf, &nh_len) < 0) {
            goto fail;
        }
    }

    if (bgp_builder_init(&builder) < 0) {
        goto fail;
    }

    nlri_buffer = malloc(max_pdu_size);
    if (!nlri_buffer) {
        goto fail;
    }

    if (withdrawn_list) {
        available_space = bgp_mp_unreach_payload_budget(max_pdu_size);
        if (available_space <= 0) {
            goto fail;
        }

        curr = withdrawn_list;
        while (curr) {
            int nlri_len = encode_mvpn_type6_chunk(&curr, nlri_buffer, available_space, withdrawn_add_path, afi);
            if (nlri_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .afi         = afi,
                    .safi        = SAFI_MVPN,
                    .mp_nlri     = nlri_buffer,
                    .mp_nlri_len = (uint16_t)nlri_len,
                }) < 0) {
                goto fail;
            }
        }
    }

    if (nlri_list) {
        available_space = bgp_mp_reach_payload_budget(max_pdu_size, base_attr_len, nh_len);
        if (available_space <= 0) {
            goto fail;
        }

        curr = nlri_list;
        while (curr) {
            int nlri_len = encode_mvpn_type6_chunk(&curr, nlri_buffer, available_space, nlri_add_path, afi);
            if (nlri_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .attrs       = base_attr_data,
                    .attrs_len   = base_attr_len,
                    .is_reach    = 1,
                    .afi         = afi,
                    .safi        = SAFI_MVPN,
                    .next_hop    = nh_buf,
                    .nh_len      = nh_len,
                    .mp_nlri     = nlri_buffer,
                    .mp_nlri_len = (uint16_t)nlri_len,
                }) < 0) {
                goto fail;
            }
        }
    } else if (!withdrawn_list) {
        if (bgp_builder_append_attrs_only(&builder,
                                          base_attr_data,
                                          base_attr_len) < 0) {
            goto fail;
        }
    }

    free(base_attr_data);
    free(nlri_buffer);
    return bgp_builder_take(&builder);

fail:
    free(base_attr_data);
    free(nlri_buffer);
    bgp_builder_release(&builder);
    return NULL;
}

bgp_update_result_t* bgp_generate_update_mvpn_type7(
    mvpn_type7_nlri_t *nlri_list,
    bgp_path_attr_t *attributes,
    mvpn_type7_nlri_t *withdrawn_list,
    uint16_t max_pdu_size,
    uint16_t afi,
    const bgp_next_hop_t *next_hop)
{
    bgp_builder_t      builder = {0};
    uint8_t           *base_attr_data = NULL;
    uint16_t           base_attr_len = 0;
    uint8_t           *nlri_buffer = NULL;
    uint8_t            nh_buf[BGP_STANDARD_NEXT_HOP_BUF_SIZE];
    uint8_t            nh_len = 0;
    int                available_space;
    int                nlri_add_path = 0;
    int                withdrawn_add_path = 0;
    mvpn_type7_nlri_t *curr;

    if (afi != AFI_IPV4 && afi != AFI_IPV6) {
        return NULL;
    }

    if (max_pdu_size == 0) {
        max_pdu_size = BGP_MAX_PDU_SIZE;
    }
    if (max_pdu_size < BGP_UPDATE_MIN_SIZE) {
        return NULL;
    }

    if (bgp_attr_list_contains_type(attributes, BGP_ATTR_MP_REACH_NLRI) ||
        bgp_attr_list_contains_type(attributes, BGP_ATTR_MP_UNREACH_NLRI)) {
        return NULL;
    }

    if (bgp_detect_mvpn_type7_add_path(nlri_list, &nlri_add_path) < 0 ||
        bgp_detect_mvpn_type7_add_path(withdrawn_list, &withdrawn_add_path) < 0) {
        return NULL;
    }

    if (bgp_serialize_path_attributes_alloc(attributes,
                                            &base_attr_data,
                                            &base_attr_len) < 0) {
        return NULL;
    }

    if (nlri_list) {
        if (!bgp_validate_mp_attrs(attributes) ||
            bgp_encode_standard_next_hop(next_hop, nh_buf, &nh_len) < 0) {
            goto fail;
        }
    }

    if (bgp_builder_init(&builder) < 0) {
        goto fail;
    }

    nlri_buffer = malloc(max_pdu_size);
    if (!nlri_buffer) {
        goto fail;
    }

    if (withdrawn_list) {
        available_space = bgp_mp_unreach_payload_budget(max_pdu_size);
        if (available_space <= 0) {
            goto fail;
        }

        curr = withdrawn_list;
        while (curr) {
            int nlri_len = encode_mvpn_type7_chunk(&curr, nlri_buffer, available_space, withdrawn_add_path, afi);
            if (nlri_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .afi         = afi,
                    .safi        = SAFI_MVPN,
                    .mp_nlri     = nlri_buffer,
                    .mp_nlri_len = (uint16_t)nlri_len,
                }) < 0) {
                goto fail;
            }
        }
    }

    if (nlri_list) {
        available_space = bgp_mp_reach_payload_budget(max_pdu_size, base_attr_len, nh_len);
        if (available_space <= 0) {
            goto fail;
        }

        curr = nlri_list;
        while (curr) {
            int nlri_len = encode_mvpn_type7_chunk(&curr, nlri_buffer, available_space, nlri_add_path, afi);
            if (nlri_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .attrs       = base_attr_data,
                    .attrs_len   = base_attr_len,
                    .is_reach    = 1,
                    .afi         = afi,
                    .safi        = SAFI_MVPN,
                    .next_hop    = nh_buf,
                    .nh_len      = nh_len,
                    .mp_nlri     = nlri_buffer,
                    .mp_nlri_len = (uint16_t)nlri_len,
                }) < 0) {
                goto fail;
            }
        }
    } else if (!withdrawn_list) {
        if (bgp_builder_append_attrs_only(&builder,
                                          base_attr_data,
                                          base_attr_len) < 0) {
            goto fail;
        }
    }

    free(base_attr_data);
    free(nlri_buffer);
    return bgp_builder_take(&builder);

fail:
    free(base_attr_data);
    free(nlri_buffer);
    bgp_builder_release(&builder);
    return NULL;
}
