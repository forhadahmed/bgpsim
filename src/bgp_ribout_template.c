#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "bgp.h"
#include "util.h"
#include "bgp_update.h"
#include "bgp_ribout_config.h"

/*
 * One typed route template per block. The protocol encoders remain the sole owners of wire layouts.
 */
enum {
    STEP_NONE, STEP_RD, STEP_TARGET, STEP_VE, STEP_ROUTER, STEP_SOURCE, STEP_GROUP, STEP_TAG, STEP_ID, STEP_ESI,
    // BGP-LS identity axes: the node (its Router-ID, local and remote together), the link descriptors, the prefix,
    // the SRv6 SID, and the remote node alone (the neighbors or BGP peers of one node). An SR Policy candidate
    // path (RFC 9857) has its color, endpoint and discriminator.
    STEP_NODE, STEP_LINK, STEP_PREFIX, STEP_SID, STEP_REMOTE, STEP_COLOR, STEP_ENDPOINT, STEP_DISCRIMINATOR
};

typedef struct {
    char *next;
} tokens_t;

static char *word(tokens_t *tokens) {
    char *start = tokens->next;
    while (*start && isspace((unsigned char)*start))
        start++;
    if (!*start)
        return NULL;
    char *end = start;
    while (*end && !isspace((unsigned char)*end))
        end++;
    tokens->next = *end ? end + 1 : end;
    *end = '\0';
    return start;
}

static char *field(tokens_t *tokens, const char *key) {
    char *name = word(tokens);
    return name && strcmp(name, key) == 0 ? word(tokens) : NULL;
}

static int number(const char *text, uint64_t max, uint64_t *out) {
    if (!text || !*text)
        return -1;
    for (const char *p = text; *p; p++)
        if (!isdigit((unsigned char)*p))
            return -1;
    errno = 0;
    char *end;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno || *end || value > max)
        return -1;
    *out = value;
    return 0;
}

/*
 * A number in decimal, or in hexadecimal with 0x (flags and masks read better that way).
 */
static int number_any(const char *text, uint64_t max, uint64_t *out) {
    if (!text || text[0] != '0' || (text[1] != 'x' && text[1] != 'X'))
        return number(text, max, out);
    if (!text[2])
        return -1;
    for (const char *p = text + 2; *p; p++)
        if (!isxdigit((unsigned char)*p))
            return -1;
    errno = 0;
    char *end;
    unsigned long long value = strtoull(text + 2, &end, 16);
    if (errno || *end || value > max)
        return -1;
    *out = value;
    return 0;
}

/*
 * True when the next word is key; the word stays unread.
 */
static int next_is(const tokens_t *tokens, const char *key) {
    const char *p = tokens->next;
    size_t      len = strlen(key);
    while (*p && isspace((unsigned char)*p))
        p++;
    return !strncmp(p, key, len) && (!p[len] || isspace((unsigned char)p[len]));
}

static int numeric_field(tokens_t *tokens, const char *key, uint64_t max, uint64_t *value) {
    return number(field(tokens, key), max, value);
}

static int hex_bytes(const char *text, uint8_t *out, size_t cap) {
    if (!text || !*text || strlen(text) % 2 || strlen(text) / 2 > cap)
        return -1;
    size_t len = strlen(text) / 2;
    for (size_t i = 0; i < len; i++) {
        unsigned byte;
        if (!isxdigit((unsigned char)text[2 * i]) || !isxdigit((unsigned char)text[2 * i + 1]) ||
            sscanf(text + 2 * i, "%2x", &byte) != 1)
            return -1;
        out[i] = (uint8_t)byte;
    }
    return (int)len;
}

static int address(const char *text, uint8_t *out, uint8_t *af) {
    if (!text)
        return -1;
    int parsed_af = strchr(text, ':') ? AF_INET6 : AF_INET;
    if (*af && *af != parsed_af)
        return -1;
    if (inet_pton(parsed_af, text, out) != 1)
        return -1;
    *af = (uint8_t)parsed_af;
    return 0;
}

static int add_bytes(uint8_t *bytes, size_t len, uint64_t increment) {
    while (len) {
        len--;
        increment += bytes[len];
        bytes[len] = (uint8_t)increment;
        increment >>= 8;
    }
    return increment ? -1 : 0;
}

static void put_be(uint8_t *out, uint64_t value, size_t width) {
    while (width) {
        out[--width] = (uint8_t)value;
        value >>= 8;
    }
}

/*
 * Append one TLV to a descriptor chain; -1 when it does not fit.
 */
static int put_tlv(uint8_t *chain, size_t cap, uint16_t *len, uint16_t type, const uint8_t *value, uint16_t value_len) {
    if ((size_t)*len + 4 + value_len > cap)
        return -1;
    chain[*len] = (uint8_t)(type >> 8);
    chain[*len + 1] = (uint8_t)type;
    chain[*len + 2] = (uint8_t)(value_len >> 8);
    chain[*len + 3] = (uint8_t)value_len;
    memcpy(chain + *len + 4, value, value_len);
    *len = (uint16_t)(*len + 4 + value_len);
    return 0;
}

/*
 * The TLVs of an encoded chain as a list for the BGP-LS encoder, which copies their values; NULL for an empty chain.
 */
static bgpls_tlv_t *chain_view(uint8_t *chain, uint16_t len, bgpls_tlv_t *tlvs, size_t max) {
    size_t count = 0;
    for (uint16_t off = 0; off + 4 <= len && count < max; count++) {
        tlvs[count] = (bgpls_tlv_t){.type = (uint16_t)((chain[off] << 8) | chain[off + 1]),
                                    .length = (uint16_t)((chain[off + 2] << 8) | chain[off + 3]),
                                    .value = chain + off + 4};
        if (count)
            tlvs[count - 1].next = &tlvs[count];
        off = (uint16_t)(off + 4 + tlvs[count].length);
    }
    return count ? tlvs : NULL;
}

/*
 * The octets one BGP-LS identity axis adds an instance number to. One axis can move several fields together: a link
 * template that steps its node moves the local and the remote Router-ID, so link i joins node i to its neighbor.
 */
typedef struct {
    uint8_t *bytes;
    size_t   len;
    unsigned shift;  /* The instance number is added times 2^shift */
} step_range_t;

#define LS_STEP_RANGES 6

static size_t ls_step_ranges(bgp_ribout_template_t *s, int axis, step_range_t *ranges) {
    bgpls_tlv_t tlvs[8];
    size_t      count = 0;
    if (s->family != BGP_RIBOUT_FAMILY_BGP_LS)
        return 0;
    if (axis == STEP_NODE || axis == STEP_REMOTE) {
        // A pseudonode keeps its trailing octets: the sequence is over the System-ID or the Router-ID. A BGP node
        // (RFC 9086) is named by its BGP Router-ID.
        size_t id = s->protocol == BGPLS_PROTO_ISIS_L1 || s->protocol == BGPLS_PROTO_ISIS_L2 ? 6
                    : s->protocol == BGPLS_PROTO_OSPFV2 || s->protocol == BGPLS_PROTO_OSPFV3 ? 4
                                                                                             : 16;
        uint16_t type = s->protocol == BGPLS_PROTO_BGP ? BGPLS_TLV_BGP_ROUTER_ID : BGPLS_TLV_IGP_ROUTER_ID;
        uint8_t *chains[] = {s->local_desc, s->remote_desc};
        uint16_t lens[] = {s->local_len, s->remote_len};
        for (int i = axis == STEP_REMOTE; i < 2; i++)
            for (bgpls_tlv_t *tlv = chain_view(chains[i], lens[i], tlvs, 8); tlv; tlv = tlv->next) {
                // The headend of an SR Policy: its Router-ID (TLV 1028 or 1029) and, when given, its BGP Router-ID.
                int headend = s->protocol == BGPLS_PROTO_SR &&
                              (tlv->type == BGPLS_TLV_BGP_ROUTER_ID || tlv->type == BGPLS_TLV_IPV4_ROUTER_ID ||
                               tlv->type == BGPLS_TLV_IPV6_ROUTER_ID);
                if (headend || (s->protocol != BGPLS_PROTO_SR && tlv->type == type))
                    ranges[count++] = (step_range_t){tlv->value, tlv->length < id ? tlv->length : id, 0};
            }
        return count;
    }
    if (axis >= STEP_COLOR) {
        // RFC 9857 section 4: Protocol-Origin, flags, two reserved octets, the endpoint (16 octets with the E flag),
        // the color, the originator AS and address, and the discriminator in the last four octets.
        bgpls_tlv_t *tlv = chain_view(s->descriptor, s->descriptor_len, tlvs, 8);
        if (!tlv || tlv->type != BGPLS_TLV_SR_POLICY_CP || tlv->length < 24)
            return 0;
        size_t endpoint = (tlv->value[1] & 0x80) ? 16 : 4;
        ranges[0] = axis == STEP_ENDPOINT ? (step_range_t){tlv->value + 4, endpoint, 0}
                    : axis == STEP_COLOR  ? (step_range_t){tlv->value + 4 + endpoint, 4, 0}
                                          : (step_range_t){tlv->value + tlv->length - 4, 4, 0};
        return 1;
    }
    for (bgpls_tlv_t *tlv = chain_view(s->descriptor, s->descriptor_len, tlvs, 8); tlv; tlv = tlv->next) {
        if (axis == STEP_LINK && tlv->type == BGPLS_TLV_LINK_LOCAL_REMOTE && tlv->length == 8) {
            ranges[count++] = (step_range_t){tlv->value, 4, 0};
            ranges[count++] = (step_range_t){tlv->value + 4, 4, 0};
        } else if (axis == STEP_LINK && tlv->type >= BGPLS_TLV_IPV4_IFACE_ADDR &&
                   tlv->type <= BGPLS_TLV_IPV6_NEIGHBOR_ADDR) {
            ranges[count++] = (step_range_t){tlv->value, tlv->length, 0};
        } else if (axis == STEP_PREFIX && tlv->type == BGPLS_TLV_IP_REACH_INFO && tlv->length > 1) {
            ranges[count++] = (step_range_t){tlv->value + 1, tlv->length - 1U, (8 - tlv->value[0] % 8) % 8};
        } else if (axis == STEP_SID && tlv->type == BGPLS_TLV_SRV6_SID_INFO && tlv->length == 16) {
            ranges[count++] = (step_range_t){tlv->value, s->step_bits / 8U, 0};
        }
    }
    return count;
}

/*
 * Find the octets the axes of a BGP-LS template step, once: template_step() then needs no walk of the descriptors.
 */
static void ls_step_cache(bgp_ribout_template_t *s) {
    int axes[BGP_RIBOUT_STEP_AXES] = {s->step, s->more_steps[0], s->more_steps[1]};
    for (int which = 0; which < BGP_RIBOUT_STEP_AXES; which++) {
        step_range_t ranges[LS_STEP_RANGES];
        size_t       count = axes[which] >= STEP_NODE ? ls_step_ranges(s, axes[which], ranges) : 0;
        s->ls_steps[which] = (uint8_t)count;
        for (size_t i = 0; i < count; i++) {
            s->ls_step[which][i].off = (uint16_t)(ranges[i].bytes - (uint8_t *)s);
            s->ls_step[which][i].len = (uint8_t)ranges[i].len;
            s->ls_step[which][i].shift = (uint8_t)ranges[i].shift;
        }
    }
}

/*
 * Add an instance number to the field of one axis; `which` is 0 for the template's first axis and 1 for its second.
 */
static int template_step_axis(bgp_ribout_template_t *s, int axis, int which, uint64_t instance) {
    size_t len = s->af == AF_INET6 ? 16 : 4;
    switch (axis) {
    case STEP_NONE:
        return instance ? -1 : 0;
    case STEP_RD: {
        size_t width = s->rd.type == 0 ? 4 : 2;
        return add_bytes(s->rd.value + 6 - width, width, instance);
    }
    case STEP_TARGET: {
        size_t width = s->target[0] == 0 ? 4 : 2;
        return add_bytes(s->target + 8 - width, width, instance);
    }
    case STEP_VE:
        if (instance > UINT16_MAX - (uint64_t)s->ve_id)
            return -1;
        s->ve_id += (uint16_t)instance;
        return 0;
    case STEP_ROUTER:
        return add_bytes(s->router, len, instance);
    case STEP_SOURCE:
        return add_bytes(s->source, len, instance);
    case STEP_GROUP:
        return add_bytes(s->group, len, instance);
    case STEP_TAG:
        if (instance > UINT32_MAX - (uint64_t)s->tag)
            return -1;
        s->tag += (uint32_t)instance;
        return 0;
    case STEP_ID:
        if (instance > UINT64_MAX - s->identifier)
            return -1;
        s->identifier += instance;
        return 0;
    case STEP_ESI:
        return add_bytes(s->esi.value, sizeof(s->esi.value), instance);
    case STEP_NODE:
    case STEP_LINK:
    case STEP_PREFIX:
    case STEP_SID:
    case STEP_REMOTE:
    case STEP_COLOR:
    case STEP_ENDPOINT:
    case STEP_DISCRIMINATOR: {
        if (!s->ls_steps[which] || instance > UINT32_MAX)
            return -1;
        for (size_t i = 0; i < s->ls_steps[which]; i++)
            if (bytes_be_add((uint8_t *)s + s->ls_step[which][i].off, s->ls_step[which][i].len, (uint32_t)instance,
                             s->ls_step[which][i].shift) < 0)
                return -1;
        return 0;
    }
    default:
        return -1;
    }
}

void bgp_ribout_template_axis_indexes(const bgp_ribout_template_t *t, uint64_t instance, uint32_t index[BGP_RIBOUT_STEP_AXES]) {
    // The last axis is the innermost: it takes the instance modulo its count, and the axes before it the rest.
    for (int which = BGP_RIBOUT_STEP_AXES - 1; which > 0; which--) {
        uint32_t values = t->more_steps[which - 1] ? t->more_counts[which - 1] : 1;
        index[which] = (uint32_t)(instance % values);
        instance /= values;
    }
    index[0] = (uint32_t)instance;
}

/*
 * Instance i of a template: each axis adds the index the instance has on it. Every value of an axis has every
 * value of the axes after it.
 */
static int template_step(bgp_ribout_template_t *s, uint64_t instance) {
    uint32_t index[BGP_RIBOUT_STEP_AXES];
    bgp_ribout_template_axis_indexes(s, instance, index);
    if (template_step_axis(s, s->step, 0, index[0]) < 0)
        return -1;
    for (int which = 1; which < BGP_RIBOUT_STEP_AXES; which++)
        if (s->more_steps[which - 1] && template_step_axis(s, s->more_steps[which - 1], which, index[which]) < 0)
            return -1;
    return 0;
}

int bgp_ribout_template_encode(const bgp_ribout_template_t *base, uint64_t instance, int label_vni, uint8_t *buffer) {
    bgp_ribout_template_t s;
    if (!base || !buffer || instance >= base->count)
        return -1;
    // The display text is not needed for materialization.
    memcpy(&s, base, offsetof(bgp_ribout_template_t, text));
    if (template_step(&s, instance) < 0)
        return -1;
    if (s.local_len > sizeof(s.local_desc) || s.remote_len > sizeof(s.remote_desc) ||
        s.descriptor_len > sizeof(s.descriptor) || s.route_key_len > sizeof(s.route_key))
        return -1;
    if ((s.family == BGP_RIBOUT_FAMILY_MVPN_IPV4 || s.family == BGP_RIBOUT_FAMILY_MVPN_IPV6) && s.route_type >= 3 &&
        s.route_type != 4 &&
        ((s.af == AF_INET && (s.group[0] & 0xF0) != 0xE0) || (s.af == AF_INET6 && s.group[0] != 0xFF)))
        return -1;
    int bits = s.af == AF_INET6 ? 128 : 32;
    switch (s.family) {
    case BGP_RIBOUT_FAMILY_RTC: {
        rtc_prefix_t p = {.prefix_len = s.is_default ? 0 : 96, .origin_as = htonl(s.origin_as)};
        memcpy(p.route_target, s.target, 8);
        return bgp_encode_rtc_prefix(buffer, &p);
    }
    case BGP_RIBOUT_FAMILY_VPLS: {
        vpls_prefix_t p = {.length = 17,
                           .rd = s.rd,
                           .ve_id = s.ve_id,
                           .ve_block_offset = s.offset,
                           .ve_block_size = s.size,
                           .label_base = {.label = s.label, .s = 1}};
        return bgp_encode_vpls_prefix(buffer, &p);
    }
    case BGP_RIBOUT_FAMILY_EVPN_TYPE1: {
        // RFC 8365 section 5.1.3: with a VNI encapsulation the label field carries the whole 24-bit VNI.
        evpn_type1_prefix_t p = {.route_type = 1,
                                 .rd = s.rd,
                                 .esi = s.esi,
                                 .ethernet_tag_id = s.tag,
                                 .label = {.label = s.label, .s = 1},
                                 .label_vni = label_vni != 0};
        return bgp_encode_evpn_type1_prefix(buffer, &p);
    }
    case BGP_RIBOUT_FAMILY_EVPN_TYPE3: {
        evpn_type3_prefix_t p = {.route_type = 3, .rd = s.rd, .ethernet_tag_id = s.tag, .ip_addr_len = bits};
        memcpy(p.orig_router_ip, s.router, 16);
        return bgp_encode_evpn_type3_prefix(buffer, &p);
    }
    case BGP_RIBOUT_FAMILY_EVPN_TYPE4: {
        evpn_type4_prefix_t p = {.route_type = 4, .rd = s.rd, .esi = s.esi, .ip_addr_len = bits};
        memcpy(p.orig_router_ip, s.router, 16);
        return bgp_encode_evpn_type4_prefix(buffer, &p);
    }
    case BGP_RIBOUT_FAMILY_MVPN_IPV4:
    case BGP_RIBOUT_FAMILY_MVPN_IPV6:
        switch (s.route_type) {
        case 1: {
            mvpn_type1_prefix_t p = {.route_type = 1, .af = s.af, .rd = s.rd};
            memcpy(p.orig_router_ip, s.router, 16);
            return bgp_encode_mvpn_type1_prefix(buffer, &p);
        }
        case 2: {
            mvpn_type2_prefix_t p = {.route_type = 2, .rd = s.rd, .source_as = htonl(s.source_as)};
            return bgp_encode_mvpn_type2_prefix(buffer, &p);
        }
        case 3: {
            mvpn_type3_prefix_t p = {
                .route_type = 3, .af = s.af, .rd = s.rd, .mcast_src_len = bits, .mcast_grp_len = bits};
            memcpy(p.mcast_src, s.source, 16);
            memcpy(p.mcast_grp, s.group, 16);
            memcpy(p.orig_router_ip, s.router, 16);
            return bgp_encode_mvpn_type3_prefix(buffer, &p);
        }
        case 4: {
            mvpn_type4_prefix_t p = {.route_type = 4, .af = s.af, .route_key_len = s.route_key_len};
            memcpy(p.route_key, s.route_key, s.route_key_len);
            memcpy(p.orig_router_ip, s.router, 16);
            return bgp_encode_mvpn_type4_prefix(buffer, &p);
        }
        case 5: {
            mvpn_type5_prefix_t p = {
                .route_type = 5, .af = s.af, .rd = s.rd, .mcast_src_len = bits, .mcast_grp_len = bits};
            memcpy(p.mcast_src, s.source, 16);
            memcpy(p.mcast_grp, s.group, 16);
            return bgp_encode_mvpn_type5_prefix(buffer, &p);
        }
        case 6:
        case 7: {
            mvpn_cmulticast_prefix_t p = {.route_type = s.route_type,
                                          .af = s.af,
                                          .rd = s.rd,
                                          .source_as = htonl(s.source_as),
                                          .mcast_src_len = bits,
                                          .mcast_grp_len = bits};
            memcpy(p.mcast_src, s.source, 16);
            memcpy(p.mcast_grp, s.group, 16);
            return s.route_type == 6 ? bgp_encode_mvpn_type6_prefix(buffer, &p)
                                     : bgp_encode_mvpn_type7_prefix(buffer, &p);
        }
        default:
            return -1;
        }
    case BGP_RIBOUT_FAMILY_BGP_LS: {
        bgpls_tlv_t  local = {.type = BGPLS_TLV_LOCAL_NODE_DESC, .length = s.local_len, .value = s.local_desc};
        bgpls_tlv_t  remote = {.type = BGPLS_TLV_REMOTE_NODE_DESC, .length = s.remote_len, .value = s.remote_desc};
        bgpls_tlv_t  tlvs[8];
        bgpls_tlv_t *desc = chain_view(s.descriptor, s.descriptor_len, tlvs, 8);
        int          prefix = s.route_type == BGPLS_NLRI_IPV4_PREFIX || s.route_type == BGPLS_NLRI_IPV6_PREFIX;
        bgpls_prefix_t p = {.nlri_type = s.route_type,
                            .protocol_id = s.protocol,
                            .identifier = s.identifier,
                            .local_node_descriptors = &local,
                            .remote_node_descriptors = s.remote_len ? &remote : NULL,
                            .link_descriptors = s.route_type == BGPLS_NLRI_LINK ? desc : NULL,
                            .prefix_descriptors = prefix ? desc : NULL,
                            .srv6_sid_descriptors = s.route_type == BGPLS_NLRI_SRV6_SID ? desc : NULL,
                            .sr_policy_descriptors = s.route_type == BGPLS_NLRI_SR_POLICY ? desc : NULL};
        // A step changes values, never the TLVs or their lengths: the first and the last instance are checked,
        // here and when the template is parsed, and the instances between them have the same shape.
        return instance == 0 || instance == base->count - 1 ? bgp_encode_bgpls_prefix(buffer, &p)
                                                            : bgp_encode_bgpls_prefix_unchecked(buffer, &p);
    }
    default:
        return -1;
    }
}

/*
 * A Router-ID or System-ID: dotted IPv4, hex octets, or hex in dotted groups as IS-IS writes it (0000.0000.0001).
 */
static int router_id(const char *text, uint8_t *id, size_t cap) {
    char hex[64];
    size_t n = 0;
    if (!text)
        return -1;
    if (strchr(text, '.') && inet_pton(AF_INET, text, id) == 1)
        return 4;
    for (const char *p = text; *p; p++) {
        if (*p == '.')
            continue;
        if (n + 1 >= sizeof(hex))
            return -1;
        hex[n++] = *p;
    }
    hex[n] = '\0';
    return hex_bytes(hex, id, cap);
}

/*
 * The sub-TLVs of a node descriptor, in TLV order (RFC 9552 section 5.2.1.4, RFC 9086 section 4):
 *   <side>-as <asn> [<side>-bgp-ls-id <n>] [<side>-ospf-area <n|a.b.c.d>] <side>-router <id> [<side>-member-as <asn>]
 *   [<side>-te-router-id <ip>]
 * <side> is local or remote. With protocol bgp or sr the router is the BGP Router-ID (TLV 516), else the IGP
 * Router-ID. The TE Router-ID (TLV 1028 or 1029) names the headend of an SR Policy (RFC 9857 section 3).
 */
static int node_descriptor(tokens_t *tokens, const char *side, uint8_t protocol, uint8_t *out, uint16_t *len) {
    static const struct {
        const char *name;
        uint16_t    type;
    } numbers[] = {{"as", BGPLS_TLV_AS}, {"bgp-ls-id", BGPLS_TLV_BGPLS_ID}, {"ospf-area", BGPLS_TLV_OSPF_AREA},
                   {"router", 0}, {"member-as", BGPLS_TLV_MEMBER_ASN}, {"te-router-id", BGPLS_TLV_IPV4_ROUTER_ID}};
    *len = 0;
    for (size_t i = 0; i < sizeof(numbers) / sizeof(*numbers); i++) {
        char     key[32];
        uint64_t n;
        uint8_t  value[16];
        uint16_t type = numbers[i].type, value_len = 4;
        snprintf(key, sizeof(key), "%s-%s", side, numbers[i].name);
        // The AS number and the router are required; the others are there only when their keyword is next. The
        // headend of an SR Policy needs only its TE Router-ID: a PCE may not know the rest (RFC 9857 section 3.2).
        if ((protocol == BGPLS_PROTO_SR || (i != 0 && i != 3)) && !next_is(tokens, key))
            continue;
        const char *text = field(tokens, key);
        if (!text)
            return -1;
        if (i == 3) {
            int id_len = router_id(text, value, sizeof(value));
            if (id_len <= 0)
                return -1;
            type = protocol == BGPLS_PROTO_BGP || protocol == BGPLS_PROTO_SR ? BGPLS_TLV_BGP_ROUTER_ID
                                                                               : BGPLS_TLV_IGP_ROUTER_ID;
            value_len = (uint16_t)id_len;
        } else if (type == BGPLS_TLV_IPV4_ROUTER_ID) {
            uint8_t af = 0;
            if (address(text, value, &af) < 0)
                return -1;
            type = af == AF_INET ? BGPLS_TLV_IPV4_ROUTER_ID : BGPLS_TLV_IPV6_ROUTER_ID;
            value_len = af == AF_INET ? 4 : 16;
        } else if (type == BGPLS_TLV_OSPF_AREA && strchr(text, '.')) {
            if (inet_pton(AF_INET, text, value) != 1)
                return -1;
        } else {
            if (number(text, UINT32_MAX, &n) < 0)
                return -1;
            put_be(value, n, 4);
        }
        if (put_tlv(out, 64, len, type, value, value_len) < 0)
            return -1;
    }
    return 0;
}

static int ls_protocol(const char *text, uint8_t *protocol) {
    static const char *const names[] = {NULL,     "isis-l1", "isis-l2", "ospfv2", "direct",
                                        "static", "ospfv3",  "bgp",     NULL,     "sr"};
    uint64_t n;
    for (size_t i = 1; text && i < sizeof(names) / sizeof(*names); i++) {
        if (names[i] && !strcmp(text, names[i])) {
            *protocol = (uint8_t)i;
            return 0;
        }
    }
    if (number(text, 255, &n) < 0)
        return -1;
    *protocol = (uint8_t)n;
    return 0;
}

/*
 * An optional Multi-Topology ID descriptor (RFC 9552 section 5.2.2.1): 12 bits in two octets.
 */
static int ls_mt_id(tokens_t *tokens, bgp_ribout_template_t *s) {
    uint64_t n;
    if (!next_is(tokens, "mt-id"))
        return 0;
    if (numeric_field(tokens, "mt-id", 4095, &n) < 0)
        return -1;
    uint8_t value[2] = {(uint8_t)(n >> 8), (uint8_t)n};
    return put_tlv(s->descriptor, sizeof(s->descriptor), &s->descriptor_len, BGPLS_TLV_MT_ID, value, 2);
}

static int parse_ls(tokens_t *tokens, bgp_ribout_template_t *s) {
    const char *type = word(tokens);
    if (!type)
        return -1;
    s->route_type = !strcmp(type, "node")          ? BGPLS_NLRI_NODE
                    : !strcmp(type, "link")        ? BGPLS_NLRI_LINK
                    : !strcmp(type, "ipv4-prefix") ? BGPLS_NLRI_IPV4_PREFIX
                    : !strcmp(type, "ipv6-prefix") ? BGPLS_NLRI_IPV6_PREFIX
                    : !strcmp(type, "srv6-sid")    ? BGPLS_NLRI_SRV6_SID
                    : !strcmp(type, "sr-policy")   ? BGPLS_NLRI_SR_POLICY
                                                   : 0;
    uint64_t n;
    uint8_t *desc = s->descriptor;
    size_t   cap = sizeof(s->descriptor);
    if (!s->route_type || ls_protocol(field(tokens, "protocol"), &s->protocol) < 0)
        return -1;
    if (numeric_field(tokens, "identifier", UINT64_MAX, &s->identifier) < 0 ||
        node_descriptor(tokens, "local", s->protocol, s->local_desc, &s->local_len) < 0)
        return -1;
    if (s->route_type == BGPLS_NLRI_LINK) {
        if (node_descriptor(tokens, "remote", s->protocol, s->remote_desc, &s->remote_len) < 0)
            return -1;
        // Link descriptors in ascending TLV order: the identifier pair or one address pair, then the topology.
        if (next_is(tokens, "local-id")) {
            uint64_t local_id, remote_id;
            if (numeric_field(tokens, "local-id", UINT32_MAX, &local_id) < 0 ||
                numeric_field(tokens, "remote-id", UINT32_MAX, &remote_id) < 0)
                return -1;
            bgpls_tlv_t *ids = bgpls_tlv_create_link_local_remote((uint32_t)local_id, (uint32_t)remote_id);
            if (!ids)
                return -1;
            int rc = put_tlv(desc, cap, &s->descriptor_len, ids->type, ids->value, ids->length);
            bgpls_tlv_list_free(ids);
            if (rc < 0)
                return -1;
        }
        if (next_is(tokens, "local-ip")) {
            uint8_t local[16], remote[16], af = 0;
            if (address(field(tokens, "local-ip"), local, &af) < 0 ||
                address(field(tokens, "remote-ip"), remote, &af) < 0)
                return -1;
            uint16_t first = af == AF_INET ? BGPLS_TLV_IPV4_IFACE_ADDR : BGPLS_TLV_IPV6_IFACE_ADDR;
            uint16_t len = af == AF_INET ? 4 : 16;
            if (put_tlv(desc, cap, &s->descriptor_len, first, local, len) < 0 ||
                put_tlv(desc, cap, &s->descriptor_len, (uint16_t)(first + 1), remote, len) < 0)
                return -1;
        }
        if (!s->descriptor_len || ls_mt_id(tokens, s) < 0)
            return -1;
    } else if (s->route_type == BGPLS_NLRI_IPV4_PREFIX || s->route_type == BGPLS_NLRI_IPV6_PREFIX) {
        uint64_t bits;
        if (ls_mt_id(tokens, s) < 0)
            return -1;
        if (next_is(tokens, "ospf-route-type")) {
            if (numeric_field(tokens, "ospf-route-type", 6, &n) < 0 || !n)
                return -1;
            uint8_t route_type = (uint8_t)n;
            if (put_tlv(desc, cap, &s->descriptor_len, BGPLS_TLV_OSPF_ROUTE_TYPE, &route_type, 1) < 0)
                return -1;
        }
        char *prefix = field(tokens, "prefix");
        char *slash = prefix ? strchr(prefix, '/') : NULL;
        s->af = s->route_type == BGPLS_NLRI_IPV4_PREFIX ? AF_INET : AF_INET6;
        if (!slash || number(slash + 1, s->af == AF_INET ? 32 : 128, &bits) < 0)
            return -1;
        *slash = '\0';
        uint8_t ip[16] = {0}, reach[17];
        if (inet_pton(s->af, prefix, ip) != 1)
            return -1;
        size_t bytes = (bits + 7) / 8;
        reach[0] = (uint8_t)bits;
        memcpy(reach + 1, ip, bytes);
        if (bits % 8)
            reach[bytes] &= (uint8_t)(0xFF << (8 - bits % 8));
        if (put_tlv(desc, cap, &s->descriptor_len, BGPLS_TLV_IP_REACH_INFO, reach, (uint16_t)(1 + bytes)) < 0)
            return -1;
    } else if (s->route_type == BGPLS_NLRI_SRV6_SID) {
        // sid <ipv6>[/<bits>]: a sequence adds at that bit length, as a prefix sequence does (default: the whole SID).
        uint64_t bits = 128;
        uint8_t  sid[16];
        if (ls_mt_id(tokens, s) < 0)
            return -1;
        char *text = field(tokens, "sid");
        char *slash = text ? strchr(text, '/') : NULL;
        if (slash) {
            if (number(slash + 1, 128, &bits) < 0 || !bits || bits % 8)
                return -1;
            *slash = '\0';
        }
        if (!text || inet_pton(AF_INET6, text, sid) != 1 ||
            put_tlv(desc, cap, &s->descriptor_len, BGPLS_TLV_SRV6_SID_INFO, sid, 16) < 0)
            return -1;
        s->step_bits = (uint8_t)bits;
    } else if (s->route_type == BGPLS_NLRI_SR_POLICY) {
        // origin <pcep|bgp|config|n> endpoint <ip> color <n> originator-as <asn> originator <ip> discriminator <n>
        static const char *const origins[] = {NULL, "pcep", "bgp", "config"};
        uint8_t     value[48] = {0}, endpoint_af = 0, originator_af = 0;
        uint16_t    at = 4;
        uint64_t    origin = 0, color, asn, discriminator;
        const char *text = field(tokens, "origin");
        for (size_t i = 1; text && i < sizeof(origins) / sizeof(*origins); i++)
            origin = !strcmp(text, origins[i]) ? i : origin;
        if (!origin && number(text, 255, &origin) < 0)
            return -1;
        value[0] = (uint8_t)origin;
        if (address(field(tokens, "endpoint"), value + at, &endpoint_af) < 0)
            return -1;
        at = (uint16_t)(at + (endpoint_af == AF_INET6 ? 16 : 4));
        if (numeric_field(tokens, "color", UINT32_MAX, &color) < 0 ||
            numeric_field(tokens, "originator-as", UINT32_MAX, &asn) < 0)
            return -1;
        put_be(value + at, color, 4);
        put_be(value + at + 4, asn, 4);
        at = (uint16_t)(at + 8);
        if (address(field(tokens, "originator"), value + at, &originator_af) < 0)
            return -1;
        at = (uint16_t)(at + (originator_af == AF_INET6 ? 16 : 4));
        if (numeric_field(tokens, "discriminator", UINT32_MAX, &discriminator) < 0)
            return -1;
        put_be(value + at, discriminator, 4);
        // The E and O flags say which addresses are IPv6.
        value[1] = (uint8_t)((endpoint_af == AF_INET6 ? 0x80 : 0) | (originator_af == AF_INET6 ? 0x40 : 0));
        if (put_tlv(desc, cap, &s->descriptor_len, BGPLS_TLV_SR_POLICY_CP, value, (uint16_t)(at + 4)) < 0)
            return -1;
    }
    s->step = STEP_ID;
    return 0;
}

/*
 * The axis a field name stands for in `step <field>` and `per <field>`; 0 for a name that is not one.
 */
static uint8_t step_by_name(const char *name) {
    static const struct {
        const char *name;
        uint8_t     step;
    } steps[] = {{"rd", STEP_RD}, {"target", STEP_TARGET}, {"ve-id", STEP_VE}, {"router", STEP_ROUTER}, {"source", STEP_SOURCE}, {"group", STEP_GROUP}, {"ethernet-tag", STEP_TAG}, {"identifier", STEP_ID}, {"esi", STEP_ESI}, {"node", STEP_NODE}, {"link", STEP_LINK}, {"prefix", STEP_PREFIX}, {"sid", STEP_SID}, {"remote", STEP_REMOTE}, {"color", STEP_COLOR}, {"endpoint", STEP_ENDPOINT}, {"discriminator", STEP_DISCRIMINATOR}};
    for (size_t i = 0; name && i < sizeof(steps) / sizeof(*steps); i++)
        if (!strcmp(name, steps[i].name))
            return steps[i].step;
    return 0;
}

static int parse_nlri(bgp_ribout_config_t *block, const char *line) {
    if (strlen(line) >= sizeof(block->nlri_template.text))
        return -1;
    char text[1024];
    snprintf(text, sizeof(text), "%s", line);
    tokens_t tokens = {.next = text};
    char    *family = field(&tokens, "nlri");
    if (!family)
        return -1;
    bgp_ribout_template_t s = {.count = 1};
    uint64_t              n;
    if (!strcmp(family, "rtc")) {
        s.family = BGP_RIBOUT_FAMILY_RTC;
        char *first = word(&tokens);
        if (first && !strcmp(first, "default")) {
            s.is_default = 1;
        } else {
            if (!first || strcmp(first, "origin-as") || number(word(&tokens), UINT32_MAX, &n) < 0)
                return -1;
            s.origin_as = (uint32_t)n;
            bgp_ext_comm_t target;
            const char    *target_text = field(&tokens, "target");
            if (!target_text || bgp_ribout_parse_ext_comm_value(target_text, 2, &target) < 0)
                return -1;
            memcpy(s.target, target.bytes, 8);
            s.step = STEP_TARGET;
        }
    } else if (!strcmp(family, "bgp-ls")) {
        s.family = BGP_RIBOUT_FAMILY_BGP_LS;
        if (parse_ls(&tokens, &s) < 0)
            return -1;
    } else {
        int vpls = !strcmp(family, "vpls");
        int evpn = !strcmp(family, "evpn");
        int mvpn = !strcmp(family, "mvpn4") || !strcmp(family, "mvpn6");
        if (!vpls && !evpn && !mvpn)
            return -1;
        if (vpls) {
            s.family = BGP_RIBOUT_FAMILY_VPLS;
        } else {
            const char *type = word(&tokens);
            if (!type || strncmp(type, "type", 4) || number(type + 4, 7, &n) < 0 || n == 0)
                return -1;
            s.route_type = (uint8_t)n;
            if (evpn) {
                s.family = n == 1   ? BGP_RIBOUT_FAMILY_EVPN_TYPE1
                           : n == 3 ? BGP_RIBOUT_FAMILY_EVPN_TYPE3
                           : n == 4 ? BGP_RIBOUT_FAMILY_EVPN_TYPE4
                                    : 0;
                if (!s.family)
                    return -1;
            } else {
                s.af = !strcmp(family, "mvpn4") ? AF_INET : AF_INET6;
                s.family = s.af == AF_INET ? BGP_RIBOUT_FAMILY_MVPN_IPV4 : BGP_RIBOUT_FAMILY_MVPN_IPV6;
            }
        }
        if (mvpn && s.route_type == 4) {
            int len = hex_bytes(field(&tokens, "route-key"), s.route_key, sizeof(s.route_key));
            if (len < 2 || s.route_key[1] + 2 != len || (s.route_key[0] != 2 && s.route_key[0] != 3))
                return -1;
            s.route_key_len = (uint8_t)len;
            if (address(field(&tokens, "router"), s.router, &s.af) < 0)
                return -1;
            s.step = STEP_ROUTER;
        } else {
            const char *rd = field(&tokens, "rd");
            if (!rd || bgp_ribout_parse_rd_value(rd, &s.rd) < 0)
                return -1;
            s.step = STEP_RD;
            if (vpls) {
                if (numeric_field(&tokens, "ve-id", UINT16_MAX, &n) < 0)
                    return -1;
                s.ve_id = (uint16_t)n;
                if (numeric_field(&tokens, "offset", UINT16_MAX, &n) < 0)
                    return -1;
                s.offset = (uint16_t)n;
                if (numeric_field(&tokens, "size", UINT16_MAX, &n) < 0 || !n)
                    return -1;
                s.size = (uint16_t)n;
                if (numeric_field(&tokens, "label-base", 0xFFFFF, &n) < 0)
                    return -1;
                s.label = (uint32_t)n;
                if (s.label + s.size - 1 > 0xFFFFF || (uint32_t)s.offset + s.size > 65536)
                    return -1;
                s.step = STEP_VE;
            } else if (evpn) {
                if (s.route_type != 3) {
                    const char *esi = field(&tokens, "esi");
                    if (!esi || bgp_ribout_parse_esi_value(esi, &s.esi) < 0)
                        return -1;
                }
                if (s.route_type != 4) {
                    // "max" is MAX-ET (RFC 7432 section 3), the tag of an Ethernet A-D per ES route.
                    const char *tag = field(&tokens, "ethernet-tag");
                    if (tag && !strcmp(tag, "max"))
                        n = UINT32_MAX;
                    else if (number(tag, UINT32_MAX, &n) < 0)
                        return -1;
                    s.tag = (uint32_t)n;
                }
                if (s.route_type == 1) {
                    // Up to a 24-bit VNI here; generation rejects a value above 20 bits without a VNI encap.
                    if (numeric_field(&tokens, "label", 0xFFFFFF, &n) < 0)
                        return -1;
                    s.label = (uint32_t)n;
                } else {
                    if (address(field(&tokens, "router"), s.router, &s.af) < 0)
                        return -1;
                    s.step = STEP_ROUTER;
                }
            } else {
                if (s.route_type == 2 || s.route_type >= 6) {
                    if (numeric_field(&tokens, "source-as", UINT32_MAX, &n) < 0)
                        return -1;
                    s.source_as = (uint32_t)n;
                }
                if (s.route_type >= 3) {
                    if (address(field(&tokens, "source"), s.source, &s.af) < 0 ||
                        address(field(&tokens, "group"), s.group, &s.af) < 0)
                        return -1;
                    if ((s.af == AF_INET && (s.group[0] & 0xF0) != 0xE0) || (s.af == AF_INET6 && s.group[0] != 0xFF))
                        return -1;
                }
                if (s.route_type == 1 || s.route_type == 3) {
                    if (address(field(&tokens, "router"), s.router, &s.af) < 0)
                        return -1;
                }
            }
        }
    }
    const char *option = word(&tokens);
    for (int axis = 0; option && axis < BGP_RIBOUT_STEP_AXES; axis++) {
        if (!strcmp(option, "step")) {
            const char *name = word(&tokens);
            if (!name)
                return -1;
            uint8_t step = step_by_name(name);
            int ls = s.family == BGP_RIBOUT_FAMILY_BGP_LS;
            int prefix = s.route_type == BGPLS_NLRI_IPV4_PREFIX || s.route_type == BGPLS_NLRI_IPV6_PREFIX;
            int allowed =
                (!ls && step == s.step) || (ls && (step == STEP_ID || step == STEP_NODE)) ||
                (ls && (step == STEP_LINK || step == STEP_REMOTE) && s.route_type == BGPLS_NLRI_LINK) ||
                (ls && step == STEP_PREFIX && prefix) ||
                (ls && step >= STEP_COLOR && s.route_type == BGPLS_NLRI_SR_POLICY) ||
                (ls && step == STEP_SID && s.route_type == BGPLS_NLRI_SRV6_SID) ||
                (step == STEP_RD && s.family != BGP_RIBOUT_FAMILY_RTC && !ls &&
                 !(s.route_type == 4 &&
                   (s.family == BGP_RIBOUT_FAMILY_MVPN_IPV4 || s.family == BGP_RIBOUT_FAMILY_MVPN_IPV6))) ||
                (step == STEP_TAG &&
                 (s.family == BGP_RIBOUT_FAMILY_EVPN_TYPE1 || s.family == BGP_RIBOUT_FAMILY_EVPN_TYPE3)) ||
                (step == STEP_ESI &&
                 (s.family == BGP_RIBOUT_FAMILY_EVPN_TYPE1 || s.family == BGP_RIBOUT_FAMILY_EVPN_TYPE4)) ||
                ((step == STEP_SOURCE || step == STEP_GROUP) &&
                 (s.family == BGP_RIBOUT_FAMILY_MVPN_IPV4 || s.family == BGP_RIBOUT_FAMILY_MVPN_IPV6) &&
                 s.route_type >= 3 && s.route_type != 4);
            // More axes are for BGP-LS only, and each names a different field.
            if (!step || !allowed || s.is_default ||
                (axis && (!ls || step == s.step || (axis == 2 && step == s.more_steps[0]))))
                return -1;
            if (axis)
                s.more_steps[axis - 1] = step;
            else
                s.step = step;
            option = word(&tokens);
        } else if (axis) {
            return -1;
        }
        if (option && !strcmp(option, "x")) {
            if (number(word(&tokens), UINT32_MAX, &n) < 0 || !n || n > UINT32_MAX / s.count)
                return -1;
            if (axis)
                s.more_counts[axis - 1] = (uint32_t)n;
            s.count *= (uint32_t)n;
            option = word(&tokens);
        } else if (axis) {
            return -1;
        }
    }
    if (option)
        return -1;
    uint8_t encoded[1024];
    int vni = s.label > 0xFFFFF;
    ls_step_cache(&s);
    if (bgp_ribout_template_encode(&s, 0, vni, encoded) < 0 ||
        bgp_ribout_template_encode(&s, s.count - 1, vni, encoded) < 0)
        return -1;
    snprintf(s.text, sizeof(s.text), "%s", line);
    block->nlri_template = s;
    return 0;
}

/*
 * A rejected template line names its expected form: the parser above returns at the first field that does not fit.
 */
int bgp_ribout_parse_nlri(bgp_ribout_config_t *block, const char *line) {
    if (parse_nlri(block, line) == 0)
        return 0;
    fprintf(stderr, "Error: Invalid nlri template: expected nlri <family> <typed fields in order> [step <field>] "
                    "[x <count>], with every value in range\n");
    return -1;
}

// BGP-LS Attribute lines

typedef struct {
    uint8_t              bytes[BGP_RIBOUT_LS_VALUE_MAX];
    uint16_t             len;
    uint8_t              set;
    // The sequences of the TLVs nested in this field, with offsets from the start of the field.
    uint8_t              step_count;
    bgp_ribout_ls_step_t steps[BGP_RIBOUT_LS_STEPS];
} ls_field_t;

/*
 * What a line records beside its value: the sequence field and what depends on the Protocol-ID of the NLRI.
 */
typedef struct {
    uint16_t             flags_off;
    uint8_t              sid_len;      /* Octets of an SRv6 SID that its sequence adds to                             */
    uint8_t              neighbor_len, metric_width;
    uint8_t              step_count;   /* Sequences, with offsets from the start of the TLV value                     */
    bgp_ribout_ls_step_t steps[BGP_RIBOUT_LS_STEPS];
    uint8_t              flags_named;  /* Flag names with two layouts: bit 0 named, bit 1 IS-IS valid, bit 2 OSPF valid */
    uint8_t              flags_ospf;   /* The OSPF value of those flags                                               */
    uint8_t              sid_label;    /* The sequence field is a 20-bit label                                        */
} ls_line_t;

static const struct {
    const char *name;
    uint16_t    value;
} srv6_behaviors[] = {  // RFC 8986 section 10.2
    {"end", 1},      {"end.x", 5},    {"end.t", 9},     {"end.b6.encaps", 14}, {"end.dx6", 16},  {"end.dx4", 17},
    {"end.dt6", 18}, {"end.dt4", 19}, {"end.dt46", 20}, {"end.dx2", 21},       {"end.dx2v", 22}, {"end.dt2u", 23},
    {"end.dt2m", 24},
};

/*
 * A bandwidth in bits per second, with an optional k, m or g (powers of 1000), as the IEEE float of octets per second
 * that RFC 9552 section 5.3.2 and the Link Bandwidth extended community carry.
 */
static int bandwidth(const char *text, uint8_t *out) {
    char  *end;
    double bits;
    if (!text || !isdigit((unsigned char)*text))
        return -1;
    errno = 0;
    bits = strtod(text, &end);
    if (errno || bits < 0)
        return -1;
    if (*end == 'k' || *end == 'm' || *end == 'g') {
        bits *= *end == 'k' ? 1e3 : *end == 'm' ? 1e6 : 1e9;
        end++;
    }
    if (*end)
        return -1;
    float    octets = (float)(bits / 8);
    uint32_t wire;
    memcpy(&wire, &octets, sizeof(wire));
    put_be(out, wire, 4);
    return 0;
}

/*
 * Flags as a number, or as names from the layout of the TLV: "v,l". With two layouts the IS-IS value goes to *value
 * and the OSPF one to *ospf; valid gets bit 1 (IS-IS) and bit 2 (OSPF) for the layouts that have every name.
 */
static int ls_flags(const bgpls_attr_def_t *def, const char *text, unsigned bits, uint64_t *value, uint64_t *ospf,
                    uint8_t *valid) {
    if (!text)
        return -1;
    *valid = 0;
    if (number_any(text, bits == 8 ? 0xFF : 0xFFFF, value) == 0) {
        *ospf = *value;
        return 0;
    }
    uint64_t out[2] = {0, 0};
    for (int layout = 0; layout < 2; layout++) {
        const char *names = def->flag_names[layout] ? def->flag_names[layout] : def->flag_names[0];
        int         ok = names != NULL;
        for (const char *name = text; ok && *name;) {
            size_t      len = strcspn(name, ",");
            unsigned    bit = 0;
            const char *known = names;
            for (;; bit++) {
                size_t known_len = strcspn(known, ",");
                if (known_len == len && !strncmp(known, name, len) && strncmp(name, "-", len))
                    break;
                if (!known[known_len]) {
                    ok = 0;
                    break;
                }
                known += known_len + 1;
            }
            if (ok && bit < bits)
                out[layout] |= 1ULL << (bits - 1 - bit);
            if (!len || (name[len] && !name[len + 1]))
                ok = 0;
            name += len + (name[len] ? 1 : 0);
        }
        if (ok)
            *valid |= (uint8_t)(2 << layout);
    }
    if (!*valid)
        return -1;
    *valid |= (uint8_t)(def->flag_names[1] ? 1 : 0);
    *value = *valid & 2 ? out[0] : out[1];
    *ospf = *valid & 4 ? out[1] : out[0];
    if (!def->flag_names[1] && !(*valid & 2))
        return -1;
    return 0;
}

static const char *ls_tlv(tokens_t *tokens, const bgpls_attr_def_t *def, int nested, uint16_t *type, uint8_t *value,
                          uint16_t *value_len, ls_line_t *line);

/*
 * One field from the words at the cursor. Lists and nested TLVs take every word up to the next keyword.
 */
static const char *ls_field(tokens_t *tokens, const bgpls_attr_def_t *def, const bgpls_field_def_t *field,
                            ls_field_t *f, ls_line_t *line) {
    uint64_t n = 0, ospf = 0;
    uint8_t  af = 0, valid = 0;
    size_t   unit = field->kind == BGPLS_FIELD_U8_LIST ? 1 : field->kind == BGPLS_FIELD_U16_LIST ? 2
                    : field->kind == BGPLS_FIELD_U24_LIST ? 3
                    : field->kind == BGPLS_FIELD_U32_LIST || field->kind == BGPLS_FIELD_IPV4_LIST ? 4 : 8;
    // A nested TLV has a 2-octet type and length in the BGP-LS Attribute, and a 1-octet type in a path attribute.
    size_t   header = field->kind == BGPLS_FIELD_EMBED8 ? 3 : 4;
    char    *text;
    switch (field->kind) {
    case BGPLS_FIELD_U8_LIST:
    case BGPLS_FIELD_U16_LIST:
    case BGPLS_FIELD_U24_LIST:
    case BGPLS_FIELD_U32_LIST:
    case BGPLS_FIELD_U64_LIST:
    case BGPLS_FIELD_IPV4_LIST:
        while (*tokens->next && !next_is(tokens, "x") && !next_is(tokens, "per") && !next_is(tokens, "sub")) {
            char *item = word(tokens);
            if (f->len + unit > sizeof(f->bytes))
                return "the list is too long";
            // An IPv4 list takes dotted addresses, or plain 32-bit numbers.
            if (field->kind == BGPLS_FIELD_IPV4_LIST && item && strchr(item, '.')) {
                if (inet_pton(AF_INET, item, f->bytes + f->len) != 1)
                    return "a list value is not an IPv4 address";
                f->len = (uint16_t)(f->len + 4);
                while (*tokens->next && isspace((unsigned char)*tokens->next))
                    tokens->next++;
                continue;
            }
            if (number_any(item, unit == 8 ? UINT64_MAX : (1ULL << (8 * unit)) - 1, &n) < 0)
                return "a list value is not a number in range, or the list is too long";
            put_be(f->bytes + f->len, n, unit);
            f->len = (uint16_t)(f->len + unit);
            while (*tokens->next && isspace((unsigned char)*tokens->next))
                tokens->next++;
        }
        return f->len ? NULL : "the list is empty";
    case BGPLS_FIELD_SUB_TLVS:
    case BGPLS_FIELD_EMBED8: {
        // The word after `sub` names a TLV of the same table; its fields run to the next `sub`. An embedded TLV
        // has no keyword: the rest of the line is its fields, and the field key names its row.
        const bgpls_attr_def_t *sub = header == 3 ? bgp_path_attr_def_find(NULL, field->key)
                                                  : bgpls_attr_def_find(word(tokens));
        uint16_t                type, len;
        uint8_t                 bytes[BGP_RIBOUT_LS_VALUE_MAX];
        ls_line_t               ignored = {0};
        if (!sub)
            return "unknown TLV name after sub";
        const char *error = ls_tlv(tokens, sub, 1, &type, bytes, &len, &ignored);
        if (error)
            return error;
        if (ignored.flags_named & 1)
            return "a nested TLV with protocol-specific flags takes them as a number";
        // The sequences of the nested TLV now start after its header, inside this field.
        for (uint8_t i = 0; i < ignored.step_count; i++) {
            if (f->step_count >= BGP_RIBOUT_LS_STEPS)
                return "too many sequences on one line";
            f->steps[f->step_count] = ignored.steps[i];
            f->steps[f->step_count++].off = (uint16_t)(f->len + header + ignored.steps[i].off);
        }
        if (header == 4)
            return put_tlv(f->bytes, sizeof(f->bytes), &f->len, type, bytes, len) < 0 ? "the nested TLVs are too long"
                                                                                       : NULL;
        if (type > 255 || f->len + 3U + len > sizeof(f->bytes))
            return "the nested TLVs are too long";
        f->bytes[f->len] = (uint8_t)type;
        put_be(f->bytes + f->len + 1, len, 2);
        memcpy(f->bytes + f->len + 3, bytes, len);
        f->len = (uint16_t)(f->len + 3 + len);
        return NULL;
    }
    case BGPLS_FIELD_RANGES: {
        uint64_t first, size;
        // RFC 9085 section 2.1.2: a 3-octet size, then a SID/Label sub-TLV with the first label.
        if (number(word(tokens), 0xFFFFF, &first) < 0 || number(word(tokens), 0xFFFFFF, &size) < 0 || !size ||
            first + size - 1 > 0xFFFFF || f->len + 10U > sizeof(f->bytes))
            return "range takes <first-label> <size>, within the 20-bit label space";
        put_be(f->bytes + f->len, size, 3);
        put_be(f->bytes + f->len + 3, BGPLS_TLV_SID_LABEL, 2);
        put_be(f->bytes + f->len + 5, 3, 2);
        put_be(f->bytes + f->len + 7, first, 3);
        f->len = (uint16_t)(f->len + 10);
        return NULL;
    }
    case BGPLS_FIELD_SID_STRUCTURE6:
        // RFC 9252 section 3.2.1: sub-sub-TLV type 1, length 6: locator block, locator node, function and
        // argument lengths, then the transposition length and offset (0 unless `transposition` gives them).
        f->bytes[0] = 1;
        put_be(f->bytes + 1, 6, 2);
        memset(f->bytes + 3, 0, 6);
        for (int i = 0; i < 6; i++) {
            if (i == 4 && !next_is(tokens, "transposition"))
                break;
            if (i == 4)
                word(tokens);
            if (number(word(tokens), 128, &n) < 0)
                return "structure takes four lengths: locator block, locator node, function, argument; then "
                       "transposition <length> <offset>";
            f->bytes[3 + i] = (uint8_t)n;
        }
        if (f->bytes[3] + f->bytes[4] + f->bytes[5] + f->bytes[6] > 128)
            return "the structure lengths exceed 128 bits";
        f->len = 9;
        return NULL;
    case BGPLS_FIELD_STRUCTURE:
        put_be(f->bytes, BGPLS_TLV_SRV6_SID_STRUCTURE, 2);
        put_be(f->bytes + 2, 4, 2);
        for (int i = 0; i < 4; i++) {
            if (number(word(tokens), 128, &n) < 0)
                return "structure takes four lengths: locator block, locator node, function, argument";
            f->bytes[4 + i] = (uint8_t)n;
        }
        if (f->bytes[4] + f->bytes[5] + f->bytes[6] + f->bytes[7] > 128)
            return "the structure lengths exceed 128 bits";
        f->len = 8;
        return NULL;
    default:
        break;
    }
    text = word(tokens);
    if (!text)
        return "a value is missing";
    switch (field->kind) {
    case BGPLS_FIELD_U8:
    case BGPLS_FIELD_U16:
    case BGPLS_FIELD_U24:
    case BGPLS_FIELD_U32:
    case BGPLS_FIELD_U64:
    case BGPLS_FIELD_METRIC:
        f->len = field->kind == BGPLS_FIELD_U8 ? 1 : field->kind == BGPLS_FIELD_U16 ? 2
                 : field->kind == BGPLS_FIELD_U24 ? 3 : field->kind == BGPLS_FIELD_U64 ? 8 : 4;
        if (number_any(text, f->len == 8 ? UINT64_MAX : (1ULL << (8 * f->len)) - 1, &n) < 0)
            return "a value is not a number, or is out of range (positional values come before keywords)";
        put_be(f->bytes, n, f->len);
        return NULL;
    case BGPLS_FIELD_FLAGS8:
    case BGPLS_FIELD_FLAGS16:
        f->len = field->kind == BGPLS_FIELD_FLAGS8 ? 1 : 2;
        if (ls_flags(def, text, 8U * f->len, &n, &ospf, &valid) < 0)
            return "flags take a number or the flag names of this TLV, comma separated";
        put_be(f->bytes, n, f->len);
        line->flags_named = valid;
        line->flags_ospf = (uint8_t)ospf;
        return NULL;
    case BGPLS_FIELD_MPLS:
        // RFC 9857 section 5.1: a label stack entry with the label in its 20 leftmost bits.
        if (number(text, 0xFFFFF, &n) < 0)
            return "a label is 0-1048575";
        f->len = 4;
        put_be(f->bytes, n << 12, 4);
        return NULL;
    case BGPLS_FIELD_BANDWIDTH:
        f->len = 4;
        return bandwidth(text, f->bytes) < 0 ? "a bandwidth is bits per second, with an optional k, m or g" : NULL;
    case BGPLS_FIELD_IPV4:
    case BGPLS_FIELD_IPV6:
    case BGPLS_FIELD_IP:
        af = field->kind == BGPLS_FIELD_IPV4 ? AF_INET : field->kind == BGPLS_FIELD_IPV6 ? AF_INET6 : 0;
        if (address(text, f->bytes, &af) < 0)
            return "an address is not valid for this TLV";
        f->len = af == AF_INET ? 4 : 16;
        return NULL;
    case BGPLS_FIELD_TEXT:
        if (strlen(text) > sizeof(f->bytes))
            return "the text is too long";
        f->len = (uint16_t)strlen(text);
        memcpy(f->bytes, text, f->len);
        return NULL;
    case BGPLS_FIELD_HEX: {
        int len = hex_bytes(text, f->bytes, sizeof(f->bytes));
        if (len < 0)
            return "the value is not an even number of hex digits, or is too long";
        f->len = (uint16_t)len;
        return NULL;
    }
    case BGPLS_FIELD_NEIGHBOR: {
        int len = router_id(text, f->bytes, sizeof(f->bytes));
        if (len != 4 && len != 6)
            return "neighbor is an IS-IS System-ID (6 octets) or an OSPF Router-ID (4 octets)";
        f->len = (uint16_t)len;
        line->neighbor_len = (uint8_t)len;
        return NULL;
    }
    case BGPLS_FIELD_BEHAVIOR:
        f->len = 2;
        for (size_t i = 0; i < sizeof(srv6_behaviors) / sizeof(*srv6_behaviors); i++)
            if (!strcmp(text, srv6_behaviors[i].name))
                n = srv6_behaviors[i].value;
        if (!n && number_any(text, 0xFFFF, &n) < 0)
            return "behavior is a number or a name such as end, end.x or end.dt4";
        put_be(f->bytes, n, 2);
        return NULL;
    case BGPLS_FIELD_SRV6_SID: {
        // <ipv6>[/<bits>]: an `x <count>` sequence adds at that bit length.
        char    *slash = strchr(text, '/');
        uint64_t bits = 128;
        if (slash) {
            if (number(slash + 1, 128, &bits) < 0 || !bits || bits % 8)
                return "the SID bit length is a multiple of 8, from 8 to 128";
            *slash = '\0';
        }
        if (inet_pton(AF_INET6, text, f->bytes) != 1)
            return "the SID is not an IPv6 address";
        f->len = 16;
        line->sid_len = (uint8_t)(bits / 8);
        return NULL;
    }
    default:
        return "unexpected value";
    }
}

/*
 * Whether a sequence can add n to its field: the number fits the octets, and a label or a small metric its bits.
 */
static int ls_step_fits(const uint8_t *value, const bgp_ribout_ls_step_t *step, uint32_t n) {
    uint8_t last[16];
    if (step->len > sizeof(last))
        return 0;
    memcpy(last, value + step->off, step->len);
    return bytes_be_add(last, step->len, n, step->shift) == 0 && !(step->bound == 1 && last[0] > 0x0F) &&
           !(step->bound == 2 && last[0] > 63);
}

/*
 * The value of one TLV from the words at the cursor: positional fields first, then keyword fields in any order. A
 * nested TLV ends at the next `sub`; a top-level one may end with `x <count>`, which the caller reads.
 */
static const char *ls_tlv(tokens_t *tokens, const bgpls_attr_def_t *def, int nested, uint16_t *type, uint8_t *value,
                          uint16_t *value_len, ls_line_t *line) {
    ls_field_t           fields[8];
    uint64_t             n;
    uint8_t              width = 3;
    int                  sid = -1, ranges = -1, metric = -1, own_sid = 0, embed = -1;
    bgp_ribout_ls_step_t own = {0};  /* The field of this TLV that a sequence adds to */
    memset(fields, 0, sizeof(fields));
    for (int i = 0; i < 8 && def->fields[i].kind; i++) {
        const bgpls_field_def_t *field = &def->fields[i];
        sid = field->kind == BGPLS_FIELD_SID ? i : sid;
        ranges = field->kind == BGPLS_FIELD_RANGES ? i : ranges;
        metric = field->kind == BGPLS_FIELD_METRIC ? i : metric;
        embed = field->kind == BGPLS_FIELD_EMBED8 ? i : embed;
        if (field->key || field->kind == BGPLS_FIELD_ZERO8 || field->kind == BGPLS_FIELD_ZERO16 ||
            field->kind == BGPLS_FIELD_SID || field->kind == BGPLS_FIELD_RANGES || field->kind == BGPLS_FIELD_CONST8)
            continue;
        const char *error = ls_field(tokens, def, field, &fields[i], line);
        if (error)
            return error;
        fields[i].set = 1;
    }
    // An embedded TLV takes the rest of the line, with its own sequences.
    if (embed >= 0) {
        const char *error = ls_field(tokens, def, &def->fields[embed], &fields[embed], line);
        if (error)
            return error;
        fields[embed].set = 1;
    }
    while (*tokens->next && !next_is(tokens, "x") && !next_is(tokens, "per") && !(nested && next_is(tokens, "sub"))) {
        const char *key = word(tokens);
        int         found = -1;
        if (!key)
            break;
        if (sid >= 0 && (!strcmp(key, "label") || !strcmp(key, "index"))) {
            // RFC 9085 section 2.1.1: a label is the 20 rightmost bits of 3 octets; an index is 4 octets.
            int label = !strcmp(key, "label");
            if (fields[sid].set || number(word(tokens), label ? 0xFFFFF : UINT32_MAX, &n) < 0)
                return "a SID is label <0-1048575> or index <0-4294967295>, once";
            fields[sid].len = label ? 3 : 4;
            put_be(fields[sid].bytes, n, fields[sid].len);
            fields[sid].set = 1;
            line->sid_label = (uint8_t)label;
            continue;
        }
        if (metric >= 0 && !strcmp(key, "width")) {
            if (number(word(tokens), 3, &n) < 0 || !n)
                return "width is 1, 2 or 3 octets";
            width = (uint8_t)n;
            continue;
        }
        for (int i = 0; i < 8 && def->fields[i].kind; i++)
            if ((def->fields[i].key && !strcmp(def->fields[i].key, key)) || (i == ranges && !strcmp(key, "range")))
                found = i;
        if (found < 0)
            return "unknown field for this TLV";
        if (fields[found].set && found != ranges && def->fields[found].kind != BGPLS_FIELD_SUB_TLVS)
            return "a field is given twice";
        const char *error = ls_field(tokens, def, &def->fields[found], &fields[found], line);
        if (error)
            return error;
        fields[found].set = 1;
    }
    *value_len = 0;
    for (int i = 0; i < 8 && def->fields[i].kind; i++) {
        const bgpls_field_def_t *field = &def->fields[i];
        ls_field_t              *f = &fields[i];
        if (field->kind == BGPLS_FIELD_CONST8) {
            f->bytes[0] = (uint8_t)(field->flags >> 8);
            f->len = 1;
        } else if (!f->set) {
            if (field->flags & BGPLS_FIELD_REQUIRED)
                return "a required field is missing";
            // An absent optional field is zero at its fixed width; variable ones are simply absent.
            f->len = field->kind == BGPLS_FIELD_U8 || field->kind == BGPLS_FIELD_ZERO8 ||
                             field->kind == BGPLS_FIELD_FLAGS8 ? 1
                     : field->kind == BGPLS_FIELD_U16 || field->kind == BGPLS_FIELD_ZERO16 ||
                               field->kind == BGPLS_FIELD_FLAGS16 ? 2
                     : field->kind == BGPLS_FIELD_U24 ? 3
                     : field->kind == BGPLS_FIELD_U32 || field->kind == BGPLS_FIELD_IPV4 ||
                               field->kind == BGPLS_FIELD_MPLS ? 4 : 0;
        }
        if (field->kind == BGPLS_FIELD_METRIC) {
            // RFC 9552 section 5.3.2.4: 1 octet (IS-IS small, 6 bits), 2 (OSPF) or 3 (IS-IS wide).
            uint64_t metric_value = ((uint64_t)f->bytes[0] << 24) | (f->bytes[1] << 16) | (f->bytes[2] << 8) | f->bytes[3];
            if (metric_value > (width == 1 ? 63U : width == 2 ? 0xFFFFU : 0xFFFFFFU))
                return "the metric does not fit its width";
            put_be(f->bytes, metric_value, width);
            f->len = width;
            line->metric_width = width;
        }
        if ((size_t)*value_len + f->len > BGP_RIBOUT_LS_VALUE_MAX)
            return "the TLV value is longer than 255 octets";
        if (field->flags & BGPLS_FIELD_STEP) {
            own.off = *value_len;
            own_sid = field->kind == BGPLS_FIELD_SRV6_SID;
            own.len = own_sid ? line->sid_len : (uint8_t)f->len;
            // A label stack entry has its label in the 20 leftmost bits: the sequence is over the first three
            // octets, four bits up.
            if (field->kind == BGPLS_FIELD_MPLS) {
                own.len = 3;
                own.shift = 4;
            }
            // The last value of a sequence must fit: 20 bits for a label, 6 for a 1-octet metric.
            own.bound = line->sid_label ? 1 : line->metric_width == 1 ? 2 : 0;
        }
        for (uint8_t k = 0; k < f->step_count; k++) {
            if (line->step_count >= BGP_RIBOUT_LS_STEPS)
                return "too many sequences on one line";
            line->steps[line->step_count] = f->steps[k];
            line->steps[line->step_count++].off = (uint16_t)(*value_len + f->steps[k].off);
        }
        if (field->kind == BGPLS_FIELD_FLAGS8 && (line->flags_named & 1))
            line->flags_off = *value_len;
        memcpy(value + *value_len, f->bytes, f->len);
        *value_len = (uint16_t)(*value_len + f->len);
    }
    *type = def->type;
    if (!def->type && !(def->nlri_mask & BGP_ON_PATH_ATTR)) {  // raw: the first field is the code point
        *type = (uint16_t)((value[0] << 8) | value[1]);
        *value_len = (uint16_t)(*value_len - 2);
        memmove(value, value + 2, *value_len);
        own.len = 0;
    }
    if ((def->type == 266 || def->type == 267) && *value_len % 2)
        return "an MSD list is pairs of type and value";
    if (def->type == 1107 && line->neighbor_len != 6)
        return "the IS-IS neighbor is a 6-octet System-ID";
    if (def->type == 1108 && line->neighbor_len != 4)
        return "the OSPFv3 neighbor is a 4-octet Router-ID";
    // Sequences of this TLV: they follow its fields, so in a nested TLV they come before the next `sub`.
    while (next_is(tokens, "x") || next_is(tokens, "per")) {
        bgp_ribout_ls_step_t step = own;
        int                  per = next_is(tokens, "per");
        word(tokens);
        char *text = word(tokens);
        if (!own.len)
            return "this TLV has no field that x <count> or per <axis> can make a sequence of";
        if (line->step_count >= BGP_RIBOUT_LS_STEPS)
            return "too many sequences on one line";
        if (per) {
            // per <axis>[/<bits>]: for an SRv6 SID, the bit length this axis adds at.
            char *slash = text ? strchr(text, '/') : NULL;
            if (slash) {
                if (!own_sid || number(slash + 1, 128, &n) < 0 || !n || n % 8)
                    return "per <axis>/<bits> is for an SRv6 SID; bits is a multiple of 8, from 8 to 128";
                *slash = '\0';
                step.len = (uint8_t)(n / 8);
            }
            step.axis = step_by_name(text);
            if (!step.axis)
                return "per takes a step field of the nlri template, for example node, link, prefix or router";
        } else {
            if (number(text, UINT32_MAX, &n) < 0 || !n)
                return "x takes a count from 1";
            if (!ls_step_fits(value, &step, (uint32_t)(n - 1)))
                return "the sequence runs past the end of its field";
            step.count = (uint32_t)n;
        }
        line->steps[line->step_count++] = step;
    }
    return NULL;
}

static const char *parse_ls_attr(bgp_ribout_config_t *b, const char *line) {
    char text[BGPSIM_COMMAND_SIZE + 64];
    if (strlen(line) >= sizeof(text))
        return "the line is too long";
    snprintf(text, sizeof(text), "%s", line);
    tokens_t                tokens = {.next = text};
    const char             *keyword = word(&tokens);
    int                     alias = keyword && !strcmp(keyword, "ls-attribute");
    const bgpls_attr_def_t *def = bgpls_attr_def_find(alias ? "raw" : word(&tokens));
    bgp_ribout_ls_attr_t    attr = {0};
    ls_line_t               info = {0};
    if (!def)
        return "unknown TLV name";
    // The line as running-config prints it: everything after the keyword, with the alias spelled out.
    const char *rest = line + (tokens.next - text);
    while (*rest && isspace((unsigned char)*rest))
        rest++;
    if ((size_t)snprintf(attr.text, sizeof(attr.text), "%s%s%s", def->name, *rest ? " " : "", rest) >= sizeof(attr.text))
        return "the line is too long";
    const char *error = ls_tlv(&tokens, def, 0, &attr.type, attr.value, &attr.len, &info);
    if (error)
        return error;
    attr.step_count = info.step_count;
    memcpy(attr.steps, info.steps, sizeof(attr.steps));
    if (word(&tokens))
        return "unexpected text at the end";
    attr.nlri_mask = def->nlri_mask;
    attr.neighbor_len = info.neighbor_len;
    attr.metric_width = info.metric_width;
    attr.flags_named = info.flags_named;
    attr.flags_ospf = info.flags_ospf;
    attr.flags_off = info.flags_off;
    size_t total = 4U + attr.len;
    for (uint32_t i = 0; i < b->ls_attr_count; i++)
        total += 4U + b->ls_attrs[i].len;
    if (b->ls_attr_count >= BGP_RIBOUT_LS_ATTRS_MAX || total > BGP_RIBOUT_LS_ATTR_MAX)
        return "the BGP-LS Attribute is full (64 TLVs, 2048 octets)";
    if (bgp_ribout_reserve_ls_attrs(b, b->ls_attr_count + 1) < 0)
        return "out of memory";
    // RFC 9552 section 5.3: TLVs in ascending type order; equal types keep the order of their lines.
    uint32_t at = b->ls_attr_count;
    while (at > 0 && b->ls_attrs[at - 1].type > attr.type) {
        b->ls_attrs[at] = b->ls_attrs[at - 1];
        at--;
    }
    b->ls_attrs[at] = attr;
    b->ls_attr_count++;
    return NULL;
}

int bgp_ribout_parse_ls(bgp_ribout_config_t *b, const char *line) {
    const char *error = parse_ls_attr(b, line);
    if (error)
        fprintf(stderr, "Error: Invalid ls line: %s. Form: ls <tlv-name> <fields> [x <count>] [per <axis>]\n", error);
    return error ? -1 : 0;
}

/*
 * The place an axis has in a template (0 is the outermost) and its number of values; -1 when the template does not
 * step it.
 */
static int template_axis_slot(const bgp_ribout_template_t *t, uint8_t axis, uint32_t *values) {
    uint32_t inner = 1;
    for (int which = 1; which < BGP_RIBOUT_STEP_AXES; which++) {
        if (!t->more_steps[which - 1])
            continue;
        inner *= t->more_counts[which - 1];
        if (t->more_steps[which - 1] == axis) {
            *values = t->more_counts[which - 1];
            return which;
        }
    }
    *values = t->count / inner;
    return t->step == axis ? 0 : -1;
}

/*
 * A value that follows an axis: the template must step that axis, and the last value of the axis must fit.
 */
static const char *line_steps_error(const bgp_ribout_template_t *t, const bgp_ribout_ls_attr_t *a) {
    for (uint8_t k = 0; k < a->step_count; k++) {
        uint32_t values = 1;
        if (!a->steps[k].axis)
            continue;
        if (template_axis_slot(t, a->steps[k].axis, &values) < 0)
            return "follows an axis that the nlri template does not step";
        if (!ls_step_fits(a->value, &a->steps[k], values - 1))
            return "runs past the end of its field on the last value of its axis";
    }
    return NULL;
}

/*
 * Each TLV must fit the NLRI type of the template, and the fields that follow the Protocol-ID must fit that protocol.
 */
static int ls_attrs_validate(const bgp_ribout_config_t *b) {
    const bgp_ribout_template_t *t = &b->nlri_template;
    int isis = t->protocol == BGPLS_PROTO_ISIS_L1 || t->protocol == BGPLS_PROTO_ISIS_L2;
    int ospf = t->protocol == BGPLS_PROTO_OSPFV2 || t->protocol == BGPLS_PROTO_OSPFV3;
    uint8_t on = t->route_type == BGPLS_NLRI_NODE ? BGPLS_ON_NODE : t->route_type == BGPLS_NLRI_LINK ? BGPLS_ON_LINK
                 : t->route_type == BGPLS_NLRI_SRV6_SID ? BGPLS_ON_SRV6_SID
                 : t->route_type == BGPLS_NLRI_SR_POLICY ? BGPLS_ON_SR_POLICY : BGPLS_ON_PREFIX;
    if (b->ls_attr_count && t->family != BGP_RIBOUT_FAMILY_BGP_LS) {
        fprintf(stderr, "Error: ls lines need an nlri bgp-ls template\n");
        return -1;
    }
    for (uint32_t i = 0; i < b->ls_attr_count; i++) {
        const bgp_ribout_ls_attr_t *a = &b->ls_attrs[i];
        const char                 *error = NULL;
        if (!(a->nlri_mask & on))
            error = "is not an attribute of this NLRI type";
        else if (a->neighbor_len && ((isis && a->neighbor_len != 6) || (ospf && a->neighbor_len != 4)))
            error = "has a neighbor ID of the wrong length for the protocol (IS-IS 6 octets, OSPF 4)";
        else if (a->metric_width && ((isis && a->metric_width == 2) || (ospf && a->metric_width != 2)))
            error = "has a metric width the protocol does not use (IS-IS: width 1 or 3, OSPF: width 2)";
        else if ((a->flags_named & 1) && !(isis && (a->flags_named & 2)) && !(ospf && (a->flags_named & 4)))
            error = "names flags that the protocol of the NLRI does not define; use a number";
        else if ((a->type == 1039 || a->type == 1044) && a->value[0] < 128)
            error = "needs a Flexible Algorithm number from 128 to 255";
        else if (a->type >= 1101 && a->type <= 1103 && t->protocol != BGPLS_PROTO_BGP)
            error = "is a BGP peering SID: the NLRI needs protocol bgp";
        if (!error)
            error = line_steps_error(t, a);
        if (error) {
            fprintf(stderr, "Error: ls %s: %s\n", a->text, error);
            return -1;
        }
    }
    return 0;
}

/*
 * Add the sequences of one line to a plan; `value` is where the value of the line starts in the plan.
 */
static void plan_line_steps(bgp_ribout_ls_attr_plan_t *plan, const bgp_ribout_template_t *t,
                            const bgp_ribout_ls_attr_t *a, uint16_t value) {
    for (uint8_t k = 0; k < a->step_count; k++) {
        uint32_t values;
        int      slot = a->steps[k].axis ? template_axis_slot(t, a->steps[k].axis, &values) : -1;
        if (!a->steps[k].axis && a->steps[k].count < 2)
            continue;
        plan->step[plan->steps].off = (uint16_t)(value + a->steps[k].off);
        plan->step[plan->steps].len = a->steps[k].len;
        plan->step[plan->steps].shift = a->steps[k].shift;
        plan->step[plan->steps].slot = (uint8_t)(slot + 1);
        plan->step[plan->steps++].count = a->steps[k].count;
        plan->per |= slot >= 0;
    }
}

void bgp_ribout_ls_attr_plan(const bgp_ribout_config_t *b, bgp_ribout_ls_attr_plan_t *plan) {
    int ospf = b->nlri_template.protocol == BGPLS_PROTO_OSPFV2 || b->nlri_template.protocol == BGPLS_PROTO_OSPFV3;
    plan->len = plan->steps = plan->per = 0;
    for (uint32_t i = 0; i < b->ls_attr_count; i++) {
        const bgp_ribout_ls_attr_t *a = &b->ls_attrs[i];
        uint16_t                    value = (uint16_t)(plan->len + 4);
        if (put_tlv(plan->data, BGP_RIBOUT_LS_ATTR_MAX, &plan->len, a->type, a->value, a->len) < 0)
            break;
        plan_line_steps(plan, &b->nlri_template, a, value);
        if (ospf && (a->flags_named & 1))
            plan->data[value + a->flags_off] = a->flags_ospf;
    }
}

uint16_t bgp_ribout_ls_attr_encode(const bgp_ribout_ls_attr_plan_t *plan, uint64_t rotation,
                                   const uint32_t index[BGP_RIBOUT_STEP_AXES], uint8_t *out) {
    memcpy(out, plan->data, plan->len);
    for (uint16_t i = 0; i < plan->steps; i++) {
        uint32_t n = plan->step[i].slot ? index[plan->step[i].slot - 1] : (uint32_t)(rotation % plan->step[i].count);
        bytes_be_add(out + plan->step[i].off, plan->step[i].len, n, plan->step[i].shift);
    }
    return plan->len;
}

/*
 * Attributes bgpsim builds from their own lines. A raw `attribute` line cannot name one of them.
 */
static int path_attr_is_built(uint8_t type) {
    static const uint8_t built[] = {BGP_ATTR_ORIGIN,        BGP_ATTR_AS_PATH,       BGP_ATTR_NEXT_HOP,
                                    BGP_ATTR_MULTI_EXIT_DISC, BGP_ATTR_LOCAL_PREF,  BGP_ATTR_COMMUNITIES,
                                    BGP_ATTR_MP_REACH_NLRI, BGP_ATTR_MP_UNREACH_NLRI, BGP_ATTR_EXT_COMM,
                                    BGP_ATTR_AS4_PATH,      BGP_ATTR_AS4_AGGREGATOR, BGP_ATTR_PMSI_TUNNEL,
                                    BGP_ATTR_TUNNEL_ENCAP,  BGP_ATTR_IPV6_EXT_COMM, BGP_ATTR_BGP_LS,
                                    BGP_ATTR_LARGE_COMMUNITY};
    for (size_t i = 0; i < sizeof(built); i++)
        if (built[i] == type)
            return 1;
    return 0;
}

static const char *parse_path_attr(bgp_ribout_config_t *b, const char *line) {
    char text[BGPSIM_COMMAND_SIZE + 64];
    if (strlen(line) >= sizeof(text))
        return "the line is too long";
    snprintf(text, sizeof(text), "%s", line);
    tokens_t             tokens = {.next = text};
    const char          *keyword = word(&tokens);
    bgp_ribout_ls_attr_t attr = {0};
    ls_line_t            info = {0};
    int                  container = 0;
    uint8_t              code = bgp_path_attr_line(keyword, &attr.attr_flags, &container);
    if (!code)
        return "unknown path attribute";
    // A container line names one TLV of the attribute: `prefix-sid index 100`.
    const bgpls_attr_def_t *def = bgp_path_attr_def_find(keyword, container ? word(&tokens) : NULL);
    if (!def)
        return "unknown TLV name for this attribute";
    while (*line && isspace((unsigned char)*line))
        line++;
    if ((size_t)snprintf(attr.text, sizeof(attr.text), "%s", line) >= sizeof(attr.text))
        return "the line is too long";
    // A keyword without a value arrives with a space after it.
    for (size_t end = strlen(attr.text); end && isspace((unsigned char)attr.text[end - 1]); end--)
        attr.text[end - 1] = '\0';
    const char *error = ls_tlv(&tokens, def, 0, &attr.type, attr.value, &attr.len, &info);
    if (error)
        return error;
    if (word(&tokens))
        return "unexpected text at the end";
    attr.step_count = info.step_count;
    memcpy(attr.steps, info.steps, sizeof(attr.steps));
    attr.type = code;
    attr.container = (uint8_t)container;
    attr.tlv = container ? (uint8_t)def->type : 0;
    if (code == 255) {
        // attribute type <n> [flags <hex>] value <hex>: the first two octets are the type and the flags.
        attr.raw = 1;
        attr.type = attr.value[0];
        if (path_attr_is_built(attr.value[0]))
            return "bgpsim builds this attribute from its own line";
        if (attr.value[1])
            attr.attr_flags = attr.value[1] & (uint8_t)~BGP_ATTR_FLAG_EXTENDED_LEN;
        attr.len = (uint16_t)(attr.len - 2);
        memmove(attr.value, attr.value + 2, attr.len);
        attr.step_count = 0;
    }
    // RFC 8669 section 3.2: an Originator SRGB is two flag octets, then pairs of first label and size.
    if (container && code == 40 && attr.tlv == 3 && (attr.len < 8 || (attr.len - 2) % 6))
        return "srgb takes range <first-label> <size>, and more such pairs";
    // A line of the same attribute, or of the same TLV of a container, replaces the earlier one.
    uint32_t at = b->path_attr_count, same = b->path_attr_count;
    size_t   total = 4U + attr.len;
    for (uint32_t i = 0; i < b->path_attr_count; i++) {
        const bgp_ribout_ls_attr_t *other = &b->path_attrs[i];
        if (other->type == attr.type && other->tlv == attr.tlv)
            same = i;
        else
            total += 4U + other->len;
    }
    if (total > BGP_RIBOUT_PATH_ATTR_MAX || (same == b->path_attr_count && b->path_attr_count >= BGP_RIBOUT_LS_ATTRS_MAX))
        return "the path attribute lines are full (64 lines, 1024 octets)";
    if (same < b->path_attr_count) {
        b->path_attrs[same] = attr;
        return NULL;
    }
    if (bgp_ribout_reserve_path_attrs(b, b->path_attr_count + 1) < 0)
        return "out of memory";
    // Attributes in type order, and the TLVs of a container in the order of their types.
    while (at > 0 && (b->path_attrs[at - 1].type > attr.type ||
                      (b->path_attrs[at - 1].type == attr.type && b->path_attrs[at - 1].tlv > attr.tlv))) {
        b->path_attrs[at] = b->path_attrs[at - 1];
        at--;
    }
    b->path_attrs[at] = attr;
    b->path_attr_count++;
    return NULL;
}

int bgp_ribout_parse_attr(bgp_ribout_config_t *b, const char *line) {
    const char *error = parse_path_attr(b, line);
    if (error)
        fprintf(stderr, "Error: Invalid path attribute line: %s\n", error);
    return error ? -1 : 0;
}

void bgp_ribout_clear_attr(bgp_ribout_config_t *b, const char *keyword) {
    uint8_t  flags;
    int      container;
    uint8_t  code = bgp_path_attr_line(keyword, &flags, &container);
    uint32_t kept = 0;
    // `no attribute` removes every raw line; any other keyword removes the lines of its attribute.
    for (uint32_t i = 0; i < b->path_attr_count; i++) {
        const bgp_ribout_ls_attr_t *a = &b->path_attrs[i];
        if (code == 255 ? a->raw : (!a->raw && a->type == code))
            continue;
        b->path_attrs[kept++] = *a;
    }
    b->path_attr_count = kept;
}

int bgp_ribout_path_attrs_validate(const bgp_ribout_config_t *b) {
    for (uint32_t i = 0; i < b->path_attr_count; i++) {
        const bgp_ribout_ls_attr_t *a = &b->path_attrs[i];
        const char                 *error = line_steps_error(&b->nlri_template, a);
        // No type is here twice: a line replaces the earlier line of its attribute. A raw line cannot share the
        // type of a container, whose lines are TLVs.
        if (!error && i && a->container != b->path_attrs[i - 1].container && b->path_attrs[i - 1].type == a->type)
            error = "is an attribute that another line already sends";
        if (error) {
            fprintf(stderr, "Error: %s: %s\n", a->text, error);
            return -1;
        }
    }
    return 0;
}

void bgp_ribout_path_attr_plan(const bgp_ribout_config_t *b, bgp_ribout_ls_attr_plan_t *plan) {
    plan->len = plan->steps = plan->per = 0;
    for (uint32_t i = 0; i < b->path_attr_count;) {
        const bgp_ribout_ls_attr_t *first = &b->path_attrs[i];
        uint32_t                    end = i + 1;
        size_t                      size = first->container ? 3U + first->len : first->len;
        // The lines of a container are the TLVs of one attribute.
        while (first->container && end < b->path_attr_count && b->path_attrs[end].type == first->type)
            size += 3U + b->path_attrs[end++].len;
        int extended = size > 255;
        if (plan->len + 3U + extended + size > BGP_RIBOUT_PATH_ATTR_MAX)
            break;
        plan->data[plan->len++] = (uint8_t)(first->attr_flags | (extended ? BGP_ATTR_FLAG_EXTENDED_LEN : 0));
        plan->data[plan->len++] = (uint8_t)first->type;
        if (extended)
            plan->data[plan->len++] = (uint8_t)(size >> 8);
        plan->data[plan->len++] = (uint8_t)size;
        for (; i < end; i++) {
            const bgp_ribout_ls_attr_t *a = &b->path_attrs[i];
            if (a->container) {
                plan->data[plan->len++] = a->tlv;
                plan->data[plan->len++] = (uint8_t)(a->len >> 8);
                plan->data[plan->len++] = (uint8_t)a->len;
            }
            memcpy(plan->data + plan->len, a->value, a->len);
            plan_line_steps(plan, &b->nlri_template, a, plan->len);
            plan->len = (uint16_t)(plan->len + a->len);
        }
    }
}

int bgp_ribout_template_validate(const bgp_ribout_config_t *b) {
    // These tokens describe a different NLRI model. Never accept and then silently ignore them.
    if (b->prefix_spec.count || b->rd_count || b->label_count || b->label2_count || b->ethernet_tag_count ||
        b->mac_spec.count || b->ip_spec.count || b->ip2_spec.count || b->gateway_ip_spec.count || b->esi_count ||
        bgp_ribout_has_flowspec_tokens(b) || bgp_ribout_has_srpolicy_tokens(b))
        return -1;
    if (b->next_hop_spec.has_link_local)
        return -1;
    bgp_ribout_family_t family = b->nlri_template.family;
    if (b->family_attr_type == BGP_ATTR_PMSI_TUNNEL && family != BGP_RIBOUT_FAMILY_MVPN_IPV4 &&
        family != BGP_RIBOUT_FAMILY_MVPN_IPV6 && family != BGP_RIBOUT_FAMILY_EVPN_TYPE3)
        return -1;
    if (ls_attrs_validate(b) < 0)
        return -1;
    // One family extended community per template family: l2-info, esi-label or es-import.
    static const struct {
        bgp_ribout_family_t family;
        uint8_t             type, subtype;
    } owners[] = {{BGP_RIBOUT_FAMILY_VPLS, 0x80, 0x0a},
                  {BGP_RIBOUT_FAMILY_EVPN_TYPE1, 0x06, 0x01},
                  {BGP_RIBOUT_FAMILY_EVPN_TYPE4, 0x06, 0x02}};
    const bgp_ribout_ext_comm_line_t *line = &b->ext_comm_lines[BGP_RIBOUT_EXT_COMM_FAMILY];
    int                               owned = !*line->text;
    for (size_t i = 0; i < sizeof(owners) / sizeof(owners[0]); i++)
        owned |= family == owners[i].family && line->values[0].bytes[0] == owners[i].type &&
                 line->values[0].bytes[1] == owners[i].subtype;
    if (!owned)
        return -1;
    uint8_t encoded[1024];
    int     vni = b->nlri_template.label > 0xFFFFF;
    return b->nlri_template.count && bgp_ribout_template_encode(&b->nlri_template, 0, vni, encoded) > 0 &&
                   bgp_ribout_template_encode(&b->nlri_template, b->nlri_template.count - 1, vni, encoded) > 0
               ? 0
               : -1;
}

/*
 * The extended community lines and the place of each in ext_comm_lines[]. The family lines share the first.
 */
static const struct {
    const char *keyword;
    uint8_t     place;
} ext_comm_keywords[] = {{"l2-info", BGP_RIBOUT_EXT_COMM_FAMILY},
                         {"esi-label", BGP_RIBOUT_EXT_COMM_FAMILY},
                         {"es-import", BGP_RIBOUT_EXT_COMM_FAMILY},
                         {"link-bandwidth", BGP_RIBOUT_EXT_COMM_LINK_BANDWIDTH},
                         {"mac-mobility", BGP_RIBOUT_EXT_COMM_MAC_MOBILITY},
                         {"default-gateway", BGP_RIBOUT_EXT_COMM_DEFAULT_GATEWAY},
                         {"ext-community", BGP_RIBOUT_EXT_COMM_RAW}};

static bgp_ribout_ext_comm_line_t *ext_comm_line(bgp_ribout_config_t *b, const char *keyword) {
    for (size_t i = 0; i < sizeof(ext_comm_keywords) / sizeof(*ext_comm_keywords); i++)
        if (!strcmp(keyword, ext_comm_keywords[i].keyword))
            return &b->ext_comm_lines[ext_comm_keywords[i].place];
    return NULL;
}

void bgp_ribout_clear_ext_comm(bgp_ribout_config_t *b, const char *keyword) {
    bgp_ribout_ext_comm_line_t *line = ext_comm_line(b, keyword);
    size_t                      len = strlen(keyword);
    // The family lines share a place: `no l2-info` leaves an esi-label line alone.
    if (line && !strncmp(line->text, keyword, len) && (!line->text[len] || line->text[len] == ' '))
        memset(line, 0, sizeof(*line));
}

/*
 * The values of the extended community line `kind`, from the words after the keyword. Returns their count, or -1.
 */
static int ext_comm_values(const char *kind, tokens_t *tokens, bgp_ext_comm_t *values) {
    uint64_t         a = 0, c, d;
    uint8_t          mac[6];
    bgp_path_attr_t *attr = NULL;
    if (!strcmp(kind, "ext-community")) {
        // Any extended community: the eight octets of each value as 16 hex digits.
        int count = 0;
        for (const char *value; (value = word(tokens)); count++)
            if (count == BGP_RIBOUT_EXT_COMM_VALUES || hex_bytes(value, values[count].bytes, 8) != 8)
                return -1;
        return count ? count : -1;
    }
    if (!strcmp(kind, "l2-info")) {
        if (numeric_field(tokens, "encap", 255, &a) < 0 || numeric_field(tokens, "flags", 255, &c) < 0 ||
            numeric_field(tokens, "mtu", UINT16_MAX, &d) < 0 || word(tokens))
            return -1;
        attr = bgp_attr_create_ext_comm_l2info((uint8_t)a, (uint8_t)c, (uint16_t)d);
    } else if (!strcmp(kind, "esi-label")) {
        // flags <n> | single-active | nothing (all-active), then label <n>.
        const char *first = word(tokens);
        if (first && !strcmp(first, "single-active")) {
            a = 1;
            first = word(tokens);
        } else if (first && !strcmp(first, "flags")) {
            if (number(word(tokens), 255, &a) < 0)
                return -1;
            first = word(tokens);
        }
        if (!first || strcmp(first, "label") || number(word(tokens), 0xFFFFF, &d) < 0 || word(tokens))
            return -1;
        attr = bgp_attr_create_ext_comm_esi_label((uint8_t)a, (uint32_t)d);
    } else if (!strcmp(kind, "es-import")) {
        // mac <mac>, or esi <esi>: RFC 7432 section 7.6 takes the six high-order octets of the ESI value.
        const char *from = word(tokens);
        const char *value = word(tokens);
        evpn_esi_t  esi;
        if (from && value && !strcmp(from, "esi") && bgp_ribout_parse_esi_value(value, &esi) == 0)
            memcpy(mac, esi.value, sizeof(mac));
        else if (!from || !value || strcmp(from, "mac") || bgp_ribout_parse_mac_value(value, mac) < 0)
            return -1;
        if (word(tokens))
            return -1;
        attr = bgp_attr_create_ext_comm_es_import(mac);
    } else if (!strcmp(kind, "link-bandwidth")) {
        // draft-ietf-idr-link-bandwidth: sub-type 4 with a 2-octet AS and the rate as an IEEE float of octets per
        // second. Type 0x40 (not transitive across ASes) unless the line ends with `transitive` (type 0x00).
        uint8_t     rate[4];
        const char *as = word(tokens);
        const char *text = word(tokens);
        const char *last = word(tokens);
        if (number(as, UINT16_MAX, &a) < 0 || bandwidth(text, rate) < 0 ||
            (last && (strcmp(last, "transitive") || word(tokens))))
            return -1;
        attr = bgp_attr_alloc_ext_comm(last ? 0x00 : 0x40, 0x04);
        if (attr) {
            put_be(attr->value + 2, a, 2);
            memcpy(attr->value + 4, rate, sizeof(rate));
        }
    } else if (!strcmp(kind, "mac-mobility")) {
        // RFC 7432 section 7.7: a sequence number; the low-order flag bit marks a sticky (static) MAC.
        const char *sequence = word(tokens);
        const char *last = word(tokens);
        if (number(sequence, UINT32_MAX, &d) < 0 || (last && (strcmp(last, "sticky") || word(tokens))))
            return -1;
        attr = bgp_attr_create_ext_comm_mac_mobility(last ? 1 : 0, (uint32_t)d);
    } else {
        // default-gateway (RFC 7432 section 7.8) has no value.
        if (word(tokens))
            return -1;
        attr = bgp_attr_create_ext_comm_default_gateway();
    }
    if (!attr)
        return -1;
    memcpy(values[0].bytes, attr->value, sizeof(values[0].bytes));
    bgp_path_attr_free(attr);
    return 1;
}

static int parse_family_attr(bgp_ribout_config_t *b, const char *line) {
    char text[1024];
    if (strlen(line) >= sizeof(text))
        return -1;
    snprintf(text, sizeof(text), "%s", line);
    tokens_t    tokens = {.next = text};
    const char *kind = word(&tokens);
    if (!kind)
        return -1;
    bgp_ribout_ext_comm_line_t *place = ext_comm_line(b, kind);
    if (place) {
        bgp_ribout_ext_comm_line_t parsed = {0};
        int count = strlen(line) < sizeof(parsed.text) ? ext_comm_values(kind, &tokens, parsed.values) : -1;
        if (count < 0)
            return -1;
        parsed.count = (uint8_t)count;
        snprintf(parsed.text, sizeof(parsed.text), "%s", line);
        // A keyword without a value arrives with a space after it.
        for (size_t end = strlen(parsed.text); end && isspace((unsigned char)parsed.text[end - 1]); end--)
            parsed.text[end - 1] = '\0';
        *place = parsed;
        return 0;
    }
    if (strcmp(kind, "pmsi"))
        return -1;
    uint64_t a, c, d;
    if (numeric_field(&tokens, "flags", 255, &a) < 0 || numeric_field(&tokens, "type", 255, &c) < 0 ||
        numeric_field(&tokens, "label", 0xFFFFFF, &d) < 0)
        return -1;
    const char *id = field(&tokens, "id");
    uint8_t     bytes[500];
    uint8_t     af = 0;
    // The tunnel identifier: hex octets, "none", or an IPv4 or IPv6 address (the ingress router).
    int len = id && !strcmp(id, "none")                ? 0
              : id && (strchr(id, '.') || strchr(id, ':')) ? (address(id, bytes, &af) < 0 ? -1 : af == AF_INET6 ? 16 : 4)
                                                           : hex_bytes(id, bytes, sizeof(bytes));
    if (len < 0 || word(&tokens))
        return -1;
    // The MPLS form. A label above 20 bits goes out only as a VNI; generation writes that form per group.
    bgp_path_attr_t *attr = bgp_attr_create_pmsi_tunnel((uint8_t)a, (uint8_t)c, d > 0xFFFFF ? 0 : (uint32_t)d, bytes,
                                                        (uint16_t)len);
    if (!attr || attr->length > sizeof(b->family_attr)) {
        bgp_path_attr_free(attr);
        return -1;
    }
    b->pmsi_label = (uint32_t)d;
    memcpy(b->family_attr, attr->value, attr->length);
    b->family_attr_len = attr->length;
    b->family_attr_type = attr->type_code;
    snprintf(b->family_attr_text, sizeof(b->family_attr_text), "%s", line);
    bgp_path_attr_free(attr);
    return 0;
}

int bgp_ribout_parse_family_attr(bgp_ribout_config_t *b, const char *line) {
    static const char *const forms[] = {"pmsi flags <n> type <n> label <label|vni> id <hex|ip|none>",
                                        "l2-info encap <n> flags <n> mtu <n>",
                                        "esi-label [flags <0|1> | single-active] label <20-bit-label>",
                                        "es-import mac <mac> | esi <esi>",
                                        "link-bandwidth <asn> <bits-per-second>[k|m|g] [transitive]",
                                        "mac-mobility <sequence> [sticky]",
                                        "default-gateway (no value)",
                                        "ext-community <16 hex digits> ... (at most 8)"};
    if (parse_family_attr(b, line) == 0)
        return 0;
    for (size_t i = 0; i < sizeof(forms) / sizeof(*forms); i++) {
        size_t word = strcspn(forms[i], " ");
        if (!strncmp(line, forms[i], word) && (line[word] == ' ' || !line[word])) {
            fprintf(stderr, "Error: Invalid %.*s: expected %s\n", (int)word, forms[i], forms[i]);
            break;
        }
    }
    return -1;
}

void bgp_ribout_template_describe(const bgp_ribout_template_t *base, uint64_t instance, char *buffer, size_t len) {
    bgp_ribout_template_t s;
    memcpy(&s, base, offsetof(bgp_ribout_template_t, text));
    if (template_step(&s, instance) < 0) {
        snprintf(buffer, len, "invalid template instance");
        return;
    }
    char        key[INET6_ADDRSTRLEN + 32] = "default";
    const char *step = "";
    switch (s.step) {
    case STEP_RD: {
        uint64_t value = 0;
        size_t   width = s.rd.type == 0 ? 4 : 2;
        for (size_t i = 6 - width; i < 6; i++)
            value = (value << 8) | s.rd.value[i];
        snprintf(key, sizeof(key), "%llu", (unsigned long long)value);
        step = "rd-assigned=";
        break;
    }
    case STEP_TARGET:
        snprintf(key, sizeof(key), "%02x%02x%02x%02x%02x%02x%02x%02x", s.target[0], s.target[1], s.target[2],
                 s.target[3], s.target[4], s.target[5], s.target[6], s.target[7]);
        step = "target=";
        break;
    case STEP_VE:
        snprintf(key, sizeof(key), "%u", s.ve_id);
        step = "ve-id=";
        break;
    case STEP_ROUTER:
        inet_ntop(s.af, s.router, key, sizeof(key));
        step = "router=";
        break;
    case STEP_SOURCE:
        inet_ntop(s.af, s.source, key, sizeof(key));
        step = "source=";
        break;
    case STEP_GROUP:
        inet_ntop(s.af, s.group, key, sizeof(key));
        step = "group=";
        break;
    case STEP_TAG:
        snprintf(key, sizeof(key), "%u", s.tag);
        step = "ethernet-tag=";
        break;
    case STEP_ID:
        snprintf(key, sizeof(key), "%llu", (unsigned long long)s.identifier);
        step = "identifier=";
        break;
    case STEP_ESI:
        snprintf(key, sizeof(key), "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", s.esi.type, s.esi.value[0],
                 s.esi.value[1], s.esi.value[2], s.esi.value[3], s.esi.value[4], s.esi.value[5], s.esi.value[6],
                 s.esi.value[7], s.esi.value[8]);
        step = "esi=";
        break;
    case STEP_NODE:
    case STEP_LINK:
    case STEP_PREFIX:
    case STEP_SID:
    case STEP_REMOTE:
    case STEP_COLOR:
    case STEP_ENDPOINT:
    case STEP_DISCRIMINATOR: {
        // The first field the axis moves, in hex: enough to tell instances apart in a preview.
        step_range_t ranges[LS_STEP_RANGES];
        size_t       at = 0;
        if (ls_step_ranges(&s, s.step, ranges))
            for (size_t i = 0; i < ranges[0].len && at + 3 < sizeof(key); i++)
                at += (size_t)snprintf(key + at, sizeof(key) - at, "%02x", ranges[0].bytes[i]);
        step = s.step == STEP_NODE ? "node=" : s.step == STEP_LINK ? "link=" : s.step == STEP_PREFIX ? "prefix="
               : s.step == STEP_SID ? "sid=" : s.step == STEP_REMOTE ? "remote=" : s.step == STEP_COLOR ? "color="
               : s.step == STEP_ENDPOINT ? "endpoint=" : "discriminator=";
        break;
    }
    }
    if (s.route_type) {
        snprintf(buffer, len, "%s type%u %s%s", bgp_ribout_family_info(s.family)->name, s.route_type, step, key);
    } else {
        snprintf(buffer, len, "%s %s%s", bgp_ribout_family_info(s.family)->name, step, key);
    }
}

/*
 * Each template varies one identity axis. Compare those intervals in semantic space, not wire offsets; labels are
 * forwarding information, not part of an EVPN A-D or VPLS key.
 * Field number sub of one axis: its value goes to out and its octets in s become zero. Returns 0 past the last field.
 * The classic axes have one field; a BGP-LS axis can move several together.
 */
static int key_axis(bgp_ribout_template_t *s, int axis, size_t sub, uint8_t out[16]) {
    const uint8_t *bytes = NULL;
    size_t         len = 0;
    uint64_t       number = 0;
    memset(out, 0, 16);
    if (axis >= STEP_NODE) {
        step_range_t ranges[LS_STEP_RANGES];
        if (sub >= ls_step_ranges(s, axis, ranges))
            return 0;
        memcpy(out + 16 - ranges[sub].len, ranges[sub].bytes, ranges[sub].len);
        memset(ranges[sub].bytes, 0, ranges[sub].len);
        return 1;
    }
    if (sub)
        return 0;
    switch (axis) {
    case STEP_RD:
        len = s->rd.type == 0 ? 4 : 2;
        bytes = s->rd.value + 6 - len;
        break;
    case STEP_TARGET:
        len = s->target[0] == 0 ? 4 : 2;
        bytes = s->target + 8 - len;
        break;
    case STEP_VE:
        number = s->ve_id;
        s->ve_id = 0;
        break;
    case STEP_ROUTER:
        len = s->af == AF_INET6 ? 16 : 4;
        bytes = s->router;
        break;
    case STEP_SOURCE:
        len = s->af == AF_INET6 ? 16 : 4;
        bytes = s->source;
        break;
    case STEP_GROUP:
        len = s->af == AF_INET6 ? 16 : 4;
        bytes = s->group;
        break;
    case STEP_TAG:
        number = s->tag;
        s->tag = 0;
        break;
    case STEP_ID:
        number = s->identifier;
        s->identifier = 0;
        break;
    case STEP_ESI:
        len = sizeof(s->esi.value);
        bytes = s->esi.value;
        break;
    }
    if (bytes) {
        memcpy(out + 16 - len, bytes, len);
        memset((uint8_t *)bytes, 0, len);
    } else {
        for (int i = 15; i >= 8; i--) {
            out[i] = (uint8_t)number;
            number >>= 8;
        }
    }
    return 1;
}

int bgp_ribout_template_compare_keys(const bgp_ribout_template_t *a, const bgp_ribout_template_t *b, int equal) {
    if (!a->count || !b->count || a->family != b->family)
        return 0;
    bgp_ribout_template_t first_a, first_b, last_a, last_b;
    size_t size = offsetof(bgp_ribout_template_t, text);
    memcpy(&first_a, a, size);
    memcpy(&first_b, b, size);
    memcpy(&last_a, a, size);
    memcpy(&last_b, b, size);
    if (template_step(&last_a, a->count - 1) < 0 || template_step(&last_b, b->count - 1) < 0)
        return !equal;
    for (int axis = STEP_RD; axis <= STEP_DISCRIMINATOR; axis++) {
        for (size_t sub = 0;; sub++) {
            uint8_t af[16], al[16], bf[16], bl[16];
            int     fields = key_axis(&first_a, axis, sub, af) + key_axis(&last_a, axis, sub, al) +
                             key_axis(&first_b, axis, sub, bf) + key_axis(&last_b, axis, sub, bl);
            if (!fields)
                break;
            // A field only one template has: their keys cannot meet.
            if (fields != 4)
                return 0;
            if (equal ? (memcmp(af, bf, 16) || memcmp(al, bl, 16)) : (memcmp(af, bl, 16) > 0 || memcmp(bf, al, 16) > 0))
                return 0;
        }
    }
    if (a->family == BGP_RIBOUT_FAMILY_EVPN_TYPE1 || a->family == BGP_RIBOUT_FAMILY_VPLS) {
        first_a.label = first_b.label = 0;
    }
    if (a->family == BGP_RIBOUT_FAMILY_VPLS) {
        first_a.size = first_b.size = 0;
    }
    // Compare fields, not struct padding: independent parses need not have identical padding bytes.
    return first_a.route_type == first_b.route_type && first_a.af == first_b.af &&
           first_a.is_default == first_b.is_default && first_a.rd.type == first_b.rd.type &&
           !memcmp(first_a.rd.value, first_b.rd.value, sizeof(first_a.rd.value)) &&
           first_a.esi.type == first_b.esi.type &&
           !memcmp(first_a.esi.value, first_b.esi.value, sizeof(first_a.esi.value)) &&
           first_a.origin_as == first_b.origin_as && first_a.source_as == first_b.source_as &&
           first_a.label == first_b.label && first_a.offset == first_b.offset && first_a.size == first_b.size &&
           !memcmp(first_a.target, first_b.target, sizeof(first_a.target)) &&
           !memcmp(first_a.route_key, first_b.route_key, sizeof(first_a.route_key)) &&
           first_a.route_key_len == first_b.route_key_len && first_a.protocol == first_b.protocol &&
           first_a.local_len == first_b.local_len && first_a.remote_len == first_b.remote_len &&
           first_a.descriptor_len == first_b.descriptor_len &&
           !memcmp(first_a.local_desc, first_b.local_desc, sizeof(first_a.local_desc)) &&
           !memcmp(first_a.remote_desc, first_b.remote_desc, sizeof(first_a.remote_desc)) &&
           !memcmp(first_a.descriptor, first_b.descriptor, sizeof(first_a.descriptor));
}
