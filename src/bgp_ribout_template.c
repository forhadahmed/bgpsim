#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "bgp.h"
#include "bgp_update.h"
#include "bgp_ribout_config.h"

/*
 * One typed route template per block. The protocol encoders remain the sole owners of wire layouts.
 */
enum { STEP_NONE, STEP_RD, STEP_TARGET, STEP_VE, STEP_ROUTER, STEP_SOURCE, STEP_GROUP, STEP_TAG, STEP_ID };

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

static int template_step(bgp_ribout_template_t *s, uint64_t instance) {
    size_t len = s->af == AF_INET6 ? 16 : 4;
    switch (s->step) {
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
    default:
        return -1;
    }
}

int bgp_ribout_template_encode(const bgp_ribout_template_t *base, uint64_t instance, uint8_t *buffer) {
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
        evpn_type1_prefix_t p = {
            .route_type = 1, .rd = s.rd, .esi = s.esi, .ethernet_tag_id = s.tag, .label = {.label = s.label, .s = 1}};
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
        bgpls_tlv_t local = {.type = BGPLS_TLV_LOCAL_NODE_DESC, .length = s.local_len, .value = s.local_desc};
        bgpls_tlv_t remote = {.type = BGPLS_TLV_REMOTE_NODE_DESC, .length = s.remote_len, .value = s.remote_desc};
        bgpls_tlv_t desc = {.type = s.descriptor_type, .length = s.descriptor_len, .value = s.descriptor};
        bgpls_prefix_t p = {.nlri_type = s.route_type,
                            .protocol_id = s.protocol,
                            .identifier = s.identifier,
                            .local_node_descriptors = &local,
                            .remote_node_descriptors = s.remote_len ? &remote : NULL,
                            .link_descriptors = s.route_type == 2 ? &desc : NULL,
                            .prefix_descriptors = s.route_type >= 3 ? &desc : NULL};
        return bgp_encode_bgpls_prefix(buffer, &p);
    }
    default:
        return -1;
    }
}

static int node_descriptor(tokens_t *tokens, const char *as_key, const char *router_key, uint8_t *out, uint16_t *len) {
    uint64_t asn;
    uint8_t  id[16];
    if (numeric_field(tokens, as_key, UINT32_MAX, &asn) < 0)
        return -1;
    const char *text = field(tokens, router_key);
    if (!text)
        return -1;
    int id_len;
    if (strchr(text, '.')) {
        if (inet_pton(AF_INET, text, id) != 1)
            return -1;
        id_len = 4;
    } else {
        id_len = hex_bytes(text, id, sizeof(id));
    }
    if (id_len < 0)
        return -1;
    bgpls_tlv_t *desc = bgpls_node_desc_create((uint32_t)asn, id, (uint16_t)id_len);
    if (!desc)
        return -1;
    memcpy(out, desc->value, desc->length);
    *len = desc->length;
    bgpls_tlv_list_free(desc);
    return 0;
}

static int parse_ls(tokens_t *tokens, bgp_ribout_template_t *s) {
    const char *type = word(tokens);
    if (!type)
        return -1;
    s->route_type = !strcmp(type, "node")          ? 1
                    : !strcmp(type, "link")        ? 2
                    : !strcmp(type, "ipv4-prefix") ? 3
                    : !strcmp(type, "ipv6-prefix") ? 4
                                                   : 0;
    uint64_t n;
    if (!s->route_type || numeric_field(tokens, "protocol", 255, &n) < 0)
        return -1;
    s->protocol = (uint8_t)n;
    if (numeric_field(tokens, "identifier", UINT64_MAX, &s->identifier) < 0 ||
        node_descriptor(tokens, "local-as", "local-router", s->local_desc, &s->local_len) < 0)
        return -1;
    if (s->route_type == 2) {
        uint64_t local_id, remote_id;
        if (node_descriptor(tokens, "remote-as", "remote-router", s->remote_desc, &s->remote_len) < 0 ||
            numeric_field(tokens, "local-id", UINT32_MAX, &local_id) < 0 ||
            numeric_field(tokens, "remote-id", UINT32_MAX, &remote_id) < 0)
            return -1;
        bgpls_tlv_t *desc = bgpls_tlv_create_link_local_remote((uint32_t)local_id, (uint32_t)remote_id);
        if (!desc)
            return -1;
        s->descriptor_type = desc->type;
        s->descriptor_len = desc->length;
        memcpy(s->descriptor, desc->value, desc->length);
        bgpls_tlv_list_free(desc);
    } else if (s->route_type >= 3) {
        char    *prefix = field(tokens, "prefix");
        char    *slash = prefix ? strchr(prefix, '/') : NULL;
        uint64_t bits;
        s->af = s->route_type == 3 ? AF_INET : AF_INET6;
        if (!slash || number(slash + 1, s->af == AF_INET ? 32 : 128, &bits) < 0)
            return -1;
        *slash = '\0';
        uint8_t ip[16] = {0};
        if (inet_pton(s->af, prefix, ip) != 1)
            return -1;
        size_t bytes = (bits + 7) / 8;
        s->descriptor[0] = (uint8_t)bits;
        memcpy(s->descriptor + 1, ip, bytes);
        if (bits % 8)
            s->descriptor[bytes] &= (uint8_t)(0xFF << (8 - bits % 8));
        s->descriptor_len = (uint16_t)(1 + bytes);
        s->descriptor_type = BGPLS_TLV_IP_REACH_INFO;
    }
    s->step = STEP_ID;
    return 0;
}

int bgp_ribout_parse_nlri(bgp_ribout_config_t *block, const char *line) {
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
                    if (numeric_field(&tokens, "ethernet-tag", UINT32_MAX, &n) < 0)
                        return -1;
                    s.tag = (uint32_t)n;
                }
                if (s.route_type == 1) {
                    if (numeric_field(&tokens, "label", 0xFFFFF, &n) < 0)
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
    if (option && !strcmp(option, "step")) {
        const char *name = word(&tokens);
        if (!name)
            return -1;
        uint8_t step = !strcmp(name, "rd")             ? STEP_RD
                       : !strcmp(name, "target")       ? STEP_TARGET
                       : !strcmp(name, "ve-id")        ? STEP_VE
                       : !strcmp(name, "router")       ? STEP_ROUTER
                       : !strcmp(name, "source")       ? STEP_SOURCE
                       : !strcmp(name, "group")        ? STEP_GROUP
                       : !strcmp(name, "ethernet-tag") ? STEP_TAG
                       : !strcmp(name, "identifier")   ? STEP_ID
                                                       : 0;
        int allowed = step == s.step ||
                      (step == STEP_RD && s.family != BGP_RIBOUT_FAMILY_RTC && s.family != BGP_RIBOUT_FAMILY_BGP_LS &&
                       !(s.route_type == 4 &&
                         (s.family == BGP_RIBOUT_FAMILY_MVPN_IPV4 || s.family == BGP_RIBOUT_FAMILY_MVPN_IPV6))) ||
                      (step == STEP_TAG &&
                       (s.family == BGP_RIBOUT_FAMILY_EVPN_TYPE1 || s.family == BGP_RIBOUT_FAMILY_EVPN_TYPE3)) ||
                      ((step == STEP_SOURCE || step == STEP_GROUP) &&
                       (s.family == BGP_RIBOUT_FAMILY_MVPN_IPV4 || s.family == BGP_RIBOUT_FAMILY_MVPN_IPV6) &&
                       s.route_type >= 3 && s.route_type != 4);
        if (!step || !allowed || s.is_default)
            return -1;
        s.step = step;
        option = word(&tokens);
    }
    if (option) {
        if (strcmp(option, "x") || number(word(&tokens), UINT32_MAX, &n) < 0 || !n || word(&tokens))
            return -1;
        s.count = (uint32_t)n;
    }
    uint8_t encoded[1024];
    if (bgp_ribout_template_encode(&s, 0, encoded) < 0 || bgp_ribout_template_encode(&s, s.count - 1, encoded) < 0)
        return -1;
    snprintf(s.text, sizeof(s.text), "%s", line);
    block->nlri_template = s;
    return 0;
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
    if (b->family_attr_type == BGP_ATTR_BGP_LS && family != BGP_RIBOUT_FAMILY_BGP_LS)
        return -1;
    if (*b->l2_info_text && family != BGP_RIBOUT_FAMILY_VPLS)
        return -1;
    uint8_t encoded[1024];
    return b->nlri_template.count && bgp_ribout_template_encode(&b->nlri_template, 0, encoded) > 0 &&
                   bgp_ribout_template_encode(&b->nlri_template, b->nlri_template.count - 1, encoded) > 0
               ? 0
               : -1;
}

int bgp_ribout_parse_family_attr(bgp_ribout_config_t *b, const char *line) {
    char text[1024];
    if (strlen(line) >= sizeof(text))
        return -1;
    snprintf(text, sizeof(text), "%s", line);
    tokens_t    tokens = {.next = text};
    const char *kind = word(&tokens);
    if (!kind)
        return -1;
    uint64_t a, c, d;
    bgp_path_attr_t *attr = NULL;
    if (!strcmp(kind, "pmsi")) {
        if (numeric_field(&tokens, "flags", 255, &a) < 0 || numeric_field(&tokens, "type", 255, &c) < 0 ||
            numeric_field(&tokens, "label", 0xFFFFF, &d) < 0)
            return -1;
        const char *id = field(&tokens, "id");
        uint8_t     bytes[500];
        int         len = id && !strcmp(id, "none") ? 0 : hex_bytes(id, bytes, sizeof(bytes));
        if (len < 0 || word(&tokens))
            return -1;
        attr = bgp_attr_create_pmsi_tunnel((uint8_t)a, (uint8_t)c, (uint32_t)d, bytes, (uint16_t)len);
    } else if (!strcmp(kind, "l2-info")) {
        if (numeric_field(&tokens, "encap", 255, &a) < 0 || numeric_field(&tokens, "flags", 255, &c) < 0 ||
            numeric_field(&tokens, "mtu", UINT16_MAX, &d) < 0 || word(&tokens) ||
            strlen(line) >= sizeof(b->l2_info_text))
            return -1;
        attr = bgp_attr_create_ext_comm_l2info((uint8_t)a, (uint8_t)c, (uint16_t)d);
        if (!attr)
            return -1;
        memcpy(b->l2_info.bytes, attr->value, 8);
        snprintf(b->l2_info_text, sizeof(b->l2_info_text), "%s", line);
        bgp_path_attr_free(attr);
        return 0;
    } else if (!strcmp(kind, "ls-attribute")) {
        uint8_t bytes[508];
        if (numeric_field(&tokens, "type", UINT16_MAX, &a) < 0)
            return -1;
        int len = hex_bytes(field(&tokens, "value"), bytes, sizeof(bytes));
        if (len < 0 || word(&tokens))
            return -1;
        bgpls_tlv_t tlv = {.type = (uint16_t)a, .length = (uint16_t)len, .value = bytes};
        attr = bgp_attr_create_bgpls(&tlv);
    } else {
        return -1;
    }
    if (!attr || attr->length > sizeof(b->family_attr)) {
        bgp_path_attr_free(attr);
        return -1;
    }
    memcpy(b->family_attr, attr->value, attr->length);
    b->family_attr_len = attr->length;
    b->family_attr_type = attr->type_code;
    snprintf(b->family_attr_text, sizeof(b->family_attr_text), "%s", line);
    bgp_path_attr_free(attr);
    return 0;
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
 */
static void key_axis(bgp_ribout_template_t *s, int axis, uint8_t out[16]) {
    const uint8_t *bytes = NULL;
    size_t         len = 0;
    uint64_t       number = 0;
    memset(out, 0, 16);
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
    for (int axis = STEP_RD; axis <= STEP_ID; axis++) {
        uint8_t af[16], al[16], bf[16], bl[16];
        key_axis(&first_a, axis, af);
        key_axis(&last_a, axis, al);
        key_axis(&first_b, axis, bf);
        key_axis(&last_b, axis, bl);
        if (equal ? (memcmp(af, bf, 16) || memcmp(al, bl, 16)) : (memcmp(af, bl, 16) > 0 || memcmp(bf, al, 16) > 0))
            return 0;
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
           first_a.descriptor_len == first_b.descriptor_len && first_a.descriptor_type == first_b.descriptor_type &&
           !memcmp(first_a.local_desc, first_b.local_desc, sizeof(first_a.local_desc)) &&
           !memcmp(first_a.remote_desc, first_b.remote_desc, sizeof(first_a.remote_desc)) &&
           !memcmp(first_a.descriptor, first_b.descriptor, sizeof(first_a.descriptor));
}
