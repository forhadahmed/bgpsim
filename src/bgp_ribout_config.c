#define OUTPUT_STDIO_REMAP

#include <math.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "bgp.h"
#include "util.h"
#include "output.h"
#include "bgp_update.h"
#include "bgp_ribout_config.h"
#include "bgp_ribout_snapshot.h"

/*
 * Strict decimal numbers (defined with the value parsers below): digits only, the whole text, at most max.
 */
static int bgp_ribout_parse_field(const char *text, uint64_t max, uint32_t *out);
static int bgp_ribout_parse_count(const char *text, uint64_t max, uint32_t *out);

#define RIBOUT_RESERVE_ARRAY(type, field, count_field)                                                \
    static int reserve_##field(bgp_ribout_config_t *block, uint32_t count) {                          \
        if (count > INT_MAX) return -1;                                                               \
        void *data = array_reserve(block->field, sizeof(type), &block->field##_capacity, (int)count); \
        if (!data) return -1;                                                                         \
        block->field = data;                                                                          \
        return 0;                                                                                     \
    }
BGP_RIBOUT_OWNED_ARRAYS(RIBOUT_RESERVE_ARRAY)
#undef RIBOUT_RESERVE_ARRAY

static void ribout_config_release(bgp_ribout_config_t *block) {
#define RIBOUT_FREE_ARRAY(type, field, count) \
    free(block->field); block->field = NULL; block->field##_capacity = 0;
    BGP_RIBOUT_OWNED_ARRAYS(RIBOUT_FREE_ARRAY)
#undef RIBOUT_FREE_ARRAY
    free(block->flowspec);
    block->flowspec = NULL;
}

uint64_t bgp_ribout_config_bytes(const bgp_ribout_config_t *block) {
    if (!block) return 0;
    uint64_t bytes = sizeof(*block);
#define RIBOUT_ARRAY_BYTES(type, field, count) bytes += (uint64_t)block->field##_capacity * sizeof(type);
    BGP_RIBOUT_OWNED_ARRAYS(RIBOUT_ARRAY_BYTES)
#undef RIBOUT_ARRAY_BYTES
    return bytes + (block->flowspec ? sizeof(*block->flowspec) : 0);
}

void bgp_ribout_config_take(bgp_ribout_config_t *dst, bgp_ribout_config_t *src) {
    if (!dst || !src || dst == src) return;
    ribout_config_release(dst);
    // Replace only configuration ownership: generated maps/snapshots stay valid until regeneration commits.
    memcpy(dst, src, BGP_RIBOUT_CONFIG_SIZE);
    memset(src, 0, BGP_RIBOUT_CONFIG_SIZE);
}

// Initialization Functions

int bgp_ribout_init(bgp_ribout_config_t *block, const char *name) {
    if (!block || !bgp_ribout_name_valid(name)) return -1;
    memset(block, 0, sizeof(bgp_ribout_config_t));
    strcpy(block->name, name);

    // Set defaults
    block->path_id_count = 0;
    block->aspath_segment_count = 0;
    block->localpref_spec.mode = BGP_U32_MODE_FIXED;
    block->localpref_spec.value = 100;  /* Default local pref          */
    block->localpref_spec.range_start = 0;
    block->localpref_spec.range_end = 0;
    block->med_spec.enabled = 0;
    block->med_spec.mode = BGP_U32_MODE_FIXED;
    block->med_spec.value = 0;
    block->med_spec.range_start = 0;
    block->med_spec.range_end = 0;
    block->enlp_spec.enabled = 0;
    block->enlp_spec.mode = BGP_U32_MODE_FIXED;
    block->enlp_spec.value = 0;
    block->enlp_spec.range_start = 0;
    block->enlp_spec.range_end = 0;
    block->priority_spec.enabled = 0;
    block->priority_spec.mode = BGP_U32_MODE_FIXED;
    block->priority_spec.value = 0;
    block->priority_spec.range_start = 0;
    block->priority_spec.range_end = 0;
    block->preference_spec.enabled = 0;
    block->preference_spec.mode = BGP_U32_MODE_FIXED;
    block->preference_spec.value = 0;
    block->preference_spec.range_start = 0;
    block->preference_spec.range_end = 0;
    block->binding_sid_spec.enabled = 0;
    block->binding_sid_spec.mode = BGP_U32_MODE_FIXED;
    block->binding_sid_spec.value = 0;
    block->binding_sid_spec.range_start = 0;
    block->binding_sid_spec.range_end = 0;
    block->binding_sid_kind = BGP_RIBOUT_SR_BINDING_SID_NONE;
    block->origin = ORIGIN_IGP;         /* Default origin              */
    block->dirty = 1;                   /* New config needs generation */
    return 0;
}

/*
 * Release generated products and owned configuration inventories, then zero the block.
 */
void bgp_ribout_destroy(bgp_ribout_config_t *block) {
    if (!block) {
        return;
    }

    if (block->ribout != NULL) {
        bgp_ribout_map_destroy(block->ribout);
        block->ribout = NULL;
    }

    // Peers that still hold the snapshot keep its messages.
    bgp_ribout_snapshot_unref(block->snapshot);

    ribout_config_release(block);
    memset(block, 0, sizeof(*block));
}

/*
 * The block owns no locks or self-references, so a move is a copy that leaves src empty.
 */
void bgp_ribout_move(bgp_ribout_config_t *dst, bgp_ribout_config_t *src) {
    if (!dst || !src || dst == src) {
        return;
    }

    *dst = *src;
    memset(src, 0, sizeof(*src));
}

bgp_ribout_config_t *bgp_ribout_config_clone(const bgp_ribout_config_t *block) {
    bgp_ribout_config_t *clone;

    if (!block) {
        return NULL;
    }
    clone = calloc(1, sizeof(*clone));
    if (!clone) {
        return NULL;
    }

    memcpy(clone, block, BGP_RIBOUT_CONFIG_SIZE);
    clone->flowspec = NULL;
#define RIBOUT_RESET_ARRAY(type, field, count) clone->field = NULL; clone->field##_capacity = 0;
    BGP_RIBOUT_OWNED_ARRAYS(RIBOUT_RESET_ARRAY)
#undef RIBOUT_RESET_ARRAY
    // A sequence's logical count may be millions while its physical storage holds only the base value.
#define RIBOUT_CLONE_ARRAY(type, field, count)                                              \
    if (block->field##_capacity) {                                                          \
        if (reserve_##field(clone, (uint32_t)block->field##_capacity) < 0) goto fail;       \
        memcpy(clone->field, block->field, (size_t)block->field##_capacity * sizeof(type)); \
    }
    BGP_RIBOUT_OWNED_ARRAYS(RIBOUT_CLONE_ARRAY)
#undef RIBOUT_CLONE_ARRAY
    if (block->flowspec) {
        clone->flowspec = malloc(sizeof(*clone->flowspec));
        if (!clone->flowspec) {
            goto fail;
        }
        *clone->flowspec = *block->flowspec;
    }
    return clone;
fail:
    bgp_ribout_config_clone_free(clone);
    return NULL;
}

void bgp_ribout_config_clone_free(bgp_ribout_config_t *clone) {
    if (clone) {
        ribout_config_release(clone);
        free(clone);
    }
}

// Parsing Functions

static int bgp_ribout_has_evpn_tokens(const bgp_ribout_config_t *block) {
    return block->ethernet_tag_count > 0 ||
           block->gateway_ip_spec.count > 0 ||
           block->esi_count > 0;
}

static int bgp_ribout_has_evpn_type2_tokens(const bgp_ribout_config_t *block) {
    return block->mac_spec.count > 0 ||
           block->ip_spec.count > 0 ||
           block->label2_count > 0;
}

int bgp_ribout_has_srpolicy_tokens(const bgp_ribout_config_t *block) {
    return block->endpoint_spec.count > 0 ||
           block->distinguisher_count > 0 ||
           block->enlp_spec.enabled ||
           block->enlp_count > 0 ||
           block->priority_spec.enabled ||
           block->priority_count > 0 ||
           block->preference_spec.enabled ||
           block->preference_count > 0 ||
           block->binding_sid_spec.enabled ||
           block->binding_sid_count > 0 ||
           block->binding_sid_srv6_spec.count > 0 ||
           block->segment_list_count > 0;
}

static int bgp_ribout_srv6_structure_valid(uint32_t locator_block_len,
                                           uint32_t locator_node_len,
                                           uint32_t function_len,
                                           uint32_t argument_len) {
    uint32_t total = locator_block_len + locator_node_len +
                     function_len + argument_len;

    return total <= 128U;
}

static void ribout_u32_opt_disable(bgp_u32_optional_spec_t *spec) {
    if (!spec) {
        return;
    }

    spec->enabled = 0;
    spec->mode = BGP_U32_MODE_FIXED;
    spec->value = 0;
    spec->range_start = 0;
    spec->range_end = 0;
}

static const char *ribout_skip_space(const char *ptr) {
    while (isspace((unsigned char)*ptr)) ptr++;
    return ptr;
}

/*
 * Read one unsigned operand, leaving the delimiter for the expression parser.
 */
static int ribout_parse_u32_operand(const char **ptr, uint32_t *value) {
    char *end;
    unsigned long long parsed;

    *ptr = ribout_skip_space(*ptr);
    if (!isdigit((unsigned char)**ptr)) return -1;
    errno = 0;
    parsed = strtoull(*ptr, &end, 10);
    if (errno == ERANGE || parsed > UINT32_MAX) return -1;
    *value = (uint32_t)parsed;
    *ptr = ribout_skip_space(end);
    return 0;
}

static int bgp_ribout_parse_u32_scalar_expr(const char *ptr,
                                            const char *value_name,
                                            uint32_t min_value,
                                            uint32_t max_value,
                                            int allow_fixed_single,
                                            bgp_u32_spec_t *spec,
                                            int *matched_out) {
    uint32_t first, second;
    bgp_u32_mode_t mode;

    if (matched_out) {
        *matched_out = 0;
    }
    if (!ptr || !spec) {
        return -1;
    }
    ptr = ribout_skip_space(ptr);
    if (strncmp(ptr, "randrange", 9) == 0) {
        mode = BGP_U32_MODE_RANDOM_RANGE;
        ptr += 9;
    } else if (strncmp(ptr, "range", 5) == 0) {
        mode = BGP_U32_MODE_RANGE;
        ptr += 5;
    } else if (strncmp(ptr, "rand", 4) == 0) {
        mode = BGP_U32_MODE_RANDOM;
        ptr += 4;
    } else if (allow_fixed_single) {
        mode = BGP_U32_MODE_FIXED;
    } else {
        return 0;  /* A list or sequence belongs to the caller. */
    }

    if (mode != BGP_U32_MODE_FIXED) {
        ptr = ribout_skip_space(ptr);
        if (*ptr++ != '(') goto invalid;
    }
    if (ribout_parse_u32_operand(&ptr, &first) < 0) goto invalid;
    second = first;
    if (mode == BGP_U32_MODE_RANGE || mode == BGP_U32_MODE_RANDOM_RANGE) {
        if (*ptr++ != ',' || ribout_parse_u32_operand(&ptr, &second) < 0) goto invalid;
    }
    if (mode != BGP_U32_MODE_FIXED && *ptr++ != ')') goto invalid;
    if (*ribout_skip_space(ptr) != '\0' || first > second || first < min_value || second > max_value ||
        (mode == BGP_U32_MODE_RANDOM && first == 0)) goto invalid;

    spec->mode = mode;
    spec->value = (mode == BGP_U32_MODE_FIXED || mode == BGP_U32_MODE_RANDOM) ? first : 0;
    spec->range_start = (mode == BGP_U32_MODE_RANGE || mode == BGP_U32_MODE_RANDOM_RANGE) ? first : 0;
    spec->range_end = (mode == BGP_U32_MODE_RANGE || mode == BGP_U32_MODE_RANDOM_RANGE) ? second : 0;
    if (matched_out) *matched_out = 1;
    return 0;

invalid:
    fprintf(stderr, "Error: Invalid %s expression or value\n", value_name);
    return -1;
}

static int bgp_ribout_parse_u32_list_or_sequence(
    const char *line,
    const char *keyword,
    uint32_t **values,
    int *capacity,
    uint32_t *step,
    uint32_t *count_out,
    uint32_t max_values,
    uint32_t max_value,
    const char *value_name) {
    char           buffer[2048];
    char          *ptr;
    char          *token;
    bgp_u32_spec_t spec = {0};
    int            matched = 0;

    strncpy(buffer, line, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    ptr = strstr(buffer, keyword);
    if (!ptr) {
        fprintf(stderr, "Error: Missing '%s' keyword\n", keyword);
        return -1;
    }
    ptr += strlen(keyword);

    *count_out = 0;
    *step = 0;

    if (bgp_ribout_parse_u32_scalar_expr(ptr, value_name, 0, max_value, 0, &spec, &matched) < 0) return -1;
    if (matched) {
        uint64_t count;

        if (spec.mode != BGP_U32_MODE_RANGE) {
            fprintf(stderr, "Error: %s list requires range(), not a random expression\n", value_name);
            return -1;
        }

        count = (uint64_t)spec.range_end - spec.range_start + 1ULL;
        if (count == 0 || count > max_values) {
            fprintf(stderr, "Error: %s range() yields too many values\n", value_name);
            return -1;
        }

        void *data = array_reserve(*values, sizeof(**values), capacity, 1);
        if (!data) return -1;
        *values = data;
        (*values)[0] = spec.range_start;
        *count_out = (uint32_t)count;
        *step = 1;
        return 0;
    }

    token = strtok(ptr, " \t\n");
    if (!token) {
        fprintf(stderr, "Error: No %s values specified\n", value_name);
        return -1;
    }

    {
        uint32_t base;

        if (bgp_ribout_parse_field(token, max_value, &base) < 0) {
            fprintf(stderr, "Error: Invalid %s value: %s (0-%u)\n", value_name, token, max_value);
            return -1;
        }

        token = strtok(NULL, " \t\n");
        if (token && strcmp(token, "x") == 0) {
            char    *count_token = strtok(NULL, " \t\n");
            char    *extra_token = strtok(NULL, " \t\n");
            uint32_t count;

            if (!count_token || extra_token) {
                fprintf(stderr, "Error: Invalid %s syntax. Expected: %s <base> x <count>\n", value_name, keyword);
                return -1;
            }
            if (bgp_ribout_parse_count(count_token, UINT32_MAX, &count) < 0) {
                fprintf(stderr, "Error: Invalid %s count: %s\n", value_name, count_token);
                return -1;
            }
            if (count > max_values || (uint64_t)base + count - 1 > max_value) {
                fprintf(stderr, "Error: %s sequence exceeds supported range\n", value_name);
                return -1;
            }

            void *data = array_reserve(*values, sizeof(**values), capacity, 1);
            if (!data) return -1;
            *values = data;
            (*values)[0] = base;
            *count_out = count;
            *step = 1;
            return 0;
        }

        void *data = array_reserve(*values, sizeof(**values), capacity, 1);
        if (!data) return -1;
        *values = data;
        (*values)[(*count_out)++] = base;
        while (token) {
            uint32_t value;

            if (bgp_ribout_parse_field(token, max_value, &value) < 0) {
                fprintf(stderr, "Error: Invalid %s value: %s (0-%u)\n", value_name, token, max_value);
                return -1;
            }
            if (*count_out >= max_values || *count_out >= INT_MAX) {
                fprintf(stderr, "Error: Too many %s values (max %u)\n", value_name, max_values);
                return -1;
            }

            data = array_reserve(*values, sizeof(**values), capacity, (int)*count_out + 1);
            if (!data) return -1;
            *values = data;
            (*values)[(*count_out)++] = value;
            token = strtok(NULL, " \t\n");
        }
    }

    return 0;
}

/*
 * Parse: address-family <name>, with the CLI names of bgp_families[] (the
 * neighbor "address-family" names). The family must be one that ribout
 * generates.
 */
int bgp_ribout_parse_address_family(bgp_ribout_config_t *block, const char *line) {
    const char         *name = line;
    const bgp_family_t *family;

    while (*name == ' ' || *name == '\t') {
        name++;
    }
    if (strncmp(name, "address-family", 14) != 0) {
        return -1;
    }
    name += 14;
    while (*name == ' ' || *name == '\t') {
        name++;
    }

    family = bgp_family_find(name);
    for (int f = 0; family && f < BGP_RIBOUT_FAMILY_COUNT; f++) {
        const bgp_ribout_family_info_t *info = &bgp_ribout_families[f];

        if (info->kind != BGP_RIBOUT_KIND_NONE && info->afi == family->afi && info->safi == family->safi) {
            block->address_family_afi = family->afi;
            block->address_family_safi = family->safi;
            return 0;
        }
    }

    fprintf(stderr, "Error: ribout does not generate address-family '%s'\n", name);
    return -1;
}

/*
 * A FlowSpec block is one rule template: "prefix" is its destination prefix. The AFI comes from an explicit
 * address-family, or else from the destination and source prefixes; a block without a prefix needs the explicit
 * form. An RD selects SAFI 134.
 */
static bgp_ribout_family_t bgp_ribout_infer_flowspec_family(const bgp_ribout_config_t *block) {
    int af = 0;
    int vpn = block->rd_count > 0;

    if (block->label_count > 0 || block->label2_count > 0 ||
        block->mac_spec.count > 0 || block->ip_spec.count > 0 ||
        block->ethernet_tag_count > 0 || block->gateway_ip_spec.count > 0 ||
        block->esi_count > 0 || bgp_ribout_has_srpolicy_tokens(block)) {
        return BGP_RIBOUT_FAMILY_NONE;
    }

    if (block->address_family_safi == SAFI_FLOWSPEC || block->address_family_safi == SAFI_FLOWSPEC_VPN) {
        af = (block->address_family_afi == AFI_IPV4) ? AF_INET : AF_INET6;
        vpn = vpn || (block->address_family_safi == SAFI_FLOWSPEC_VPN);
    } else {
        af = bgp_ribout_flowspec_af(block);
    }

    if (af == AF_INET) {
        return vpn ? BGP_RIBOUT_FAMILY_FLOWSPEC_VPN_IPV4 : BGP_RIBOUT_FAMILY_FLOWSPEC_IPV4;
    }
    if (af == AF_INET6) {
        return vpn ? BGP_RIBOUT_FAMILY_FLOWSPEC_VPN_IPV6 : BGP_RIBOUT_FAMILY_FLOWSPEC_IPV6;
    }
    return BGP_RIBOUT_FAMILY_NONE;
}

static bgp_ribout_family_t bgp_ribout_infer_family(const bgp_ribout_config_t *block);

/*
 * The inferred family; an explicit address-family must agree with it.
 */
bgp_ribout_family_t bgp_ribout_resolve_family(const bgp_ribout_config_t *block) {
    bgp_ribout_family_t family;

    if (!block) {
        return BGP_RIBOUT_FAMILY_NONE;
    }

    if (block->nlri_template.family) {
        family = block->nlri_template.family;
    } else if (bgp_ribout_has_flowspec_tokens(block) ||
        block->address_family_safi == SAFI_FLOWSPEC || block->address_family_safi == SAFI_FLOWSPEC_VPN) {
        family = bgp_ribout_infer_flowspec_family(block);
    } else {
        family = bgp_ribout_infer_family(block);
    }

    if (block->address_family_afi != 0) {
        const bgp_ribout_family_info_t *info = bgp_ribout_family_info(family);

        if (info->afi != block->address_family_afi || info->safi != block->address_family_safi) {
            return BGP_RIBOUT_FAMILY_NONE;
        }
    }
    return family;
}

/*
 * Family of a non-FlowSpec block from its tokens (docs/bgp-ribout.md, "Family Inference"), or BGP_RIBOUT_FAMILY_NONE
 * when the tokens do not fit one family.
 */
static bgp_ribout_family_t bgp_ribout_infer_family(const bgp_ribout_config_t *block) {
    int has_sr_tokens;
    int has_type2_tokens;

    if (!block) {
        return BGP_RIBOUT_FAMILY_NONE;
    }

    has_sr_tokens = bgp_ribout_has_srpolicy_tokens(block);
    has_type2_tokens = bgp_ribout_has_evpn_type2_tokens(block);

    if (block->endpoint_spec.count > 0) {
        if (has_type2_tokens ||
            block->prefix_spec.count > 0 ||
            block->rd_count > 0 ||
            block->label_count > 0 ||
            block->ethernet_tag_count > 0 ||
            block->gateway_ip_spec.count > 0 ||
            block->esi_count > 0) {
            return BGP_RIBOUT_FAMILY_NONE;
        }
        return (block->endpoint_spec.af == AF_INET) ?
            BGP_RIBOUT_FAMILY_SR_POLICY_IPV4 :
            BGP_RIBOUT_FAMILY_SR_POLICY_IPV6;
    }

    if (has_sr_tokens) {
        return BGP_RIBOUT_FAMILY_NONE;
    }

    if (has_type2_tokens) {
        if (block->prefix_spec.count > 0 || block->gateway_ip_spec.count > 0) {
            return BGP_RIBOUT_FAMILY_NONE;
        }
        return BGP_RIBOUT_FAMILY_EVPN_TYPE2;
    }

    if (block->prefix_spec.count == 0) {
        return BGP_RIBOUT_FAMILY_NONE;
    }

    if (block->rd_count > 0) {
        if (bgp_ribout_has_evpn_tokens(block)) {
            return (block->prefix_spec.af == AF_INET) ?
                BGP_RIBOUT_FAMILY_EVPN_TYPE5_IPV4 :
                BGP_RIBOUT_FAMILY_EVPN_TYPE5_IPV6;
        }

        return (block->prefix_spec.af == AF_INET) ?
            BGP_RIBOUT_FAMILY_VPNV4 :
            BGP_RIBOUT_FAMILY_VPNV6;
    }

    if (block->label_count > 0) {
        return (block->prefix_spec.af == AF_INET) ?
            BGP_RIBOUT_FAMILY_LABELED_IPV4 :
            BGP_RIBOUT_FAMILY_LABELED_IPV6;
    }

    return (block->prefix_spec.af == AF_INET) ?
        BGP_RIBOUT_FAMILY_IPV4_UNICAST :
        BGP_RIBOUT_FAMILY_IPV6_UNICAST;
}

/*
 * Return 1 when next_hop_af is a next-hop AF the block family accepts (the next_hop_afs of its row). Before the family
 * is known, any AF passes; with no family, the AF must be the prefix AF.
 */
static int bgp_ribout_next_hop_family_allowed(const bgp_ribout_config_t *block, uint8_t next_hop_af) {
    bgp_ribout_family_t family;

    if (!block) {
        return 1;
    }

    if (bgp_ribout_has_srpolicy_tokens(block) ||
        bgp_ribout_has_evpn_type2_tokens(block)) {
        return next_hop_af == AF_INET || next_hop_af == AF_INET6;
    }

    if (block->prefix_spec.count == 0) {
        return 1;
    }

    family = bgp_ribout_resolve_family(block);
    if (family == BGP_RIBOUT_FAMILY_NONE) {
        return block->prefix_spec.af == next_hop_af;
    }
    if (next_hop_af == AF_INET) {
        return (bgp_ribout_family_info(family)->next_hop_afs & BGP_RIBOUT_NH_IPV4) != 0;
    }
    if (next_hop_af == AF_INET6) {
        return (bgp_ribout_family_info(family)->next_hop_afs & BGP_RIBOUT_NH_IPV6) != 0;
    }
    return 0;
}

static int bgp_ribout_gateway_ip_family_allowed(const bgp_ribout_config_t *block, uint8_t gateway_ip_af) {
    if (!block || block->prefix_spec.count == 0) {
        return 1;
    }

    return block->prefix_spec.af == gateway_ip_af;
}

static int bgp_ribout_ipv6_is_link_local(const struct in6_addr *addr) {
    return addr != NULL &&
           addr->s6_addr[0] == 0xfe &&
           (addr->s6_addr[1] & 0xc0) == 0x80;
}

/*
 * A label field holds 24 bits: a 20-bit MPLS label, or an EVPN VNI (RFC 8365). Generation checks which one applies.
 */
static int bgp_ribout_label_value_valid(uint32_t label) {
    return label <= 0xFFFFFFU;
}

/*
 * Parse a whole decimal string. Empty input, a sign, trailing text and overflow are errors (-1).
 * A number in base (10, or 0 for C prefixes such as 0x), the whole text: it starts with a digit, so no sign or space
 * (strtoull alone would take "+5", " 5" and wrap "-1"), and nothing follows it.
 */
static int bgp_ribout_parse_u64_number(const char *text, int base, uint64_t *value_out) {
    char *endptr = NULL;
    unsigned long long value;

    if (!text || !value_out || !isdigit((unsigned char)text[0])) {
        return -1;
    }

    errno = 0;
    value = strtoull(text, &endptr, base);
    if (errno == ERANGE || !endptr || *endptr != '\0') {
        return -1;
    }

    *value_out = (uint64_t)value;
    return 0;
}

static int bgp_ribout_parse_u64_decimal(const char *text, uint64_t *value_out) {
    return bgp_ribout_parse_u64_number(text, 10, value_out);
}

/*
 * A decimal number of at most max into *out; the whole text must be the number.
 */
static int bgp_ribout_parse_field(const char *text, uint64_t max, uint32_t *out) {
    uint64_t value;

    if (bgp_ribout_parse_u64_decimal(text, &value) < 0 || value > max) {
        return -1;
    }
    *out = (uint32_t)value;
    return 0;
}

/*
 * A count after "x": a decimal number from 1 to max.
 */
static int bgp_ribout_parse_count(const char *text, uint64_t max, uint32_t *out) {
    return (bgp_ribout_parse_field(text, max, out) < 0 || *out == 0) ? -1 : 0;
}

/*
 * The words of "<keyword> <value> [x <count>] [<word> ...]" (see bgp_ribout_split_value_count()).
 */
typedef struct {
    char     buf[256];
    char    *value;
    uint32_t count;  /* 1 without "x" */
    char    *rest[4];
    int      rest_count;
} bgp_ribout_value_count_t;

/*
 * Split "<keyword> <value> [x <count>] [<word> ...]" into w: the value, the count (1 to 2^32 - 1; 1 without "x") and
 * up to four words after them, which the caller accepts or rejects (bgp_ribout_no_rest()). Prints the error and
 * returns -1 when the line does not start with keyword and a value, or "x" has no valid count.
 */
static int bgp_ribout_split_value_count(const char *line, const char *keyword, bgp_ribout_value_count_t *w) {
    char *save = NULL;
    char *word;

    memset(w, 0, sizeof(*w));
    if (strlen(line) >= sizeof(w->buf)) {
        fprintf(stderr, "Error: %s line too long\n", keyword);
        return -1;
    }
    snprintf(w->buf, sizeof(w->buf), "%s", line);
    word = strtok_r(w->buf, " \t\n", &save);
    if (!word || strcmp(word, keyword) != 0 || !(w->value = strtok_r(NULL, " \t\n", &save))) {
        fprintf(stderr, "Error: Expected: %s <value> [x <count>]\n", keyword);
        return -1;
    }
    w->count = 1;
    word = strtok_r(NULL, " \t\n", &save);
    if (word && strcmp(word, "x") == 0) {
        char *count = strtok_r(NULL, " \t\n", &save);

        if (!count || bgp_ribout_parse_count(count, UINT32_MAX, &w->count) < 0) {
            fprintf(stderr, "Error: %s count must be 1-%u\n", keyword, UINT32_MAX);
            return -1;
        }
        word = strtok_r(NULL, " \t\n", &save);
    }
    for (; word; word = strtok_r(NULL, " \t\n", &save)) {
        if (w->rest_count == (int)(sizeof(w->rest) / sizeof(w->rest[0]))) {
            fprintf(stderr, "Error: Unexpected text after %s: %s\n", keyword, word);
            return -1;
        }
        w->rest[w->rest_count++] = word;
    }
    return 0;
}

/*
 * Reject the words after "<keyword> <value> [x <count>]" of a keyword that takes none.
 */
static int bgp_ribout_no_rest(const bgp_ribout_value_count_t *w, const char *keyword) {
    if (w->rest_count > 0) {
        fprintf(stderr, "Error: Unexpected text after %s: %s\n", keyword, w->rest[0]);
        return -1;
    }
    return 0;
}

static int bgp_ribout_hex_nibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
        return 10 + (c - 'A');
    }
    return -1;
}

static int bgp_ribout_parse_exact_hex_bytes(const char *text, uint8_t *bytes_out, size_t byte_count) {
    size_t text_len;

    if (!text || !bytes_out) {
        return -1;
    }

    text_len = strlen(text);
    if (text_len != byte_count * 2U) {
        return -1;
    }

    for (size_t i = 0; i < byte_count; i++) {
        int hi = bgp_ribout_hex_nibble(text[i * 2U]);
        int lo = bgp_ribout_hex_nibble(text[i * 2U + 1U]);

        if (hi < 0 || lo < 0) {
            return -1;
        }

        bytes_out[i] = (uint8_t)((hi << 4) | lo);
    }

    return 0;
}

static void bgp_ribout_u64_to_be_bytes(uint64_t value, uint8_t *bytes_out, size_t byte_count) {
    if (!bytes_out) {
        return;
    }

    memset(bytes_out, 0, byte_count);
    for (size_t i = 0; i < byte_count && value != 0; i++) {
        bytes_out[byte_count - 1U - i] = (uint8_t)(value & 0xFFu);
        value >>= 8;
    }
}

/*
 * Only hex digits and colons: %2x below would also take a sign, "0x" or a space in an octet.
 */
static int bgp_ribout_hex_colons_only(const char *text) {
    for (; *text; text++) {
        if (!isxdigit((unsigned char)*text) && *text != ':') {
            return 0;
        }
    }
    return 1;
}

static int bgp_ribout_parse_mac_value(const char *text, uint8_t mac[6]) {
    unsigned int octets[6];
    char     trailing = '\0';
    uint64_t integer_value;

    if (!text || !mac) {
        return -1;
    }

    /*
     * Accept canonical aa:bb:cc:dd:ee:ff, or a decimal u64 shorthand that
     * is zero-extended into the 48-bit MAC field. Running-config still emits
     * the canonical colon form.
     */
    if (bgp_ribout_hex_colons_only(text) &&
        sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x%c",
               &octets[0], &octets[1], &octets[2],
               &octets[3], &octets[4], &octets[5],
               &trailing) == 6) {
        for (int i = 0; i < 6; i++) {
            if (octets[i] > 0xFFU) {
                return -1;
            }
            mac[i] = (uint8_t)octets[i];
        }

        return 0;
    }

    if (bgp_ribout_parse_u64_decimal(text, &integer_value) == 0) {
        if (integer_value > 0xFFFFFFFFFFFFULL) {
            return -1;
        }
        bgp_ribout_u64_to_be_bytes(integer_value, mac, 6);
        return 0;
    }

    return -1;
}

/*
 * Parse the administrator part of an RD, RT or SoO: a dotted IPv4 address (is_ipv4_out 1, value_out in host order) or
 * a decimal number up to 2^32 - 1. Returns -1 for other text.
 */
static int bgp_ribout_parse_admin_value(const char *text,
                                        uint32_t *value_out,
                                        int *is_ipv4_out,
                                        struct in_addr *ipv4_out) {
    struct in_addr ipv4_addr;
    uint32_t       value;

    if (inet_pton(AF_INET, text, &ipv4_addr) == 1) {
        if (ipv4_out) {
            *ipv4_out = ipv4_addr;
        }
        if (is_ipv4_out) {
            *is_ipv4_out = 1;
        }
        if (value_out) {
            *value_out = ntohl(ipv4_addr.s_addr);
        }
        return 0;
    }

    if (bgp_ribout_parse_field(text, UINT32_MAX, &value) < 0) {
        return -1;
    }

    if (is_ipv4_out) {
        *is_ipv4_out = 0;
    }
    if (value_out) {
        *value_out = value;
    }
    return 0;
}

static int bgp_ribout_split_colon_pair(const char *text, char *left, size_t left_len, char *right, size_t right_len) {
    const char *colon = strrchr(text, ':');
    size_t      lhs_len;

    if (!colon || colon == text || *(colon + 1) == '\0') {
        return -1;
    }

    lhs_len = (size_t)(colon - text);
    if (lhs_len >= left_len || strlen(colon + 1) >= right_len) {
        return -1;
    }

    memcpy(left, text, lhs_len);
    left[lhs_len] = '\0';
    strncpy(right, colon + 1, right_len - 1);
    right[right_len - 1] = '\0';
    return 0;
}

/*
 * Largest assigned number of a form: 4 octets with a 2-octet AS, else 2 octets (RFC 4360, RFC 5668).
 */
static uint32_t bgp_ribout_admin_assigned_max(bgp_ribout_admin_form_t form) {
    return (form == BGP_RIBOUT_ADMIN_AS2) ? UINT32_MAX : 0xFFFFU;
}

/*
 * Parse "<admin>:<assigned>". A dotted IPv4 admin gives the IPv4 form, a
 * number above 65535 the 4-octet AS form, and other numbers the 2-octet AS
 * form. The assigned number must fit the field of its form.
 */
int bgp_ribout_parse_admin_pair(const char *text, bgp_ribout_admin_pair_t *pair_out) {
    char           left[64];
    char           right[64];
    uint32_t       admin = 0;
    int            is_ipv4 = 0;
    struct in_addr ipv4_addr;
    uint32_t       assigned;

    if (bgp_ribout_split_colon_pair(text, left, sizeof(left),
                                    right, sizeof(right)) < 0 ||
        bgp_ribout_parse_admin_value(left, &admin, &is_ipv4, &ipv4_addr) < 0) {
        return -1;
    }

    if (bgp_ribout_parse_field(right, UINT32_MAX, &assigned) < 0) {
        return -1;
    }

    pair_out->form = is_ipv4 ? BGP_RIBOUT_ADMIN_IPV4 :
                     (admin > 0xFFFFU) ? BGP_RIBOUT_ADMIN_AS4 : BGP_RIBOUT_ADMIN_AS2;
    pair_out->admin = admin;
    pair_out->assigned = (uint32_t)assigned;

    return (pair_out->assigned <= bgp_ribout_admin_assigned_max(pair_out->form)) ? 0 : -1;
}

/*
 * RD of an admin pair: type 0 (2-octet AS), type 1 (IPv4) or type 2 (4-octet AS), RFC 4364 section 4.2.
 */
static route_distinguisher_t bgp_ribout_admin_pair_rd(const bgp_ribout_admin_pair_t *pair) {
    switch (pair->form) {
        case BGP_RIBOUT_ADMIN_IPV4:
            return rd_create_type1(pair->admin, (uint16_t)pair->assigned);
        case BGP_RIBOUT_ADMIN_AS4:
            return rd_create_type2(pair->admin, (uint16_t)pair->assigned);
        case BGP_RIBOUT_ADMIN_AS2:
        default:
            return rd_create_type0((uint16_t)pair->admin, pair->assigned);
    }
}

/*
 * Community for an admin pair. type_base is the 2-octet AS Type of the
 * family (0x00 for RT/SoO, 0x80 for FlowSpec redirect); the IPv4 and 4-octet
 * AS forms use type_base + 1 and type_base + 2.
 */
bgp_path_attr_t *bgp_ribout_admin_pair_ext_comm(const bgp_ribout_admin_pair_t *pair,
                                                uint8_t type_base,
                                                uint8_t sub_type) {
    uint8_t type = (uint8_t)(type_base | (uint8_t)pair->form);

    if (pair->form == BGP_RIBOUT_ADMIN_AS2) {
        return bgp_attr_create_ext_comm_global2(type, sub_type, (uint16_t)pair->admin, pair->assigned);
    }
    return bgp_attr_create_ext_comm_global4(type, sub_type, pair->admin, (uint16_t)pair->assigned);
}

/*
 * Parse one "<admin>:<assigned>" RD.
 */
int bgp_ribout_parse_rd_value(const char *text, route_distinguisher_t *rd_out) {
    bgp_ribout_admin_pair_t pair;

    if (bgp_ribout_parse_admin_pair(text, &pair) < 0) {
        return -1;
    }

    *rd_out = bgp_ribout_admin_pair_rd(&pair);
    return 0;
}

/*
 * Copy the one 8-octet community of a library EXTENDED_COMMUNITIES attribute and free the attribute. Returns -1 (and
 * frees) when the attribute is not one community; value_name goes in the error text.
 */
int bgp_ribout_copy_single_ext_comm_attr(const char *value_name, bgp_path_attr_t *attr, bgp_ext_comm_t *ext_comm_out) {
    if (!attr || !ext_comm_out) {
        if (attr) {
            bgp_path_attr_free(attr);
        }
        return -1;
    }

    if (attr->type_code != BGP_ATTR_EXT_COMM || attr->length != 8) {
        fprintf(stderr,
                "Error: Internal %s encoding did not produce one extended community\n",
                value_name ? value_name : "ext-community");
        bgp_path_attr_free(attr);
        return -1;
    }

    memcpy(ext_comm_out->bytes, attr->value, sizeof(ext_comm_out->bytes));
    bgp_path_attr_free(attr);
    return 0;
}

/*
 * Parse one "<admin>:<assigned>" RT (subtype 0x02) or SoO (subtype 0x03) community.
 */
int bgp_ribout_parse_ext_comm_value(const char *text, uint8_t subtype, bgp_ext_comm_t *ext_comm_out) {
    bgp_ribout_admin_pair_t pair;

    if (bgp_ribout_parse_admin_pair(text, &pair) < 0) {
        return -1;
    }

    return bgp_ribout_copy_single_ext_comm_attr("route-target/SoO",
                                                bgp_ribout_admin_pair_ext_comm(&pair, 0x00, subtype),
                                                ext_comm_out);
}

static int bgp_ribout_parse_encap_type(const char *text, uint16_t *tunnel_type_out) {
    uint32_t value;

    if (!text || !tunnel_type_out) {
        return -1;
    }

    if (strcasecmp(text, "l2tpv3") == 0) {
        *tunnel_type_out = 1;
        return 0;
    }
    if (strcasecmp(text, "gre") == 0) {
        *tunnel_type_out = 2;
        return 0;
    }
    if (strcasecmp(text, "vxlan") == 0) {
        *tunnel_type_out = 8;
        return 0;
    }
    if (strcasecmp(text, "nvgre") == 0) {
        *tunnel_type_out = 9;
        return 0;
    }
    if (strcasecmp(text, "mpls-in-gre") == 0 ||
        strcasecmp(text, "mpls_in_gre") == 0) {
        *tunnel_type_out = 11;
        return 0;
    }

    if (bgp_ribout_parse_field(text, 0xFFFF, &value) < 0) {
        return -1;
    }

    *tunnel_type_out = (uint16_t)value;
    return 0;
}

static int bgp_ribout_parse_encap_value(const char *text, bgp_ext_comm_t *ext_comm_out) {
    uint16_t         tunnel_type;
    bgp_path_attr_t *attr;

    if (bgp_ribout_parse_encap_type(text, &tunnel_type) < 0) {
        return -1;
    }

    attr = bgp_attr_create_ext_comm_encap(tunnel_type);
    return bgp_ribout_copy_single_ext_comm_attr("Encapsulation EC", attr, ext_comm_out);
}

static int bgp_ribout_router_mac_invalid(const uint8_t router_mac[6]) {
    int all_ones = 1;

    if (!router_mac) {
        return 1;
    }

    if ((router_mac[0] & 0x01u) != 0) {
        return 1;
    }

    for (int i = 0; i < 6; i++) {
        if (router_mac[i] != 0xFFu) {
            all_ones = 0;
            break;
        }
    }

    return all_ones;
}

static int bgp_ribout_parse_router_mac_value(const char *text, bgp_ext_comm_t *ext_comm_out) {
    uint8_t          mac[6];
    bgp_path_attr_t *attr;

    if (bgp_ribout_parse_mac_value(text, mac) < 0 ||
        bgp_ribout_router_mac_invalid(mac)) {
        return -1;
    }

    attr = bgp_attr_create_ext_comm_router_mac(mac);
    return bgp_ribout_copy_single_ext_comm_attr("Router's MAC EC", attr, ext_comm_out);
}

int bgp_ribout_parse_esi_value(const char *text, evpn_esi_t *esi_out) {
    unsigned int bytes[10];
    char     trailing = '\0';
    uint8_t  raw[10];
    uint64_t integer_value;

    if (!text || !esi_out) {
        return -1;
    }

    /*
     * ESI accepts the canonical 10-octet colon form, a compact 20-hex-digit
     * shorthand, or a decimal u64 shorthand zero-extended into the 80-bit
     * field. Running-config continues to render canonical colon-separated ESI.
     */
    if (bgp_ribout_hex_colons_only(text) &&
        sscanf(text,
               "%2x:%2x:%2x:%2x:%2x:%2x:%2x:%2x:%2x:%2x%c",
               &bytes[0], &bytes[1], &bytes[2], &bytes[3], &bytes[4],
               &bytes[5], &bytes[6], &bytes[7], &bytes[8], &bytes[9],
               &trailing) == 10) {
        for (int i = 0; i < 10; i++) {
            if (bytes[i] > 0xFFu) {
                return -1;
            }
        }
        raw[0] = (uint8_t)bytes[0];
        for (int i = 0; i < 9; i++) {
            raw[i + 1] = (uint8_t)bytes[i + 1];
        }
    } else if (bgp_ribout_parse_exact_hex_bytes(text, raw, sizeof(raw)) == 0) {
        // Compact 20-hex-digit ESI form.
    } else if (bgp_ribout_parse_u64_decimal(text, &integer_value) == 0) {
        bgp_ribout_u64_to_be_bytes(integer_value, raw, sizeof(raw));
    } else {
        return -1;
    }

    esi_out->type = raw[0];
    for (int i = 0; i < 9; i++) {
        esi_out->value[i] = raw[i + 1];
    }

    return 0;
}

static int bgp_ribout_parse_rt_set_token(const char *token, bgp_rt_set_spec_t *set_out) {
    char   buffer[512];
    char  *value;
    char  *saveptr = NULL;
    size_t len = strlen(token);

    if (len < 3 || token[0] != '[' || token[len - 1] != ']') {
        return -1;
    }

    if (len - 2 >= sizeof(buffer)) {
        return -1;
    }

    memcpy(buffer, token + 1, len - 2);
    buffer[len - 2] = '\0';
    memset(set_out, 0, sizeof(*set_out));

    value = strtok_r(buffer, ",", &saveptr);
    while (value) {
        if (set_out->count >= MAX_RT_VALUES_PER_SET ||
            bgp_ribout_parse_ext_comm_value(str_trim(value), 0x02,
                                            &set_out->values[set_out->count]) < 0) {
            return -1;
        }
        set_out->count++;
        value = strtok_r(NULL, ",", &saveptr);
    }

    return set_out->count > 0 ? 0 : -1;
}

/*
 * Parse "<keyword> <IP/len> [x <count>]". With offset_out, an IPv6 prefix may
 * also use "<IP>/<offset>-<len>" (RFC 8956 section 3.1). Each generated
 * prefix is one whole block further on; the last one must fit.
 */
int bgp_ribout_parse_prefix_spec(const char *keyword, const char *line,
                                 bgp_prefix_spec_t *spec_out, uint8_t *offset_out) {
    char                     prefix_str[64];
    char                    *len_text;
    char                    *dash;
    uint32_t                 prefix_len;
    uint32_t                 offset = 0;
    uint32_t                 count;
    bgp_prefix_spec_t        spec;
    bgp_ribout_value_count_t words;

    memset(&spec, 0, sizeof(spec));
    if (bgp_ribout_split_value_count(line, keyword, &words) < 0 || bgp_ribout_no_rest(&words, keyword) < 0) {
        return -1;
    }
    if (strlen(words.value) >= sizeof(prefix_str)) {
        fprintf(stderr, "Error: Invalid %s: %s\n", keyword, words.value);
        return -1;
    }
    snprintf(prefix_str, sizeof(prefix_str), "%s", words.value);
    count = words.count;

    // Split IP and prefix length
    char *slash = strchr(prefix_str, '/');
    if (!slash) {
        fprintf(stderr, "Error: Prefix must include length (e.g., 10.0.0.0/16)\n");
        return -1;
    }

    *slash = '\0';
    len_text = slash + 1;
    dash = strchr(len_text, '-');
    if (dash) {
        if (!offset_out) {
            fprintf(stderr, "Error: %s does not take an offset\n", keyword);
            return -1;
        }
        *dash = '\0';
        if (bgp_ribout_parse_field(len_text, 255, &offset) < 0) {
            fprintf(stderr, "Error: Invalid prefix offset: %s\n", len_text);
            return -1;
        }
        len_text = dash + 1;
    }

    if (bgp_ribout_parse_field(len_text, 255, &prefix_len) < 0) {
        fprintf(stderr, "Error: Invalid prefix length: %s\n", len_text);
        return -1;
    }

    // Try IPv4 first
    if (inet_pton(AF_INET, prefix_str, &spec.base_addr.ipv4) == 1) {
        spec.af = AF_INET;
        if (prefix_len > 32) {
            fprintf(stderr, "Error: IPv4 prefix length must be 0-32\n");
            return -1;
        }
        if (dash) {
            fprintf(stderr, "Error: An offset is valid only for an IPv6 prefix\n");
            return -1;
        }
    }
    // Try IPv6
    else if (inet_pton(AF_INET6, prefix_str, &spec.base_addr.ipv6) == 1) {
        spec.af = AF_INET6;
        if (prefix_len > 128) {
            fprintf(stderr, "Error: IPv6 prefix length must be 0-128\n");
            return -1;
        }
        // RFC 8956 section 3.1: offset < length <= 128, or both 0.
        if (dash && !(offset < prefix_len || (offset == 0 && prefix_len == 0))) {
            fprintf(stderr, "Error: Prefix offset must be less than the length\n");
            return -1;
        }
        /*
         * Only the bits from the offset to the length are on the wire: more prefixes than they have values would
         * repeat keys.
         */
        if (dash && offset > 0 && prefix_len - offset < 32 && count > (1ULL << (prefix_len - offset))) {
            fprintf(stderr, "Error: %s %s/%u-%u x %u repeats keys: the offset form has %llu values\n", keyword,
                    prefix_str, offset, prefix_len, count, 1ULL << (prefix_len - offset));
            return -1;
        }
    }
    else {
        fprintf(stderr, "Error: Invalid IP address: %s\n", prefix_str);
        return -1;
    }

    spec.prefix_len = (uint8_t)prefix_len;
    spec.count = count;

    if (count > 1) {
        bgp_prefix_spec_t last = spec;

        if (bgp_ribout_prefix_advance(spec.af, &last.base_addr, spec.prefix_len, count - 1) < 0) {
            fprintf(stderr, "Error: %s %s/%u x %u runs past the end of the address space\n",
                    keyword, prefix_str, prefix_len, count);
            return -1;
        }
    }

    *spec_out = spec;
    if (offset_out) {
        *offset_out = (uint8_t)offset;
    }
    return 0;
}

/*
 * Parse: prefix <IP/len> [x <count>]
 */
int bgp_ribout_parse_prefix(bgp_ribout_config_t *block, const char *line) {
    bgp_prefix_spec_t spec;
    uint8_t           offset = 0;

    if (bgp_ribout_parse_prefix_spec("prefix", line, &spec, &offset) < 0) {
        return -1;
    }

    block->prefix_spec = spec;
    block->prefix_offset = offset;

    if (block->next_hop_spec.count > 0 &&
        !bgp_ribout_next_hop_family_allowed(block,
                                            block->next_hop_spec.af)) {
        fprintf(stderr, "Error: next-hop address family is not valid for this ribout family\n");
        return -1;
    }

    if (block->gateway_ip_spec.count > 0 &&
        !bgp_ribout_gateway_ip_family_allowed(block,
                                              block->gateway_ip_spec.af)) {
        fprintf(stderr, "Error: Gateway IP address family must match prefix address family\n");
        return -1;
    }

    return 0;
}

/*
 * "<keyword> rotate <values>": copy line to out without the word rotate, so that the list parser reads "<keyword>
 * <values>", and set *rotate. A rotating key list gives each path one value in turn (value i mod count on rotation
 * step i, in step with the other rotations) instead of multiplying the paths by its count.
 */
static void bgp_ribout_take_rotate(const char *line, const char *keyword, char *out, size_t size, uint8_t *rotate) {
    const char *ptr = strstr(line, keyword);
    const char *rest = ptr ? ptr + strlen(keyword) : NULL;

    *rotate = 0;
    while (rest && (*rest == ' ' || *rest == '\t')) {
        rest++;
    }
    if (rest && strncmp(rest, "rotate", 6) == 0 && (rest[6] == '\0' || isspace((unsigned char)rest[6]))) {
        *rotate = 1;
        snprintf(out, size, "%.*s%s", (int)(ptr + strlen(keyword) - line), line, rest + 6);
    } else {
        snprintf(out, size, "%s", line);
    }
}

/*
 * Parse: rd <value1> [<value2> ...] OR rd <base> x <count>
 */
int bgp_ribout_parse_rd(bgp_ribout_config_t *block, const char *line) {
    char  buffer[2048];
    char *ptr;
    char *token;

    strncpy(buffer, line, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    ptr = strstr(buffer, "rd");
    if (!ptr) {
        fprintf(stderr, "Error: Missing 'rd' keyword\n");
        return -1;
    }
    ptr += 2;

    block->rd_count = 0;
    block->rd_rotate = 0;
    block->rds_step = 0;

    token = strtok(ptr, " \t\n");
    if (token && strcmp(token, "rotate") == 0) {
        block->rd_rotate = 1;
        token = strtok(NULL, " \t\n");
    }
    if (!token) {
        fprintf(stderr, "Error: No route distinguishers specified\n");
        return -1;
    }

    {
        route_distinguisher_t base_rd;
        char                 *next_token;

        if (bgp_ribout_parse_rd_value(token, &base_rd) < 0) {
            fprintf(stderr, "Error: Invalid route distinguisher: %s\n", token);
            return -1;
        }

        next_token = strtok(NULL, " \t\n");
        if (next_token && strcmp(next_token, "x") == 0) {
            char                   *count_token = strtok(NULL, " \t\n");
            char                   *extra_token = strtok(NULL, " \t\n");
            uint32_t                count;
            bgp_ribout_admin_pair_t pair;

            if (!count_token || extra_token ||
                bgp_ribout_parse_admin_pair(token, &pair) < 0) {
                fprintf(stderr, "Error: Invalid RD sequence syntax\n");
                return -1;
            }

            if (bgp_ribout_parse_count(count_token, UINT32_MAX, &count) < 0) {
                fprintf(stderr, "Error: Invalid RD count\n");
                return -1;
            }
            if ((uint64_t)pair.assigned + (count - 1) > bgp_ribout_admin_assigned_max(pair.form)) {
                fprintf(stderr, "Error: RD sequence exceeds supported range\n");
                return -1;
            }

            if (reserve_rds(block, 1) < 0) return -1;
            block->rds[0] = base_rd;
            block->rd_count = count;
            block->rds_step = 1;

            return 0;
        }

        if (reserve_rds(block, 1) < 0) return -1;
        block->rds[block->rd_count++] = base_rd;
        token = next_token;
        while (token) {
            if (reserve_rds(block, block->rd_count + 1) < 0 ||
                bgp_ribout_parse_rd_value(token, &block->rds[block->rd_count]) < 0) {
                fprintf(stderr, "Error: Invalid route distinguisher: %s\n", token);
                return -1;
            }
            block->rd_count++;
            token = strtok(NULL, " \t\n");
        }
    }

    return 0;
}

/*
 * Parse: label [rotate] <value1> [<value2> ...] OR label [rotate] <base> x <count>. Labels multiply the paths of a
 * prefix family; with rotate they go one per path in turn, like rt-set, and the path count stays the same.
 */
int bgp_ribout_parse_label(bgp_ribout_config_t *block, const char *line) {
    char    plain[2048];
    uint8_t rotate;
    bgp_ribout_take_rotate(line, "label", plain, sizeof(plain), &rotate);
    if (bgp_ribout_parse_u32_list_or_sequence(plain, "label",
            &block->labels, &block->labels_capacity, &block->labels_step,
            &block->label_count, UINT32_MAX, 0xffffffU, "label") < 0) return -1;
    block->label_rotate = rotate;
    return 0;
}

/*
 * Parse: label2 <value1> [<value2> ...] OR label2 <base> x <count>
 */
int bgp_ribout_parse_label2(bgp_ribout_config_t *block, const char *line) {
    if (bgp_ribout_parse_u32_list_or_sequence(line,
                                              "label2",
                                              &block->label2s, &block->label2s_capacity, &block->label2s_step,
                                              &block->label2_count, UINT32_MAX,
                                              0xFFFFFFU,
                                              "EVPN Type 2 label2") < 0) {
        return -1;
    }

    return 0;
}

/*
 * Parse the list of: ethernet-tag <value1> [<value2> ...] OR ethernet-tag <base> x <count> (the line without
 * rotate: bgp_ribout_parse_ethernet_tag() takes it out).
 */
static int bgp_ribout_parse_ethernet_tag_list(bgp_ribout_config_t *block, const char *line) {
    return bgp_ribout_parse_u32_list_or_sequence(line, "ethernet-tag",
            &block->ethernet_tags, &block->ethernet_tags_capacity, &block->ethernet_tags_step,
            &block->ethernet_tag_count, UINT32_MAX, UINT32_MAX, "ethernet-tag");
}

/*
 * Parse: ethernet-tag [rotate] <values> | [rotate] <base> x <count>
 */
int bgp_ribout_parse_ethernet_tag(bgp_ribout_config_t *block, const char *line) {
    char    buffer[2048];
    uint8_t rotate;

    bgp_ribout_take_rotate(line, "ethernet-tag", buffer, sizeof(buffer), &rotate);
    if (bgp_ribout_parse_ethernet_tag_list(block, buffer) < 0) {
        return -1;
    }
    block->ethernet_tag_rotate = rotate;
    return 0;
}

/*
 * Parse: mac <aa:bb:cc:dd:ee:ff> [x <count>]
 */
int bgp_ribout_parse_mac(bgp_ribout_config_t *block, const char *line) {
    bgp_ribout_value_count_t words;

    if (bgp_ribout_split_value_count(line, "mac", &words) < 0 || bgp_ribout_no_rest(&words, "mac") < 0) {
        return -1;
    }
    if (bgp_ribout_parse_mac_value(words.value, block->mac_spec.base_addr) < 0) {
        fprintf(stderr, "Error: Invalid MAC address: %s\n", words.value);
        return -1;
    }

    block->mac_spec.count = words.count;
    return 0;
}

/*
 * Parse: ip [rotate] <ip> [x <count>]. The IPs multiply the MACs of an EVPN Type 2 ribout: each MAC is generated with
 * each IP. With rotate MAC i is bound to IP i instead (a MAC/IP binding per host). A ribout holds one ip line per
 * address family: a line of the other family adds a second, so each MAC is generated with an IPv4 and an IPv6
 * binding (dual-stack hosts); a line of a family already set replaces it.
 */
int bgp_ribout_parse_ip(bgp_ribout_config_t *block, const char *line) {
    char                     plain[256];
    uint8_t                  rotate;
    bgp_ribout_value_count_t words;
    bgp_next_hop_spec_t      spec;

    bgp_ribout_take_rotate(line, "ip", plain, sizeof(plain), &rotate);
    if (bgp_ribout_split_value_count(plain, "ip", &words) < 0 || bgp_ribout_no_rest(&words, "ip") < 0) {
        return -1;
    }

    memset(&spec, 0, sizeof(spec));
    spec.count = words.count;
    if (inet_pton(AF_INET, words.value, &spec.base_addr.ipv4) == 1) {
        spec.af = AF_INET;
    } else if (inet_pton(AF_INET6, words.value, &spec.base_addr.ipv6) == 1) {
        spec.af = AF_INET6;
    } else {
        fprintf(stderr, "Error: Invalid EVPN Type 2 IP address: %s\n", words.value);
        return -1;
    }

    if (block->ip_spec.count == 0 || block->ip_spec.af == spec.af) {
        block->ip_spec = spec;
        block->ip_rotate = (uint8_t)rotate;
    } else {
        block->ip2_spec = spec;
        block->ip2_rotate = (uint8_t)rotate;
    }
    return 0;
}

/*
 * Parse: path-id <ids...> | <base> x <count> | range(A,B)
 */
int bgp_ribout_parse_path_ids(bgp_ribout_config_t *block, const char *line) {
    char    plain[2048];
    uint8_t rotate;

    bgp_ribout_take_rotate(line, "path-id", plain, sizeof(plain), &rotate);
    if (bgp_ribout_parse_u32_list_or_sequence(plain, "path-id", &block->path_ids, &block->path_ids_capacity, &block->path_ids_step,
                                              &block->path_id_count, UINT32_MAX,
                                              UINT32_MAX, "path-id") < 0) {
        return -1;
    }
    block->path_id_rotate = rotate;
    return 0;
}

/*
 * Parse: next_hop <IP> OR next_hop <prefix> [x <count>]
 */
int bgp_ribout_parse_next_hop(bgp_ribout_config_t *block, const char *line) {
    const char              *ip_str;
    const char              *link_local_str = NULL;
    int                      has_link_local;
    bgp_ribout_value_count_t words;

    // next-hop <value> [x <count>] [link-local <ipv6>]
    if (bgp_ribout_split_value_count(line, "next-hop", &words) < 0) {
        return -1;
    }
    if (words.rest_count == 2 && strcmp(words.rest[0], "link-local") == 0) {
        link_local_str = words.rest[1];
    } else if (words.rest_count > 0) {
        fprintf(stderr, "Error: Unexpected text after next-hop: %s (expected: link-local <ipv6>)\n", words.rest[0]);
        return -1;
    }
    has_link_local = link_local_str != NULL;
    ip_str = words.value;

    block->next_hop_spec.count = words.count;
    block->next_hop_spec.has_link_local = 0;
    memset(&block->next_hop_spec.link_local, 0, sizeof(block->next_hop_spec.link_local));

    // Try IPv4
    if (inet_pton(AF_INET, ip_str, &block->next_hop_spec.base_addr.ipv4) == 1) {
        if (has_link_local) {
            fprintf(stderr, "Error: link-local next-hop requires an IPv6 global next-hop\n");
            return -1;
        }
        block->next_hop_spec.af = AF_INET;
    }
    // Try IPv6
    else if (inet_pton(AF_INET6, ip_str, &block->next_hop_spec.base_addr.ipv6) == 1) {
        block->next_hop_spec.af = AF_INET6;
        if (has_link_local) {
            if (inet_pton(AF_INET6, link_local_str,
                          &block->next_hop_spec.link_local) != 1) {
                fprintf(stderr, "Error: Invalid IPv6 link-local address: %s\n", link_local_str);
                return -1;
            }
            if (!bgp_ribout_ipv6_is_link_local(&block->next_hop_spec.link_local)) {
                fprintf(stderr, "Error: Address is not IPv6 link-local: %s\n", link_local_str);
                return -1;
            }
            block->next_hop_spec.has_link_local = 1;
        }
    }
    else {
        fprintf(stderr, "Error: Invalid next-hop IP address: %s\n", ip_str);
        return -1;
    }

    // Verify address family matches prefix (only if prefix is already configured)
    if (block->prefix_spec.count > 0 &&
        !bgp_ribout_next_hop_family_allowed(block,
                                            block->next_hop_spec.af)) {
        fprintf(stderr, "Error: next-hop address family is not valid for this ribout family\n");
        return -1;
    }

    return 0;
}

/*
 * Parse: gateway-ip <IP> OR gateway-ip <prefix> [x <count>]
 */
int bgp_ribout_parse_gateway_ip(bgp_ribout_config_t *block, const char *line) {
    const char              *ip_str;
    bgp_ribout_value_count_t words;

    if (bgp_ribout_split_value_count(line, "gateway-ip", &words) < 0 ||
        bgp_ribout_no_rest(&words, "gateway-ip") < 0) {
        return -1;
    }
    ip_str = words.value;
    block->gateway_ip_spec.count = words.count;

    if (inet_pton(AF_INET, ip_str, &block->gateway_ip_spec.base_addr.ipv4) == 1) {
        block->gateway_ip_spec.af = AF_INET;
    } else if (inet_pton(AF_INET6, ip_str, &block->gateway_ip_spec.base_addr.ipv6) == 1) {
        block->gateway_ip_spec.af = AF_INET6;
    } else {
        fprintf(stderr, "Error: Invalid gateway IP address: %s\n", ip_str);
        return -1;
    }

    if (block->prefix_spec.count > 0 &&
        !bgp_ribout_gateway_ip_family_allowed(block,
                                              block->gateway_ip_spec.af)) {
        fprintf(stderr, "Error: Gateway IP address family must match prefix address family\n");
        return -1;
    }

    return 0;
}

/*
 * Parse: esi <value1> [<value2> ...] OR esi <base> x <count>
 */
int bgp_ribout_parse_esi(bgp_ribout_config_t *block, const char *line) {
    char  buffer[2048];
    char *ptr;
    char *token;
    char  first_token[64];

    strncpy(buffer, line, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    ptr = strstr(buffer, "esi");
    if (!ptr) {
        fprintf(stderr, "Error: Missing 'esi' keyword\n");
        return -1;
    }
    ptr += 3;

    block->esi_count = 0;
    memset(block->esis, 0, sizeof(block->esis));

    token = strtok(ptr, " \t\n");
    if (!token) {
        fprintf(stderr, "Error: No ESI values specified\n");
        return -1;
    }

    strncpy(first_token, token, sizeof(first_token) - 1);
    first_token[sizeof(first_token) - 1] = '\0';

    token = strtok(NULL, " \t\n");
    if (token && strcmp(token, "x") == 0) {
        char      *count_token = strtok(NULL, " \t\n");
        char      *extra_token = strtok(NULL, " \t\n");
        uint32_t   count;
        evpn_esi_t base_esi;
        uint8_t    raw_esi[10];

        if (!count_token || extra_token) {
            fprintf(stderr, "Error: Invalid ESI syntax. Expected: esi <value> x <count>\n");
            return -1;
        }
        if (bgp_ribout_parse_count(count_token, MAX_ESIS, &count) < 0) {
            fprintf(stderr, "Error: ESI count must be 1-%d\n", MAX_ESIS);
            return -1;
        }

        if (bgp_ribout_parse_esi_value(first_token, &base_esi) < 0) {
            fprintf(stderr, "Error: Invalid ESI base value: %s\n", first_token);
            return -1;
        }

        raw_esi[0] = base_esi.type;
        memcpy(raw_esi + 1, base_esi.value, sizeof(base_esi.value));

        for (unsigned long i = 0; i < count; i++) {
            uint8_t current_raw[10];

            memcpy(current_raw, raw_esi, sizeof(current_raw));
            /*
             * Sequence ESI values over the full 10-octet wire field so both
             * the type byte and value payload advance consistently.
             */
            if (bytes_be_add(current_raw, sizeof(current_raw), (uint32_t)i, 0) < 0) {
                fprintf(stderr, "Error: ESI sequence exceeds 10-octet value space at offset %lu\n", i);
                return -1;
            }
            block->esis[block->esi_count].type = current_raw[0];
            memcpy(block->esis[block->esi_count].value, current_raw + 1, sizeof(block->esis[block->esi_count].value));
            block->esi_count++;
        }

        return 0;
    }

    if (bgp_ribout_parse_esi_value(first_token, &block->esis[block->esi_count]) < 0) {
        fprintf(stderr, "Error: Invalid ESI value: %s\n", first_token);
        return -1;
    }
    block->esi_count++;

    while (token && block->esi_count < MAX_ESIS) {
        if (bgp_ribout_parse_esi_value(token, &block->esis[block->esi_count]) < 0) {
            fprintf(stderr, "Error: Invalid ESI value: %s\n", token);
            return -1;
        }
        block->esi_count++;
        token = strtok(NULL, " \t\n");
    }

    if (token) {
        fprintf(stderr, "Error: Too many ESI values (max %d)\n", MAX_ESIS);
        return -1;
    }

    return 0;
}

/*
 * An AS number at *pp: decimal digits only, at most 2^32 - 1, ending at a space, a segment bracket or the end (so
 * "65001x" or "+65001" is no AS number). Advances *pp past it; prints the error and returns -1 otherwise.
 */
static int bgp_ribout_aspath_number(char **pp, uint32_t *out) {
    char  *p = *pp;
    size_t n = 0;
    char   saved;
    int    rc;

    while (isdigit((unsigned char)p[n])) {
        n++;
    }
    if (n == 0 || !(p[n] == '\0' || isspace((unsigned char)p[n]) || strchr("{}[]", p[n]))) {
        fprintf(stderr, "Error: Invalid AS number at \"%s\"\n", p);
        return -1;
    }
    saved = p[n];
    p[n] = '\0';
    rc = bgp_ribout_parse_field(p, UINT32_MAX, out);
    p[n] = saved;
    if (rc < 0) {
        fprintf(stderr, "Error: AS number exceeds maximum value\n");
        return -1;
    }
    *pp = p + n;
    return 0;
}

/*
 * "rand(<max>)" at *pp, spaces allowed around the parentheses' contents; advances *pp past it.
 */
static int bgp_ribout_aspath_rand(char **pp, uint32_t *max_out) {
    char *p = *pp;

    if (strncmp(p, "rand", 4) != 0) {
        return -1;
    }
    p += 4;
    while (isspace((unsigned char)*p)) p++;
    if (*p++ != '(') {
        return -1;
    }
    while (isspace((unsigned char)*p)) p++;
    if (!isdigit((unsigned char)*p)) {
        return -1;
    }
    {
        size_t n = 0;
        char   saved;
        int    rc;

        while (isdigit((unsigned char)p[n])) {
            n++;
        }
        saved = p[n];
        p[n] = '\0';
        rc = bgp_ribout_parse_field(p, UINT32_MAX, max_out);
        p[n] = saved;
        if (rc < 0) {
            return -1;
        }
        p += n;
    }
    while (isspace((unsigned char)*p)) p++;
    if (*p++ != ')') {
        return -1;
    }
    *pp = p;
    return 0;
}

/*
 * Parse AS-path: as-path <segments>
 */
int bgp_ribout_parse_aspath(bgp_ribout_config_t *block, const char *line) {
    char buffer[1024];
    strncpy(buffer, line, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    // Skip "as-path" keyword
    char *ptr = strstr(buffer, "as-path");
    if (!ptr) {
        fprintf(stderr, "Error: Missing 'as-path' keyword\n");
        return -1;
    }
    ptr += 7; /* strlen("as-path") */
    ptr = str_trim(ptr);

    // Check for empty AS-path command
    if (*ptr == '\0') {
        fprintf(stderr, "Error: as-path cannot be empty\n");
        return -1;
    }

    block->aspath_segment_count = 0;

    while (*ptr) {
        bgp_aspath_segment_t *seg;

        if (block->aspath_segment_count >= MAX_ASPATH_SEGMENTS) {
            fprintf(stderr, "Error: as-path has more than %d segments\n", MAX_ASPATH_SEGMENTS);
            return -1;
        }
        if (reserve_aspath_segments(block, block->aspath_segment_count + 1) < 0) return -1;
        seg = &block->aspath_segments[block->aspath_segment_count];

        // Check for AS set: { ... }
        if (*ptr == '{') {
            seg->type = ASPATH_SET;
            seg->value_count = 0;
            ptr++; /* Skip '{' */

            while (*ptr && *ptr != '}' &&
                   seg->value_count < MAX_AS_VALUES_PER_SEGMENT) {
                while (isspace((unsigned char)*ptr)) ptr++;
                if (*ptr == '}') break;
                if (bgp_ribout_aspath_number(&ptr, &seg->as_values[seg->value_count]) < 0) {
                    return -1;
                }
                seg->value_count++;
                while (isspace((unsigned char)*ptr)) ptr++;
            }

            if (*ptr == '}') {
                ptr++; /* Skip '}' */
                // Check for empty AS set
                if (seg->value_count == 0) {
                    fprintf(stderr, "Error: AS set cannot be empty\n");
                    return -1;
                }
                block->aspath_segment_count++;
            } else {
                fprintf(stderr, "Error: Unclosed AS set\n");
                return -1;
            }
        }
        // Random segment: [rand(N) x M]
        else if (*ptr == '[') {
            uint32_t max_val, count;

            seg->type = ASPATH_RANDOM;
            ptr++; /* Skip '[' */
            while (isspace((unsigned char)*ptr)) ptr++;
            if (bgp_ribout_aspath_rand(&ptr, &max_val) < 0) {
                fprintf(stderr, "Error: Invalid random AS segment syntax. Expected: [rand(<max>) x <count>]\n");
                return -1;
            }
            while (isspace((unsigned char)*ptr)) ptr++;
            if (*ptr != 'x' || !isspace((unsigned char)ptr[1])) {
                fprintf(stderr, "Error: Invalid random AS segment syntax. Expected: [rand(<max>) x <count>]\n");
                return -1;
            }
            ptr++;
            while (isspace((unsigned char)*ptr)) ptr++;
            if (bgp_ribout_aspath_number(&ptr, &count) < 0) {
                return -1;
            }
            while (isspace((unsigned char)*ptr)) ptr++;
            if (*ptr != ']') {
                fprintf(stderr, "Error: Invalid random AS segment syntax. Expected: [rand(<max>) x <count>]\n");
                return -1;
            }
            ptr++;
            if (max_val == 0 || count == 0) {
                fprintf(stderr, "Error: random AS segment requires rand(max >= 1) x count >= 1\n");
                return -1;
            }
            if (count > MAX_AS_VALUES_PER_SEGMENT) {
                fprintf(stderr, "Error: random AS segment exceeds %u AS values\n", MAX_AS_VALUES_PER_SEGMENT);
                return -1;
            }
            seg->rand_max = max_val;
            seg->rand_count = count;
            block->aspath_segment_count++;
        }
        // Shorthand random segment: rand(N), equivalent to [rand(N) x 1]
        else if (strncmp(ptr, "rand", 4) == 0) {
            uint32_t max_val;

            seg->type = ASPATH_RANDOM;
            if (bgp_ribout_aspath_rand(&ptr, &max_val) < 0 ||
                !(*ptr == '\0' || isspace((unsigned char)*ptr) || *ptr == '{' || *ptr == '[')) {
                fprintf(stderr, "Error: Invalid random AS shorthand syntax. Expected: rand(<max>)\n");
                return -1;
            }
            if (max_val == 0) {
                fprintf(stderr, "Error: random AS shorthand requires rand(max >= 1)\n");
                return -1;
            }
            seg->rand_max = max_val;
            seg->rand_count = 1;  /* Shorthand form defaults to count of 1 */
            block->aspath_segment_count++;
        }
        // AS sequence (space-separated numbers)
        else if (isdigit((unsigned char)*ptr)) {
            seg->type = ASPATH_SEQUENCE;
            seg->value_count = 0;

            // Numbers until a segment of another kind or the end; a long sequence continues in a new segment
            while (isdigit((unsigned char)*ptr) && seg->value_count < MAX_AS_VALUES_PER_SEGMENT) {
                if (bgp_ribout_aspath_number(&ptr, &seg->as_values[seg->value_count]) < 0) {
                    return -1;
                }
                seg->value_count++;
                while (isspace((unsigned char)*ptr)) ptr++;
            }
            block->aspath_segment_count++;
        }
        else {
            fprintf(stderr, "Error: Invalid as-path at \"%s\": expected an AS number, {set}, [rand(N) x M] or "
                    "rand(N)\n", ptr);
            return -1;
        }

        while (isspace((unsigned char)*ptr)) ptr++;
    }

    return 0;
}

/*
 * Parse: localpref <value> | rand(N) | range(A,B) | randrange(A,B)
 */
int bgp_ribout_parse_localpref(bgp_ribout_config_t *block, const char *line) {
    char *ptr;
    int   matched = 0;

    ptr = strstr(line, "localpref");
    if (!ptr) {
        fprintf(stderr, "Error: Missing 'localpref' keyword\n");
        return -1;
    }
    ptr += strlen("localpref");

    if (bgp_ribout_parse_u32_scalar_expr(ptr,
                                         "localpref",
                                         0,
                                         UINT32_MAX,
                                         1,
                                         &block->localpref_spec,
                                         &matched) < 0) {
        return -1;
    }
    if (!matched) {
        fprintf(stderr, "Error: Invalid localpref syntax\n");
        return -1;
    }

    return 0;
}

/*
 * Parse: med <value> | rand(N) | range(A,B) | randrange(A,B)
 */
int bgp_ribout_parse_med(bgp_ribout_config_t *block, const char *line) {
    char          *ptr;
    bgp_u32_spec_t spec = {0};
    int            matched = 0;

    ptr = strstr(line, "med");
    if (!ptr) {
        fprintf(stderr, "Error: Missing 'med' keyword\n");
        return -1;
    }
    ptr += strlen("med");

    if (bgp_ribout_parse_u32_scalar_expr(ptr,
                                         "MED",
                                         0,
                                         UINT32_MAX,
                                         1,
                                         &spec,
                                         &matched) < 0) {
        return -1;
    }
    if (!matched) {
        fprintf(stderr, "Error: Invalid MED syntax\n");
        return -1;
    }

    block->med_spec.enabled = 1;
    block->med_spec.mode = spec.mode;
    block->med_spec.value = spec.value;
    block->med_spec.range_start = spec.range_start;
    block->med_spec.range_end = spec.range_end;
    return 0;
}

/*
 * Parse: rt <value1> [<value2> ...]
 */
int bgp_ribout_parse_rt(bgp_ribout_config_t *block, const char *line) {
    char  buffer[2048];
    char *ptr;
    char *token;

    if (block->rt_set_count > 0) {
        fprintf(stderr, "Error: rt and rt-set are mutually exclusive\n");
        return -1;
    }

    strncpy(buffer, line, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    ptr = strstr(buffer, "rt");
    if (!ptr) {
        fprintf(stderr, "Error: Missing 'rt' keyword\n");
        return -1;
    }
    ptr += 2;

    token = strtok(ptr, " \t\n");
    if (!token) {
        fprintf(stderr, "Error: No route-target values specified\n");
        return -1;
    }

    while (token) {
        if (block->rt_count >= MAX_RTS ||
            bgp_ribout_parse_ext_comm_value(token, 0x02,
                                            &block->rt_values[block->rt_count]) < 0) {
            fprintf(stderr, "Error: Invalid route-target value: %s\n", token);
            return -1;
        }
        block->rt_count++;
        token = strtok(NULL, " \t\n");
    }

    return 0;
}

bgp_rt_set_spec_t bgp_ribout_rt_set_at(const bgp_ribout_config_t *block, uint32_t index) {
    uint32_t low = 0, high = block->rt_set_group_count;

    // Groups are stored in increasing logical-index order; lookup never walks or expands their repetitions.
    while (low + 1 < high) {
        uint32_t mid = low + (high - low) / 2;
        if (block->rt_sets[mid].first <= index) low = mid;
        else high = mid;
    }
    bgp_rt_set_spec_t set = block->rt_sets[low];
    for (uint32_t j = 0; j < set.count; j++) {
        bgp_ext_comm_local_admin_add(&set.values[j], index - set.first);
    }
    return set;
}

/*
 * Parse: rt-set [<rt1>[,<rt2>...]] [x <count>] ...
 */
int bgp_ribout_parse_rt_set(bgp_ribout_config_t *block, const char *line) {
    char  buffer[2048];
    char *ptr;
    char *token;

    if (block->rt_count > 0) {
        fprintf(stderr, "Error: rt and rt-set are mutually exclusive\n");
        return -1;
    }

    strncpy(buffer, line, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    ptr = strstr(buffer, "rt-set");
    if (!ptr) {
        fprintf(stderr, "Error: Missing 'rt-set' keyword\n");
        return -1;
    }
    ptr += strlen("rt-set");

    token = strtok(ptr, " \t\n");
    if (!token) {
        fprintf(stderr, "Error: No route-target sets specified\n");
        return -1;
    }

    while (token) {
        bgp_rt_set_spec_t set;
        char             *next;

        if (bgp_ribout_parse_rt_set_token(token, &set) < 0) {
            fprintf(stderr, "Error: Invalid rt-set token: %s\n", token);
            return -1;
        }
        set.repeat = 1;
        set.first = block->rt_set_count;
        next = strtok(NULL, " \t\n");
        if (next && strcmp(next, "x") == 0) {
            // <set> x <count>: count sets, the local administrator of every route target one larger each time
            char *count_token = strtok(NULL, " \t\n");
            if (!count_token || bgp_ribout_parse_count(count_token, UINT32_MAX, &set.repeat) < 0) {
                fprintf(stderr, "Error: Invalid rt-set sequence\n");
                return -1;
            }
            // Checking the last set proves every intermediate local administrator fits as well.
            for (uint32_t j = 0; j < set.count; j++) {
                bgp_ext_comm_t last = set.values[j];
                if (bgp_ext_comm_local_admin_add(&last, set.repeat - 1) < 0) {
                    fprintf(stderr, "Error: rt-set sequence exceeds the route target's local administrator\n");
                    return -1;
                }
            }
            next = strtok(NULL, " \t\n");
        }
        if (set.repeat > UINT32_MAX - block->rt_set_count ||
            reserve_rt_sets(block, block->rt_set_group_count + 1) < 0) return -1;
        block->rt_sets[block->rt_set_group_count++] = set;
        block->rt_set_count += set.repeat;
        token = next;
    }

    return 0;
}

/*
 * Well-known communities by name. Values 65535:x are all reserved as well known (RFC 1997): a sequence leaves them
 * as they are.
 */
static const struct {
    const char *name;
    uint32_t    value;
} bgp_community_names[] = {
    {"graceful-shutdown",   0xFFFF0000},  /* RFC 8326 */
    {"accept-own",          0xFFFF0001},  /* RFC 7611 */
    {"llgr-stale",          0xFFFF0006},  /* RFC 9494 */
    {"no-llgr",             0xFFFF0007},  /* RFC 9494 */
    {"blackhole",           0xFFFF029A},  /* RFC 7999 */
    {"no-export",           0xFFFFFF01},  /* RFC 1997 */
    {"no-advertise",        0xFFFFFF02},  /* RFC 1997 */
    {"no-export-subconfed", 0xFFFFFF03},  /* RFC 1997 */
    {"no-peer",             0xFFFFFF04},  /* RFC 3765 */
};

#define BGP_COMMUNITY_WELL_KNOWN(value) (((value) >> 16) == 0xFFFF)

const char *bgp_community_well_known_name(uint32_t value) {
    for (size_t i = 0; i < sizeof(bgp_community_names) / sizeof(bgp_community_names[0]); i++) {
        if (bgp_community_names[i].value == value) {
            return bgp_community_names[i].name;
        }
    }
    return NULL;
}

/*
 * A community value: a well-known name, or <0-65535>:<0-65535>.
 */
static int bgp_ribout_parse_community_value(char *text, uint32_t *out) {
    char *colon = strchr(text, ':');
    uint32_t high, low;

    for (size_t i = 0; i < sizeof(bgp_community_names) / sizeof(bgp_community_names[0]); i++) {
        if (strcmp(text, bgp_community_names[i].name) == 0) {
            *out = bgp_community_names[i].value;
            return 0;
        }
    }
    if (!colon) {
        return -1;
    }
    *colon = '\0';
    if (bgp_ribout_parse_field(text, 0xFFFF, &high) < 0 || bgp_ribout_parse_field(colon + 1, 0xFFFF, &low) < 0) {
        return -1;
    }
    *out = high << 16 | low;
    return 0;
}

/*
 * A large-community value: <u32>:<u32>:<u32>.
 */
static int bgp_ribout_parse_large_community_value(char *text, uint32_t out[3]) {
    char *first = strchr(text, ':');
    char *second = first ? strchr(first + 1, ':') : NULL;

    if (!second) {
        return -1;
    }
    *first = *second = '\0';
    return (bgp_ribout_parse_field(text, UINT32_MAX, &out[0]) < 0 ||
            bgp_ribout_parse_field(first + 1, UINT32_MAX, &out[1]) < 0 ||
            bgp_ribout_parse_field(second + 1, UINT32_MAX, &out[2]) < 0) ? -1 : 0;
}

/*
 * Sets of a community or large-community line, in the line's order: add() gets the text of each set's values
 * (comma-separated, no brackets) and its repeat count ("x <count>", else 1).
 */
static int bgp_ribout_parse_sets(bgp_ribout_config_t *block, const char *line, const char *keyword,
                                 int (*add)(bgp_ribout_config_t *block, char *values, uint32_t repeat)) {
    char        buffer[2048];
    char       *token;
    char       *save = NULL;
    const char *ptr = line;

    while (*ptr == ' ' || *ptr == '\t') {
        ptr++;
    }
    if (strncmp(ptr, keyword, strlen(keyword)) != 0) {
        fprintf(stderr, "Error: Missing '%s' keyword\n", keyword);
        return -1;
    }
    snprintf(buffer, sizeof(buffer), "%s", ptr + strlen(keyword));
    token = strtok_r(buffer, " \t\n", &save);
    if (!token) {
        fprintf(stderr, "Error: No %s values specified\n", keyword);
        return -1;
    }
    while (token) {
        char    *values = token;
        char    *next = strtok_r(NULL, " \t\n", &save);
        uint32_t repeat = 1;
        size_t   len = strlen(token);

        if (token[0] == '[') {
            if (len < 3 || token[len - 1] != ']') {
                fprintf(stderr, "Error: Invalid %s set: %s\n", keyword, token);
                return -1;
            }
            token[len - 1] = '\0';
            values = token + 1;
        }
        if (next && strcmp(next, "x") == 0) {
            char *count = strtok_r(NULL, " \t\n", &save);

            if (!count || bgp_ribout_parse_field(count, UINT32_MAX, &repeat) < 0 || repeat == 0) {
                fprintf(stderr, "Error: Invalid %s sequence. Expected: %s <set> x <count>\n", keyword, keyword);
                return -1;
            }
            next = strtok_r(NULL, " \t\n", &save);
        }
        if (add(block, values, repeat) < 0) {
            return -1;
        }
        token = next;
    }
    return 0;
}

static int bgp_ribout_add_community_group(bgp_ribout_config_t *block, char *values, uint32_t repeat) {
    bgp_community_group_t group;
    char                 *save = NULL;

    memset(&group, 0, sizeof(group));
    group.repeat = repeat;
    if (strstr(values, ",,") || values[0] == ',' || values[strlen(values) - 1] == ',') {
        fprintf(stderr, "Error: Invalid community set: [%s]\n", values);
        return -1;
    }
    for (char *value = strtok_r(values, ",", &save); value; value = strtok_r(NULL, ",", &save)) {
        if (group.count >= MAX_COMMUNITIES_PER_SET) {
            fprintf(stderr, "Error: A community set holds at most %d values\n", MAX_COMMUNITIES_PER_SET);
            return -1;
        }
        if (bgp_ribout_parse_community_value(value, &group.values[group.count]) < 0) {
            fprintf(stderr, "Error: Invalid community: %s (expected <0-65535>:<0-65535> or a well-known name)\n",
                    value);
            return -1;
        }
        for (uint32_t k = 0; k < group.count; k++) {
            if (group.values[k] == group.values[group.count]) {
                fprintf(stderr, "Error: community %u:%u appears twice in one set\n", group.values[k] >> 16,
                        group.values[k] & 0xFFFF);
                return -1;
            }
        }
        // x <count> steps the low 16 bits; a well-known value stays as it is.
        if (!BGP_COMMUNITY_WELL_KNOWN(group.values[group.count]) &&
            (group.values[group.count] & 0xFFFF) + (uint64_t)repeat - 1 > 0xFFFF) {
            fprintf(stderr, "Error: community sequence x %u runs past %u:65535\n", repeat,
                    group.values[group.count] >> 16);
            return -1;
        }
        group.count++;
    }
    if (bgp_ribout_community_sets(block) + repeat > UINT32_MAX) {
        fprintf(stderr, "Error: community makes more than %u sets\n", UINT32_MAX);
        return -1;
    }
    if (reserve_community_groups(block, block->community_group_count + 1) < 0) return -1;
    block->community_groups[block->community_group_count++] = group;
    return 0;
}

static int bgp_ribout_add_large_community_group(bgp_ribout_config_t *block, char *values, uint32_t repeat) {
    bgp_large_community_group_t group;
    char                       *save = NULL;

    memset(&group, 0, sizeof(group));
    group.repeat = repeat;
    if (strstr(values, ",,") || values[0] == ',' || values[strlen(values) - 1] == ',') {
        fprintf(stderr, "Error: Invalid large-community set: [%s]\n", values);
        return -1;
    }
    for (char *value = strtok_r(values, ",", &save); value; value = strtok_r(NULL, ",", &save)) {
        if (group.count >= MAX_LARGE_COMMUNITIES_PER_SET) {
            fprintf(stderr, "Error: A large-community set holds at most %d values\n", MAX_LARGE_COMMUNITIES_PER_SET);
            return -1;
        }
        if (bgp_ribout_parse_large_community_value(value, group.values[group.count]) < 0) {
            fprintf(stderr, "Error: Invalid large community: %s (expected <u32>:<u32>:<u32>)\n", value);
            return -1;
        }
        // RFC 8092 section 5: duplicate large communities must not be sent.
        for (uint32_t k = 0; k < group.count; k++) {
            if (memcmp(group.values[k], group.values[group.count], sizeof(group.values[k])) == 0) {
                fprintf(stderr, "Error: large community %u:%u:%u appears twice in one set\n", group.values[k][0],
                        group.values[k][1], group.values[k][2]);
                return -1;
            }
        }
        if (group.values[group.count][2] + (uint64_t)repeat - 1 > UINT32_MAX) {
            fprintf(stderr, "Error: large-community sequence x %u runs past the 32-bit local data 2\n", repeat);
            return -1;
        }
        group.count++;
    }
    if (bgp_ribout_large_community_sets(block) + repeat > UINT32_MAX) {
        fprintf(stderr, "Error: large-community makes more than %u sets\n", UINT32_MAX);
        return -1;
    }
    if (reserve_large_community_groups(block, block->large_community_group_count + 1) < 0) return -1;
    block->large_community_groups[block->large_community_group_count++] = group;
    return 0;
}

/*
 * A line appends its sets, or none of them when one does not parse.
 */
int bgp_ribout_parse_community(bgp_ribout_config_t *block, const char *line) {
    uint32_t before = block->community_group_count;

    if (bgp_ribout_parse_sets(block, line, "community", bgp_ribout_add_community_group) < 0) {
        block->community_group_count = before;
        return -1;
    }
    return 0;
}

int bgp_ribout_parse_large_community(bgp_ribout_config_t *block, const char *line) {
    uint32_t before = block->large_community_group_count;

    if (bgp_ribout_parse_sets(block, line, "large-community", bgp_ribout_add_large_community_group) < 0) {
        block->large_community_group_count = before;
        return -1;
    }
    return 0;
}

uint64_t bgp_ribout_community_sets(const bgp_ribout_config_t *block) {
    uint64_t sets = 0;

    for (uint32_t i = 0; i < block->community_group_count; i++) {
        sets += block->community_groups[i].repeat;
    }
    return sets;
}

uint64_t bgp_ribout_large_community_sets(const bgp_ribout_config_t *block) {
    uint64_t sets = 0;

    for (uint32_t i = 0; i < block->large_community_group_count; i++) {
        sets += block->large_community_groups[i].repeat;
    }
    return sets;
}

static void put_u32(uint8_t *out, uint32_t value) {
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

uint16_t bgp_ribout_community_set_encode(const bgp_ribout_config_t *block, uint64_t index, uint8_t *out) {
    for (uint32_t i = 0; i < block->community_group_count; i++) {
        const bgp_community_group_t *group = &block->community_groups[i];

        if (index < group->repeat) {
            for (uint32_t j = 0; j < group->count; j++) {
                uint32_t value = group->values[j];

                put_u32(out + 4 * j, BGP_COMMUNITY_WELL_KNOWN(value) ? value : value + (uint32_t)index);
            }
            return (uint16_t)(4 * group->count);
        }
        index -= group->repeat;
    }
    return 0;
}

uint16_t bgp_ribout_large_community_set_encode(const bgp_ribout_config_t *block, uint64_t index, uint8_t *out) {
    for (uint32_t i = 0; i < block->large_community_group_count; i++) {
        const bgp_large_community_group_t *group = &block->large_community_groups[i];

        if (index < group->repeat) {
            for (uint32_t j = 0; j < group->count; j++) {
                put_u32(out + 12 * j, group->values[j][0]);
                put_u32(out + 12 * j + 4, group->values[j][1]);
                put_u32(out + 12 * j + 8, group->values[j][2] + (uint32_t)index);
            }
            return (uint16_t)(12 * group->count);
        }
        index -= group->repeat;
    }
    return 0;
}

/*
 * Add delta to the local administrator of an extended community (RFC 4360 section 3, RFC 5668): four octets after a
 * two-octet AS (type 0x00), two after an IPv4 address (0x01) or a four-octet AS (0x02). -1 when it does not fit.
 */
int bgp_ext_comm_local_admin_add(bgp_ext_comm_t *ext_comm, uint32_t delta) {
    uint8_t *v = ext_comm->bytes;

    if ((v[0] & 0x3f) == 0x00) {
        uint64_t admin = ((uint64_t)v[4] << 24) | ((uint64_t)v[5] << 16) | ((uint64_t)v[6] << 8) | v[7];

        if (admin + delta > UINT32_MAX) {
            return -1;
        }
        admin += delta;
        v[4] = (uint8_t)(admin >> 24);
        v[5] = (uint8_t)(admin >> 16);
        v[6] = (uint8_t)(admin >> 8);
        v[7] = (uint8_t)admin;
        return 0;
    }
    if ((v[0] & 0x3f) == 0x01 || (v[0] & 0x3f) == 0x02) {
        uint32_t admin = ((uint32_t)v[6] << 8) | v[7];

        if (admin + (uint64_t)delta > UINT16_MAX) {
            return -1;
        }
        admin += delta;
        v[6] = (uint8_t)(admin >> 8);
        v[7] = (uint8_t)admin;
        return 0;
    }
    return -1;
}

/*
 * Parse "<keyword> <n>", n in 1..max.
 */
static int bgp_ribout_parse_positive(const char *line, const char *keyword, uint32_t max, uint32_t *out) {
    char  buffer[128];
    char *token;

    snprintf(buffer, sizeof(buffer), "%s", line);
    token = strtok(buffer, " \t\n");
    if (!token || strcmp(token, keyword) != 0 || !(token = strtok(NULL, " \t\n")) || strtok(NULL, " \t\n")) {
        fprintf(stderr, "Error: Expected: %s <1-%u>\n", keyword, max);
        return -1;
    }
    if (bgp_ribout_parse_count(token, max, out) < 0) {
        fprintf(stderr, "Error: %s must be 1-%u\n", keyword, max);
        return -1;
    }
    return 0;
}

/*
 * Parse: rotate-every <n>. The attribute rotations advance once every n paths instead of every path.
 */
int bgp_ribout_parse_rotate_every(bgp_ribout_config_t *block, const char *line) {
    return bgp_ribout_parse_positive(line, "rotate-every", 1u << 24, &block->rotate_every);
}

/*
 * Parse: rotate-period <n>. Every rotating list must have n values (or one), so they stay in step.
 */
int bgp_ribout_parse_rotate_period(bgp_ribout_config_t *block, const char *line) {
    return bgp_ribout_parse_positive(line, "rotate-period", 1u << 24, &block->rotate_period);
}

/*
 * Parse: soo <value1> [<value2> ...]
 */
int bgp_ribout_parse_soo(bgp_ribout_config_t *block, const char *line) {
    char  buffer[2048];
    char *ptr;
    char *token;

    strncpy(buffer, line, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    ptr = strstr(buffer, "soo");
    if (!ptr) {
        fprintf(stderr, "Error: Missing 'soo' keyword\n");
        return -1;
    }
    ptr += 3;

    token = strtok(ptr, " \t\n");
    if (!token) {
        fprintf(stderr, "Error: No site-of-origin values specified\n");
        return -1;
    }

    while (token) {
        if (block->soo_count >= MAX_SOOS ||
            bgp_ribout_parse_ext_comm_value(token, 0x03,
                                            &block->soo_values[block->soo_count]) < 0) {
            fprintf(stderr, "Error: Invalid site-of-origin value: %s\n", token);
            return -1;
        }
        block->soo_count++;
        token = strtok(NULL, " \t\n");
    }

    return 0;
}

/*
 * Parse: encap <type1> [<type2> ...]
 */
int bgp_ribout_parse_encap(bgp_ribout_config_t *block, const char *line) {
    char  buffer[1024];
    char *ptr;
    char *token;

    strncpy(buffer, line, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    ptr = strstr(buffer, "encap");
    if (!ptr) {
        fprintf(stderr, "Error: Missing 'encap' keyword\n");
        return -1;
    }
    ptr += (int)strlen("encap");

    token = strtok(ptr, " \t\n");
    if (!token) {
        fprintf(stderr, "Error: No encap values specified\n");
        return -1;
    }

    while (token) {
        if (block->encap_count >= MAX_ENCAPS ||
            bgp_ribout_parse_encap_value(
                token,
                &block->encap_values[block->encap_count]) < 0) {
            fprintf(stderr, "Error: Invalid encap value: %s\n", token);
            return -1;
        }
        block->encap_count++;
        token = strtok(NULL, " \t\n");
    }

    return 0;
}

/*
 * Parse: router-mac <mac1> [<mac2> ...] OR router-mac <base> x <count>
 */
int bgp_ribout_parse_router_mac(bgp_ribout_config_t *block, const char *line) {
    char           buffer[2048];
    char          *ptr;
    char          *token;
    char           first_token[64];
    bgp_ext_comm_t first_value;

    strncpy(buffer, line, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    ptr = strstr(buffer, "router-mac");
    if (!ptr) {
        fprintf(stderr, "Error: Missing 'router-mac' keyword\n");
        return -1;
    }
    ptr += strlen("router-mac");

    token = strtok(ptr, " \t\n");
    if (!token) {
        fprintf(stderr, "Error: No router-mac values specified\n");
        return -1;
    }
    strncpy(first_token, token, sizeof(first_token) - 1);
    first_token[sizeof(first_token) - 1] = '\0';

    if (bgp_ribout_parse_router_mac_value(token, &first_value) < 0) {
        fprintf(stderr, "Error: Invalid router-mac value: %s\n", token);
        return -1;
    }

    token = strtok(NULL, " \t\n");
    if (token && strcmp(token, "x") == 0) {
        char    *count_token = strtok(NULL, " \t\n");
        char    *extra_token = strtok(NULL, " \t\n");
        uint32_t count;
        uint8_t  mac[6];

        if (!count_token || extra_token) {
            fprintf(stderr, "Error: Invalid router-mac syntax. Expected: router-mac <mac> x <count>\n");
            return -1;
        }
        if (bgp_ribout_parse_count(count_token, MAX_ROUTER_MACS, &count) < 0) {
            fprintf(stderr, "Error: router-mac count must be 1-%d\n", MAX_ROUTER_MACS);
            return -1;
        }
        if (block->router_mac_count + count > MAX_ROUTER_MACS) {
            fprintf(stderr, "Error: Too many router-mac values (max %d)\n", MAX_ROUTER_MACS);
            return -1;
        }
        if (bgp_ribout_parse_mac_value(first_token, mac) < 0) {
            fprintf(stderr, "Error: Invalid router-mac base value\n");
            return -1;
        }

        for (unsigned long i = 0; i < count; i++) {
            uint8_t current_mac[6];

            memcpy(current_mac, mac, sizeof(current_mac));
            (void)bytes_be_add(current_mac, sizeof(current_mac), (uint32_t)i, 0);
            if (bgp_ribout_router_mac_invalid(current_mac)) {
                fprintf(stderr, "Error: router-mac sequence generated an invalid unicast MAC at offset %lu\n", i);
                return -1;
            }
            if (bgp_ribout_copy_single_ext_comm_attr(
                    "Router's MAC EC",
                    bgp_attr_create_ext_comm_router_mac(current_mac),
                    &block->router_mac_values[block->router_mac_count]) < 0) {
                fprintf(stderr, "Error: Failed to encode router-mac at offset %lu\n", i);
                return -1;
            }
            block->router_mac_count++;
        }

        return 0;
    }

    if (block->router_mac_count >= MAX_ROUTER_MACS) {
        fprintf(stderr, "Error: Too many router-mac values (max %d)\n", MAX_ROUTER_MACS);
        return -1;
    }
    block->router_mac_values[block->router_mac_count++] = first_value;
    while (token) {
        if (block->router_mac_count >= MAX_ROUTER_MACS ||
            bgp_ribout_parse_router_mac_value(
                token,
                &block->router_mac_values[block->router_mac_count]) < 0) {
            fprintf(stderr, "Error: Invalid router-mac value: %s\n", token);
            return -1;
        }
        block->router_mac_count++;
        token = strtok(NULL, " \t\n");
    }

    return 0;
}

/*
 * Parse: origin <igp|egp|incomplete>
 */
int bgp_ribout_parse_origin(bgp_ribout_config_t *block, const char *line) {
    char origin_str[16];
    char extra[2];

    if (sscanf(line, " origin %15s %1s", origin_str, extra) != 1) {
        fprintf(stderr, "Error: Invalid origin syntax. Expected: origin igp|egp|incomplete\n");
        return -1;
    }

    if (strcmp(origin_str, "igp") == 0) {
        block->origin = ORIGIN_IGP;
    } else if (strcmp(origin_str, "egp") == 0) {
        block->origin = ORIGIN_EGP;
    } else if (strcmp(origin_str, "incomplete") == 0) {
        block->origin = ORIGIN_INCOMPLETE;
    } else {
        fprintf(stderr, "Error: Invalid origin value '%s' " "(must be igp, egp, or incomplete)\n", origin_str);
        return -1;
    }

    return 0;
}

/*
 * Parse: distinguisher [rotate] <value1> [<value2> ...] OR distinguisher [rotate] <base> x <count>
 */
int bgp_ribout_parse_distinguisher(bgp_ribout_config_t *block, const char *line) {
    char    plain[2048];
    uint8_t rotate;

    bgp_ribout_take_rotate(line, "distinguisher", plain, sizeof(plain), &rotate);
    if (bgp_ribout_parse_u32_list_or_sequence(plain, "distinguisher", &block->distinguishers, &block->distinguishers_capacity, &block->distinguishers_step,
                                              &block->distinguisher_count, UINT32_MAX, UINT32_MAX,
                                              "SR Policy distinguisher") < 0) {
        return -1;
    }
    block->distinguisher_rotate = rotate;
    return 0;
}

/*
 * RFC 9830 CO bits by Color-Only type 0-3.
 */
static const char *const bgp_ribout_co_bits[] = {"00", "01", "10", "11"};

/*
 * Parse the CO bits "00", "01", "10" or "11" into the Color-Only type 0-3.
 */
static int bgp_ribout_parse_co_bits(const char *text, uint8_t *co_out) {
    for (uint8_t i = 0; i < 4; i++) {
        if (text && strcmp(text, bgp_ribout_co_bits[i]) == 0) {
            *co_out = i;
            return 0;
        }
    }
    return -1;
}

/*
 * Text of a Color-Only type; only its two low bits count.
 */
const char *bgp_ribout_co_bits_text(uint8_t co_type) {
    return bgp_ribout_co_bits[co_type & 0x3u];
}

/*
 * Parse: color <c> [co <bits>] [<c> [co <bits>]]...
 *        color <base> x <count> [co <bits>]
 *        color range(<a>,<b>) [co <bits>]
 * In an SR Policy block the values are the Policy Color of the NLRI, one NLRI per color, or with "color rotate ..."
 * one color per path in turn. In any other family each path carries one Color community, and the values rotate
 * either way. "co" after a value sets the CO type of that value; at the end of a sequence or a range it sets the type
 * of every value. "color set ..." puts the entire list on every path instead of rotating it.
 * The CO type and set mode are valid only for Color communities, never for an SR Policy NLRI.
 */
int bgp_ribout_parse_color(bgp_ribout_config_t *block, const char *line) {
    char     buffer[2048];
    char     values_line[2048];
    uint8_t  co_by_value[1024];  /* Explicit tokens are bounded by the input line, not the generated count. */
    uint32_t value_tokens = 0;
    int      co_for_all = -1;
    int      sequence;
    int      has_co = 0;
    uint8_t  rotate;
    int      set = 0;
    char    *ptr;

    bgp_ribout_take_rotate(line, "color", buffer, sizeof(buffer), &rotate);
    ptr = strstr(buffer, "color");
    if (!ptr) {
        fprintf(stderr, "Error: Missing 'color' keyword\n");
        return -1;
    }
    ptr += strlen("color");
    ptr = (char *)ribout_skip_space(ptr);
    if (!strncmp(ptr, "set", 3) && (!ptr[3] || isspace((unsigned char)ptr[3]))) {
        set = 1;
        ptr += 3;
    }
    if (set && (rotate || block->address_family_safi == SAFI_SR_POLICY)) {
        fprintf(stderr, "Error: color set is a fixed community set, not an SR Policy color or rotating list\n");
        return -1;
    }
    sequence = (strstr(ptr, " x ") != NULL || strstr(ptr, "range") != NULL);
    memset(co_by_value, 0, sizeof(co_by_value));
    snprintf(values_line, sizeof(values_line), "color");

    // Take the "co <bits>" pairs out; the rest goes to the shared value parser.
    for (char *token = strtok(ptr, " \t\n"); token; token = strtok(NULL, " \t\n")) {
        size_t used = strlen(values_line);

        if (strcmp(token, "co") == 0) {
            uint8_t co;

            if (value_tokens == 0 || co_for_all >= 0 || bgp_ribout_parse_co_bits(strtok(NULL, " \t\n"), &co) < 0) {
                fprintf(stderr, "Error: Invalid color CO bits. Expected: <color> co 00|01|10|11\n");
                return -1;
            }
            if (sequence) {
                co_for_all = co;
            } else {
                co_by_value[value_tokens - 1] = co;
            }
            has_co |= (co != BGP_COLOR_CO_SPECIFIC);
            continue;
        }
        if (co_for_all >= 0) {
            fprintf(stderr, "Error: co must end a color sequence or range\n");
            return -1;
        }
        if (value_tokens >= sizeof(co_by_value) || used + 1 + strlen(token) >= sizeof(values_line)) {
            fprintf(stderr, "Error: Color value list exceeds the command length\n");
            return -1;
        }
        snprintf(values_line + used, sizeof(values_line) - used, " %s", token);
        value_tokens++;
    }

    if (has_co && block->address_family_safi == SAFI_SR_POLICY) {
        fprintf(stderr, "Error: co is valid only for a Color community, not for an SR Policy color\n");
        return -1;
    }
    if (bgp_ribout_parse_u32_list_or_sequence(values_line, "color", &block->colors, &block->colors_capacity, &block->colors_step,
                                              &block->color_count, set ? MAX_EXT_COMMS_PER_ROUTE : UINT32_MAX, UINT32_MAX,
                                              "color") < 0) {
        return -1;
    }
    uint32_t stored = block->colors_step ? 1 : block->color_count;
    if (reserve_color_co(block, stored) < 0) return -1;
    for (uint32_t i = 0; i < stored; i++) {
        block->color_co[i] = (co_for_all >= 0) ? (uint8_t)co_for_all : (sequence ? 0 : co_by_value[i]);
    }
    block->color_rotate = rotate;
    block->color_set = (uint8_t)set;
    return 0;
}

/*
 * Parse: endpoint [rotate] <IP> [x <count>]
 */
int bgp_ribout_parse_endpoint(bgp_ribout_config_t *block, const char *line) {
    const char              *ip_str;
    char                     plain[256];
    uint8_t                  rotate;
    bgp_ribout_value_count_t words;

    bgp_ribout_take_rotate(line, "endpoint", plain, sizeof(plain), &rotate);
    if (bgp_ribout_split_value_count(plain, "endpoint", &words) < 0 || bgp_ribout_no_rest(&words, "endpoint") < 0) {
        return -1;
    }
    ip_str = words.value;
    block->endpoint_spec.count = words.count;
    block->endpoint_spec.has_link_local = 0;
    memset(&block->endpoint_spec.link_local, 0, sizeof(block->endpoint_spec.link_local));

    if (inet_pton(AF_INET, ip_str, &block->endpoint_spec.base_addr.ipv4) == 1) {
        block->endpoint_spec.af = AF_INET;
    } else if (inet_pton(AF_INET6, ip_str, &block->endpoint_spec.base_addr.ipv6) == 1) {
        block->endpoint_spec.af = AF_INET6;
    } else {
        fprintf(stderr, "Error: Invalid SR Policy endpoint address: %s\n", ip_str);
        return -1;
    }
    block->endpoint_rotate = rotate;

    return 0;
}

/*
 * Parse: enlp <values...> | range(A,B) | rand(N) | randrange(A,B)
 */
int bgp_ribout_parse_enlp(bgp_ribout_config_t *block, const char *line) {
    char          *ptr;
    bgp_u32_spec_t spec = {0};
    int            matched = 0;

    ptr = strstr(line, "enlp");
    if (!ptr) {
        fprintf(stderr, "Error: Missing 'enlp' keyword\n");
        return -1;
    }
    ptr += strlen("enlp");

    if (bgp_ribout_parse_u32_scalar_expr(ptr,
                                         "SR ENLP",
                                         1,
                                         4,
                                         0,
                                         &spec,
                                         &matched) < 0) {
        return -1;
    }
    if (matched) {
        block->enlp_count = 0;
        free(block->enlps);
        block->enlps = NULL;
        block->enlps_capacity = 0;
        block->enlps_step = 0;
        block->enlp_spec.enabled = 1;
        block->enlp_spec.mode = spec.mode;
        block->enlp_spec.value = spec.value;
        block->enlp_spec.range_start = spec.range_start;
        block->enlp_spec.range_end = spec.range_end;
        return 0;
    }

    ribout_u32_opt_disable(&block->enlp_spec);
    if (bgp_ribout_parse_u32_list_or_sequence(line,
                                              "enlp",
                                              &block->enlps, &block->enlps_capacity, &block->enlps_step,
                                              &block->enlp_count, UINT32_MAX,
                                              4,
                                              "SR ENLP") < 0) {
        return -1;
    }

    for (uint32_t i = 0; i < block->enlp_count; i++) {
        if (bgp_ribout_enlps_at(block, i) < 1 || bgp_ribout_enlps_at(block, i) > 4) {
            fprintf(stderr, "Error: SR ENLP must be 1-4\n");
            return -1;
        }
    }

    return 0;
}

/*
 * Parse: priority <values...> | range(A,B) | rand(N) | randrange(A,B)
 */
int bgp_ribout_parse_priority(bgp_ribout_config_t *block, const char *line) {
    char          *ptr;
    bgp_u32_spec_t spec = {0};
    int            matched = 0;

    ptr = strstr(line, "priority");
    if (!ptr) {
        fprintf(stderr, "Error: Missing 'priority' keyword\n");
        return -1;
    }
    ptr += strlen("priority");

    if (bgp_ribout_parse_u32_scalar_expr(ptr,
                                         "SR priority",
                                         0,
                                         255,
                                         0,
                                         &spec,
                                         &matched) < 0) {
        return -1;
    }
    if (matched) {
        block->priority_count = 0;
        free(block->priorities);
        block->priorities = NULL;
        block->priorities_capacity = 0;
        block->priorities_step = 0;
        block->priority_spec.enabled = 1;
        block->priority_spec.mode = spec.mode;
        block->priority_spec.value = spec.value;
        block->priority_spec.range_start = spec.range_start;
        block->priority_spec.range_end = spec.range_end;
        return 0;
    }

    ribout_u32_opt_disable(&block->priority_spec);
    return bgp_ribout_parse_u32_list_or_sequence(line,
                                                 "priority",
                                                 &block->priorities, &block->priorities_capacity, &block->priorities_step,
                                              &block->priority_count, UINT32_MAX,
                                                 255,
                                                 "SR priority");
}

/*
 * Parse: preference <values...> | range(A,B) | rand(N) | randrange(A,B)
 */
int bgp_ribout_parse_preference(bgp_ribout_config_t *block, const char *line) {
    char          *ptr;
    bgp_u32_spec_t spec = {0};
    int            matched = 0;

    ptr = strstr(line, "preference");
    if (!ptr) {
        fprintf(stderr, "Error: Missing 'preference' keyword\n");
        return -1;
    }
    ptr += strlen("preference");

    if (bgp_ribout_parse_u32_scalar_expr(ptr,
                                         "SR Policy preference",
                                         0,
                                         UINT32_MAX,
                                         0,
                                         &spec,
                                         &matched) < 0) {
        return -1;
    }
    if (matched) {
        block->preference_count = 0;
        free(block->preferences);
        block->preferences = NULL;
        block->preferences_capacity = 0;
        block->preferences_step = 0;
        block->preference_spec.enabled = 1;
        block->preference_spec.mode = spec.mode;
        block->preference_spec.value = spec.value;
        block->preference_spec.range_start = spec.range_start;
        block->preference_spec.range_end = spec.range_end;
        return 0;
    }

    ribout_u32_opt_disable(&block->preference_spec);
    return bgp_ribout_parse_u32_list_or_sequence(line,
                                                 "preference",
                                                 &block->preferences, &block->preferences_capacity, &block->preferences_step,
                                              &block->preference_count, UINT32_MAX,
                                                 UINT32_MAX,
                                                 "SR Policy preference");
}

/*
 * Parse: binding-sid mpls <labels...> | range(A,B) | rand(N) | randrange(A,B)
 *     or binding-sid srv6 <sid> [x <count>]
 */
int bgp_ribout_parse_binding_sid(bgp_ribout_config_t *block, const char *line) {
    char           line_copy[2048];
    char          *ptr;
    char           sid_str[64];
    bgp_u32_spec_t spec = {0};
    int            matched = 0;
    uint32_t       count = 1;

    strncpy(line_copy, line, sizeof(line_copy) - 1);
    line_copy[sizeof(line_copy) - 1] = '\0';

    ptr = strstr(line_copy, "binding-sid");
    if (!ptr) {
        fprintf(stderr, "Error: Missing 'binding-sid' keyword\n");
        return -1;
    }
    ptr += strlen("binding-sid");
    ptr = str_trim(ptr);

    if (strncmp(ptr, "srv6", 4) == 0 && isspace((unsigned char)ptr[4])) {
        ptr += 4;
        ptr = str_trim(ptr);

        char                     srv6_line[256];
        bgp_ribout_value_count_t words;

        snprintf(srv6_line, sizeof(srv6_line), "srv6 %s", ptr);
        if (bgp_ribout_split_value_count(srv6_line, "srv6", &words) < 0 ||
            bgp_ribout_no_rest(&words, "binding-sid srv6") < 0) {
            return -1;
        }
        snprintf(sid_str, sizeof(sid_str), "%s", words.value);
        count = words.count;

        memset(&block->binding_sid_srv6_spec, 0, sizeof(block->binding_sid_srv6_spec));
        if (inet_pton(AF_INET6, sid_str,
                      &block->binding_sid_srv6_spec.base_addr.ipv6) != 1) {
            fprintf(stderr, "Error: Invalid SRv6 Binding SID: %s\n", sid_str);
            return -1;
        }

        block->binding_sid_srv6_spec.af = AF_INET6;
        block->binding_sid_srv6_spec.count = count;
        block->binding_sid_srv6_spec.has_link_local = 0;
        memset(&block->binding_sid_srv6_spec.link_local, 0, sizeof(block->binding_sid_srv6_spec.link_local));
        block->binding_sid_kind = BGP_RIBOUT_SR_BINDING_SID_SRV6;
        ribout_u32_opt_disable(&block->binding_sid_spec);
        block->binding_sid_count = 0;
        free(block->binding_sids);
        block->binding_sids = NULL;
        block->binding_sids_capacity = 0;
        block->binding_sids_step = 0;
        return 0;
    }

    if (strncmp(ptr, "mpls", 4) != 0 || !isspace((unsigned char)ptr[4])) {
        fprintf(stderr, "Error: binding-sid requires 'mpls' or 'srv6'\n");
        return -1;
    }
    ptr += 4;
    ptr = str_trim(ptr);

    if (bgp_ribout_parse_u32_scalar_expr(ptr,
                                         "binding-sid",
                                         0,
                                         0xFFFFFU,
                                         0,
                                         &spec,
                                         &matched) < 0) {
        return -1;
    }
    if (matched) {
        block->binding_sid_count = 0;
        free(block->binding_sids);
        block->binding_sids = NULL;
        block->binding_sids_capacity = 0;
        block->binding_sids_step = 0;
        block->binding_sid_spec.enabled = 1;
        block->binding_sid_spec.mode = spec.mode;
        block->binding_sid_spec.value = spec.value;
        block->binding_sid_spec.range_start = spec.range_start;
        block->binding_sid_spec.range_end = spec.range_end;
        memset(&block->binding_sid_srv6_spec, 0, sizeof(block->binding_sid_srv6_spec));
        block->binding_sid_kind = BGP_RIBOUT_SR_BINDING_SID_MPLS;
        return 0;
    }

    ribout_u32_opt_disable(&block->binding_sid_spec);

    {
        char rewritten[2048];

        snprintf(rewritten, sizeof(rewritten), "binding-sid %s", ptr);
        if (bgp_ribout_parse_u32_list_or_sequence(rewritten,
                                                  "binding-sid",
                                                  &block->binding_sids, &block->binding_sids_capacity, &block->binding_sids_step,
                                              &block->binding_sid_count, UINT32_MAX,
                                                  0xFFFFFU,
                                                  "binding SID") < 0) {
            return -1;
        }
    }

    for (uint32_t i = 0; i < block->binding_sid_count; i++) {
        if (!bgp_ribout_label_value_valid(bgp_ribout_binding_sids_at(block, i))) {
            fprintf(stderr, "Error: binding SID must be 0-1048575\n");
            return -1;
        }
    }

    memset(&block->binding_sid_srv6_spec, 0, sizeof(block->binding_sid_srv6_spec));
    block->binding_sid_kind = BGP_RIBOUT_SR_BINDING_SID_MPLS;

    return 0;
}

/*
 * Parse: segment-list <id> weight <u32> mpls <label...>
 *     or segment-list <id> weight <u32> srv6 <sid>
 *          [behavior <u16> [structure <lb> <ln> <fn> <arg>]] ...
 */
int bgp_ribout_parse_segment_list(bgp_ribout_config_t *block, const char *line) {
    char                          buffer[2048];
    char                         *ptr;
    char                         *token;
    uint32_t                      list_id;
    uint32_t                      weight;
    bgp_ribout_sr_segment_list_t *list;

    strncpy(buffer, line, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    ptr = strstr(buffer, "segment-list");
    if (!ptr) {
        fprintf(stderr, "Error: Missing 'segment-list' keyword\n");
        return -1;
    }
    ptr += strlen("segment-list");
    ptr = str_trim(ptr);

    token = strtok(ptr, " \t\n");
    if (!token) {
        fprintf(stderr, "Error: segment-list requires an identifier\n");
        return -1;
    }
    if (bgp_ribout_parse_field(token, UINT32_MAX, &list_id) < 0) {
        fprintf(stderr, "Error: Invalid segment-list identifier: %s (0-%u)\n", token, UINT32_MAX);
        return -1;
    }

    for (uint32_t i = 0; i < block->segment_list_count; i++) {
        if (block->segment_lists[i].id == list_id) {
            fprintf(stderr, "Error: Duplicate segment-list identifier: %u\n", list_id);
            return -1;
        }
    }

    token = strtok(NULL, " \t\n");
    if (!token || strcmp(token, "weight") != 0) {
        fprintf(stderr, "Error: segment-list requires 'weight <value>'\n");
        return -1;
    }

    token = strtok(NULL, " \t\n");
    if (!token) {
        fprintf(stderr, "Error: segment-list requires a weight value\n");
        return -1;
    }
    if (bgp_ribout_parse_count(token, UINT32_MAX, &weight) < 0) {
        fprintf(stderr, "Error: Invalid segment-list weight: %s (1-%u)\n", token, UINT32_MAX);
        return -1;
    }

    token = strtok(NULL, " \t\n");
    if (!token || (strcmp(token, "mpls") != 0 && strcmp(token, "srv6") != 0)) {
        fprintf(stderr, "Error: segment-list requires 'mpls' or 'srv6'\n");
        return -1;
    }

    if (reserve_segment_lists(block, block->segment_list_count + 1) < 0) return -1;
    list = &block->segment_lists[block->segment_list_count];
    memset(list, 0, sizeof(*list));
    list->id = list_id;
    list->weight = weight;

    if (strcmp(token, "mpls") == 0) {
        while ((token = strtok(NULL, " \t\n")) != NULL) {
            uint32_t label;
            uint32_t label_net;

            if (bgp_ribout_parse_field(token, 0xFFFFFFFFu, &label) < 0 || !bgp_ribout_label_value_valid(label)) {
                fprintf(stderr, "Error: Invalid segment-list MPLS label %s: must be 0-1048575\n", token);
                return -1;
            }
            if (list->segment_count >= MAX_SR_SEGMENTS_PER_LIST) {
                fprintf(stderr, "Error: Too many segments in segment-list (max %d)\n", MAX_SR_SEGMENTS_PER_LIST);
                return -1;
            }

            memset(&list->segments[list->segment_count], 0, sizeof(list->segments[list->segment_count]));
            list->segments[list->segment_count].type = SR_SEGMENT_TYPE_MPLS;
            label_net = htonl((uint32_t)label);
            memcpy(list->segments[list->segment_count].sid, &label_net, sizeof(label_net));
            list->segment_count++;
        }
    } else {
        srpolicy_segment_t *current_segment = NULL;
        int                 current_segment_has_structure = 0;

        while ((token = strtok(NULL, " \t\n")) != NULL) {
            if (strcmp(token, "behavior") == 0) {
                uint64_t behavior;

                if (!current_segment) {
                    fprintf(stderr, "Error: behavior requires a preceding SRv6 SID\n");
                    return -1;
                }
                if (current_segment->has_srv6_behavior) {
                    fprintf(stderr, "Error: duplicate behavior for SRv6 segment-list SID\n");
                    return -1;
                }

                token = strtok(NULL, " \t\n");
                if (!token) {
                    fprintf(stderr, "Error: behavior requires an endpoint behavior value\n");
                    return -1;
                }
                if (bgp_ribout_parse_u64_number(token, 0, &behavior) < 0 ||
                    behavior > 0xFFFFUL) {
                    fprintf(stderr, "Error: Invalid SRv6 endpoint behavior: %s\n", token);
                    return -1;
                }

                current_segment->has_srv6_behavior = 1;
                current_segment->srv6_behavior.endpoint_behavior =
                    (uint16_t)behavior;
                current_segment->srv6_behavior.locator_block_len = 0;
                current_segment->srv6_behavior.locator_node_len = 0;
                current_segment->srv6_behavior.function_len = 0;
                current_segment->srv6_behavior.argument_len = 0;
                current_segment_has_structure = 0;
                continue;
            }

            if (strcmp(token, "structure") == 0) {
                uint32_t locator_block_len;
                uint32_t locator_node_len;
                uint32_t function_len;
                uint32_t argument_len;

                if (!current_segment || !current_segment->has_srv6_behavior) {
                    fprintf(stderr, "Error: structure requires a preceding behavior clause\n");
                    return -1;
                }
                if (current_segment_has_structure) {
                    fprintf(stderr, "Error: duplicate structure for SRv6 segment-list SID\n");
                    return -1;
                }

                token = strtok(NULL, " \t\n");
                if (!token) {
                    fprintf(stderr, "Error: structure requires 4 length values\n");
                    return -1;
                }
                if (bgp_ribout_parse_field(token, 128, &locator_block_len) < 0) {
                    fprintf(stderr, "Error: Invalid locator-block length: %s\n", token);
                    return -1;
                }

                token = strtok(NULL, " \t\n");
                if (!token) {
                    fprintf(stderr, "Error: structure requires 4 length values\n");
                    return -1;
                }
                if (bgp_ribout_parse_field(token, 128, &locator_node_len) < 0) {
                    fprintf(stderr, "Error: Invalid locator-node length: %s\n", token);
                    return -1;
                }

                token = strtok(NULL, " \t\n");
                if (!token) {
                    fprintf(stderr, "Error: structure requires 4 length values\n");
                    return -1;
                }
                if (bgp_ribout_parse_field(token, 128, &function_len) < 0) {
                    fprintf(stderr, "Error: Invalid function length: %s\n", token);
                    return -1;
                }

                token = strtok(NULL, " \t\n");
                if (!token) {
                    fprintf(stderr, "Error: structure requires 4 length values\n");
                    return -1;
                }
                if (bgp_ribout_parse_field(token, 128, &argument_len) < 0) {
                    fprintf(stderr, "Error: Invalid argument length: %s\n", token);
                    return -1;
                }

                if (!bgp_ribout_srv6_structure_valid((uint32_t)locator_block_len,
                                                     (uint32_t)locator_node_len,
                                                     (uint32_t)function_len,
                                                     (uint32_t)argument_len)) {
                    fprintf(stderr, "Error: SRv6 structure lengths must sum to 128 bits or less\n");
                    return -1;
                }

                current_segment->srv6_behavior.locator_block_len =
                    (uint8_t)locator_block_len;
                current_segment->srv6_behavior.locator_node_len =
                    (uint8_t)locator_node_len;
                current_segment->srv6_behavior.function_len =
                    (uint8_t)function_len;
                current_segment->srv6_behavior.argument_len =
                    (uint8_t)argument_len;
                current_segment_has_structure = 1;
                continue;
            }

            if (list->segment_count >= MAX_SR_SEGMENTS_PER_LIST) {
                fprintf(stderr, "Error: Too many segments in segment-list (max %d)\n", MAX_SR_SEGMENTS_PER_LIST);
                return -1;
            }
            current_segment = &list->segments[list->segment_count];
            memset(current_segment, 0, sizeof(*current_segment));
            if (inet_pton(AF_INET6, token, current_segment->sid) != 1) {
                fprintf(stderr, "Error: Invalid segment-list SRv6 SID: %s\n", token);
                return -1;
            }

            current_segment->type = SR_SEGMENT_TYPE_SRV6;
            current_segment_has_structure = 0;
            list->segment_count++;
        }
    }

    if (list->segment_count == 0) {
        fprintf(stderr, "Error: segment-list requires at least one segment\n");
        return -1;
    }

    block->segment_list_count++;
    return 0;
}

// Component keywords

typedef struct {
    const char *keyword;
    uint8_t     type;
    uint8_t     bitmask;  /* bitmask_op (RFC 8955 4.2.1.2), else numeric_op */
} bgp_ribout_flowspec_component_kw_t;

#define BGP_RIBOUT_FLOWSPEC_COMPONENT_ROW(id, kw, type, bitmask, help) {kw, type, bitmask},
static const bgp_ribout_flowspec_component_kw_t bgp_ribout_flowspec_op_components[] = {
    BGP_RIBOUT_FLOWSPEC_OP_COMPONENTS(BGP_RIBOUT_FLOWSPEC_COMPONENT_ROW)
};
#undef BGP_RIBOUT_FLOWSPEC_COMPONENT_ROW

#define BGP_RIBOUT_FLOWSPEC_OP_COMPONENT_COUNT \
    (sizeof(bgp_ribout_flowspec_op_components) / sizeof(bgp_ribout_flowspec_op_components[0]))

/*
 * Operator component with this keyword ("protocol", "dst-port", ...), or NULL.
 */
static const bgp_ribout_flowspec_component_kw_t *bgp_ribout_flowspec_component_by_keyword(const char *keyword) {
    for (size_t i = 0; i < BGP_RIBOUT_FLOWSPEC_OP_COMPONENT_COUNT; i++) {
        if (strcmp(bgp_ribout_flowspec_op_components[i].keyword, keyword) == 0) {
            return &bgp_ribout_flowspec_op_components[i];
        }
    }
    return NULL;
}

/*
 * Operator component with this type (3-13), or NULL.
 */
static const bgp_ribout_flowspec_component_kw_t *bgp_ribout_flowspec_component_by_type(uint8_t type) {
    for (size_t i = 0; i < BGP_RIBOUT_FLOWSPEC_OP_COMPONENT_COUNT; i++) {
        if (bgp_ribout_flowspec_op_components[i].type == type) {
            return &bgp_ribout_flowspec_op_components[i];
        }
    }
    return NULL;
}

/*
 * Config keyword of a component type, prefix types included; NULL for an unknown type.
 */
const char *bgp_ribout_flowspec_component_keyword(uint8_t type) {
    const bgp_ribout_flowspec_component_kw_t *kw;

    if (type == FLOWSPEC_DEST_PREFIX) {
        return "dst-prefix";
    }
    if (type == FLOWSPEC_SRC_PREFIX) {
        return "src-prefix";
    }
    kw = bgp_ribout_flowspec_component_by_type(type);
    return kw ? kw->keyword : NULL;
}

/*
 * Bitmask names: TCP flags (RFC 9293 control bits) and fragment bits
 * (RFC 8955 section 4.2.2.12).
 */
typedef struct {
    const char *name;
    uint32_t    bit;
} bgp_ribout_flowspec_bit_name_t;

static const bgp_ribout_flowspec_bit_name_t bgp_ribout_flowspec_tcp_flag_names[] = {
    {"fin", FLOWSPEC_TCP_FIN}, {"syn", FLOWSPEC_TCP_SYN}, {"rst", FLOWSPEC_TCP_RST},
    {"psh", FLOWSPEC_TCP_PSH}, {"ack", FLOWSPEC_TCP_ACK}, {"urg", FLOWSPEC_TCP_URG},
    {"ece", FLOWSPEC_TCP_ECE}, {"cwr", FLOWSPEC_TCP_CWR},
};

static const bgp_ribout_flowspec_bit_name_t bgp_ribout_flowspec_fragment_names[] = {
    {"df", FLOWSPEC_FRAG_DF}, {"isf", FLOWSPEC_FRAG_ISF},
    {"ff", FLOWSPEC_FRAG_FF}, {"lf", FLOWSPEC_FRAG_LF},
};

/*
 * Flag names of a bitmask component: TCP flags for type 9, else the fragment bits.
 */
static const bgp_ribout_flowspec_bit_name_t *bgp_ribout_flowspec_bit_names(uint8_t type, size_t *count) {
    if (type == FLOWSPEC_TCP_FLAGS) {
        *count = sizeof(bgp_ribout_flowspec_tcp_flag_names) / sizeof(bgp_ribout_flowspec_tcp_flag_names[0]);
        return bgp_ribout_flowspec_tcp_flag_names;
    }
    *count = sizeof(bgp_ribout_flowspec_fragment_names) / sizeof(bgp_ribout_flowspec_fragment_names[0]);
    return bgp_ribout_flowspec_fragment_names;
}

// The FlowSpec part of a block

/*
 * Most ribouts have no FlowSpec line, so the FlowSpec part is allocated on first use.
 */
bgp_ribout_flowspec_t *bgp_ribout_flowspec_get(bgp_ribout_config_t *block) {
    if (!block->flowspec) {
        block->flowspec = calloc(1, sizeof(*block->flowspec));
        if (!block->flowspec) {
            fprintf(stderr, "Error: Out of memory for FlowSpec lines\n");
        }
    }
    return block->flowspec;
}

/*
 * A FlowSpec-only line makes the block FlowSpec; "prefix" alone does not, because it is also the unicast prefix.
 */
int bgp_ribout_has_flowspec_tokens(const bgp_ribout_config_t *block) {
    const bgp_ribout_flowspec_t *fs = block ? block->flowspec : NULL;

    if (!fs) {
        return 0;
    }
    return fs->src_prefix.count > 0 || fs->actions.line_count > 0 || fs->set_count > 0;
}

/*
 * Operator expressions
 *
 *   expr  := term { " " term }      space = OR
 *   term  := cmp { "&" cmp }        "&"   = AND
 *   numeric cmp := [!=|<|<=|>|>=] value[:width] | true | false
 *                  (a bare value means equal)
 *   bitmask cmp := [!] bits | [!] any(bits)      bits := flag{+flag} | value [:width]
 *                  (bits: all of them set; any(bits): at least one set)
 *   values are decimal
 *
 * The first pair of each term has the AND bit clear; the last pair of the
 * whole list has the end-of-list bit (RFC 8955 section 4.2.1).
 */

/*
 * Operator length bits for a value width of 1, 2, 4 or 8 octets (RFC 8955 section 4.2.1).
 */
static uint8_t bgp_ribout_flowspec_len_bits(unsigned width) {
    switch (width) {
        case 1:  return FLOWSPEC_OP_LEN_1;
        case 2:  return FLOWSPEC_OP_LEN_2;
        case 4:  return FLOWSPEC_OP_LEN_4;
        default: return FLOWSPEC_OP_LEN_8;
    }
}

/*
 * Value width in octets that an operator byte gives.
 */
static unsigned bgp_ribout_flowspec_op_width(uint8_t op) {
    return 1u << ((op >> 4) & 0x03);
}

/*
 * Smallest width (1, 2 or 4 octets) that holds value.
 */
static unsigned bgp_ribout_flowspec_auto_width(uint32_t value) {
    return (value <= 0xFFu) ? 1 : (value <= 0xFFFFu) ? 2 : 4;
}

/*
 * Split "<value>[:width]"; returns -1 on a bad width.
 */
static int bgp_ribout_flowspec_split_width(char *text, unsigned *width_out) {
    char    *colon = strchr(text, ':');
    uint32_t width;

    *width_out = 0;
    if (!colon) {
        return 0;
    }
    *colon = '\0';
    if (bgp_ribout_parse_field(colon + 1, 8, &width) < 0 || (width != 1 && width != 2 && width != 4 && width != 8)) {
        return -1;
    }
    *width_out = width;
    return 0;
}

/*
 * Parse a decimal number up to 2^32 - 1.
 */
static int bgp_ribout_flowspec_parse_u32(const char *text, uint32_t *value_out) {
    uint64_t value;

    if (bgp_ribout_parse_u64_decimal(text, &value) < 0 || value > UINT32_MAX) {
        return -1;
    }
    *value_out = (uint32_t)value;
    return 0;
}

/*
 * Parse one numeric comparison ("80", "<=1500:2", "!=5", "true", "false") into an operator/value pair with the AND
 * and end bits clear. A bare value means equal.
 */
static int bgp_ribout_flowspec_parse_numeric_cmp(char *text, flowspec_op_value_t *ov) {
    static const struct {
        const char *prefix;
        uint8_t     bits;
    } cmps[] = {
        {"!=", FLOWSPEC_OP_LT | FLOWSPEC_OP_GT},
        {"<=", FLOWSPEC_OP_LT | FLOWSPEC_OP_EQ},
        {">=", FLOWSPEC_OP_GT | FLOWSPEC_OP_EQ},
        {"<",  FLOWSPEC_OP_LT},
        {">",  FLOWSPEC_OP_GT},
        {"",   FLOWSPEC_OP_EQ},
    };
    unsigned width;

    if (strcmp(text, "true") == 0 || strcmp(text, "false") == 0) {
        ov->op = (uint8_t)(FLOWSPEC_OP_LEN_1 |
                           (text[0] == 't' ? (FLOWSPEC_OP_LT | FLOWSPEC_OP_GT | FLOWSPEC_OP_EQ) : 0));
        ov->value = 0;
        return 0;
    }

    for (size_t i = 0; i < sizeof(cmps) / sizeof(cmps[0]); i++) {
        size_t n = strlen(cmps[i].prefix);

        if (strncmp(text, cmps[i].prefix, n) == 0) {
            char *value_text = text + n;

            if (!isdigit((unsigned char)value_text[0]) ||
                bgp_ribout_flowspec_split_width(value_text, &width) < 0 ||
                bgp_ribout_flowspec_parse_u32(value_text, &ov->value) < 0) {
                return -1;
            }
            if (width == 0) {
                width = bgp_ribout_flowspec_auto_width(ov->value);
            }
            ov->op = (uint8_t)(bgp_ribout_flowspec_len_bits(width) | cmps[i].bits);
            return 0;
        }
    }

    return -1;
}

/*
 * strtok_r() skips empty fields; "a&&b", "&a", "a+" must not parse as "a&b", "a".
 */
static int bgp_ribout_flowspec_has_empty_field(const char *text, char sep) {
    size_t len = strlen(text);
    char   pair[3] = {sep, sep, '\0'};

    return len == 0 || text[0] == sep || text[len - 1] == sep || strstr(text, pair) != NULL;
}

/*
 * Parse one bitmask comparison ("syn+ack", "!rst", "any(fin+syn)", "!any(18):2") for component type into an
 * operator/value pair with the AND and end bits clear. Bare bits set the match bit (all of them set); any(...) leaves
 * it clear (at least one set) (RFC 8955 section 4.2.1.2).
 */
static int bgp_ribout_flowspec_parse_bitmask_cmp(char *text, uint8_t type, flowspec_op_value_t *ov) {
    uint8_t                               bits = FLOWSPEC_OP_MATCH;
    unsigned                              width;
    uint32_t                              value = 0;
    size_t                                name_count;
    const bgp_ribout_flowspec_bit_name_t *names = bgp_ribout_flowspec_bit_names(type, &name_count);

    if (*text == '!') {
        bits |= FLOWSPEC_OP_NOT;
        text++;
    }
    if (bgp_ribout_flowspec_split_width(text, &width) < 0 || *text == '\0') {
        return -1;
    }
    if (strncmp(text, "any(", 4) == 0) {
        size_t len = strlen(text);

        if (len < 6 || text[len - 1] != ')') {
            return -1;
        }
        text[len - 1] = '\0';
        text += 4;
        bits &= (uint8_t)~FLOWSPEC_OP_MATCH;
    }

    if (bgp_ribout_flowspec_parse_u32(text, &value) < 0) {
        char *save = NULL;

        if (bgp_ribout_flowspec_has_empty_field(text, '+')) {
            return -1;
        }
        value = 0;
        for (char *flag = strtok_r(text, "+", &save); flag; flag = strtok_r(NULL, "+", &save)) {
            size_t i;

            for (i = 0; i < name_count; i++) {
                if (strcmp(flag, names[i].name) == 0) {
                    value |= names[i].bit;
                    break;
                }
            }
            if (i == name_count) {
                return -1;
            }
        }
    }

    if (width == 0) {
        width = bgp_ribout_flowspec_auto_width(value);
    }
    ov->op = (uint8_t)(bgp_ribout_flowspec_len_bits(width) | bits);
    ov->value = value;
    return 0;
}

/*
 * Parse a whole expression into an operator list: terms split by spaces (OR), comparisons in a term split by "&"
 * (AND). Sets the AND bit on all but the first comparison of a term and the end bit on the last pair (RFC 8955 section
 * 4.2.1). Returns -1 with an error for bad text or too many comparisons.
 */
static int bgp_ribout_flowspec_parse_expression(const char *args, const bgp_ribout_flowspec_component_kw_t *kw,
                                                bgp_ribout_flowspec_ops_t *ops_out) {
    char                      buffer[512];
    char                     *term_save = NULL;
    bgp_ribout_flowspec_ops_t ops;

    memset(&ops, 0, sizeof(ops));
    if (!args || strlen(args) >= sizeof(buffer)) {
        return -1;
    }
    snprintf(buffer, sizeof(buffer), "%s", args);

    for (char *term = strtok_r(buffer, " \t", &term_save); term; term = strtok_r(NULL, " \t", &term_save)) {
        char *cmp_save = NULL;
        int   first_in_term = 1;

        if (bgp_ribout_flowspec_has_empty_field(term, '&')) {
            fprintf(stderr, "Error: Invalid %s operator: %s\n", kw->keyword, term);
            return -1;
        }
        for (char *cmp = strtok_r(term, "&", &cmp_save); cmp; cmp = strtok_r(NULL, "&", &cmp_save)) {
            flowspec_op_value_t *ov;

            if (ops.num_values >= MAX_FLOWSPEC_OPS) {
                fprintf(stderr, "Error: %s takes at most %d operators\n", kw->keyword, MAX_FLOWSPEC_OPS);
                return -1;
            }
            ov = &ops.values[ops.num_values];
            if ((kw->bitmask ? bgp_ribout_flowspec_parse_bitmask_cmp(cmp, kw->type, ov) :
                               bgp_ribout_flowspec_parse_numeric_cmp(cmp, ov)) < 0) {
                fprintf(stderr, "Error: Invalid %s operator: %s\n", kw->keyword, cmp);
                return -1;
            }
            if (!first_in_term) {
                ov->op |= FLOWSPEC_OP_AND;
            }
            first_in_term = 0;
            ops.num_values++;
        }
    }

    if (ops.num_values == 0) {
        fprintf(stderr, "Error: %s needs at least one operator\n", kw->keyword);
        return -1;
    }
    ops.values[ops.num_values - 1].op |= FLOWSPEC_OP_END;

    *ops_out = ops;
    return 0;
}

/*
 * The library owns the RFC rules; a component must encode for one AFI.
 */
static int bgp_ribout_flowspec_ops_valid(uint8_t type, const bgp_ribout_flowspec_ops_t *ops) {
    uint8_t              scratch[1 + MAX_FLOWSPEC_OPS * 9];
    flowspec_component_t comp;

    memset(&comp, 0, sizeof(comp));
    comp.type = type;
    comp.values = (flowspec_op_value_t *)ops->values;
    comp.num_values = ops->num_values;
    return bgp_encode_flowspec_component_afi(scratch, &comp, AFI_IPV4) >= 0 ||
           bgp_encode_flowspec_component_afi(scratch, &comp, AFI_IPV6) >= 0;
}

/*
 * Components
 *
 *   <component> <expr>                  one NLRI
 *   <component> <cmp> x <count>         count NLRIs; the one comparison's value steps by 1
 *   <component> each(<expr>, <expr>...) one NLRI per expression
 */

/*
 * NLRIs that one component makes: its step count or its alternatives; 1 when it is not set.
 */
static uint32_t bgp_ribout_flowspec_component_count(const bgp_ribout_flowspec_component_t *comp) {
    if (comp->alternative_count == 0) {
        return 1;
    }
    return (comp->step_count > 1) ? comp->step_count : comp->alternative_count;
}

/*
 * The operator list of NLRI number index of a component: the stepped value, or one alternative.
 */
static void bgp_ribout_flowspec_component_ops(const bgp_ribout_flowspec_component_t *comp, uint32_t index,
                                              bgp_ribout_flowspec_ops_t *ops_out) {
    if (comp->step_count > 1) {
        *ops_out = comp->alternatives[0];
        ops_out->values[0].value += index;
    } else {
        *ops_out = comp->alternatives[index];
    }
}

/*
 * Decode an instance number into the position of each field: index[1] the destination prefix, index[2] the source
 * prefix, index[3-13] the components. The last component steps fastest, the destination slowest.
 */
static void bgp_ribout_flowspec_decode(const bgp_ribout_config_t *block, uint64_t instance,
                                       uint32_t index[FLOWSPEC_FLOW_LABEL + 1]) {
    const bgp_ribout_flowspec_t *fs = block->flowspec;
    uint32_t                     src_count = fs ? bgp_ribout_effective_count(fs->src_prefix.count) : 1;
    // Generation allows at most 2^32 - 1 instances, and 32-bit division is faster (this runs once per encoded NLRI).
    uint32_t                     rest = (uint32_t)instance;

    memset(index, 0, sizeof(uint32_t) * (FLOWSPEC_FLOW_LABEL + 1));
    for (int i = fs ? (int)fs->set_count - 1 : -1; i >= 0; i--) {
        uint8_t  type = fs->set_types[i];
        uint32_t count = bgp_ribout_flowspec_component_count(&fs->components[type]);

        // Most components have one value; skip the division for them.
        if (count > 1) {
            index[type] = rest % count;
            rest /= count;
        }
    }
    index[FLOWSPEC_SRC_PREFIX] = rest % src_count;
    index[FLOWSPEC_DEST_PREFIX] = rest / src_count;
}

/*
 * Parse "<cmp> x <count>": one numeric comparison whose value steps by 1, count times. All values take the width of
 * the last one, unless the comparison gives a width.
 */
static int bgp_ribout_flowspec_parse_stepped(char *expr, const char *count_text,
                                             const bgp_ribout_flowspec_component_kw_t *kw,
                                             bgp_ribout_flowspec_component_t *comp) {
    bgp_ribout_flowspec_ops_t *ops = &comp->alternatives[0];
    flowspec_op_value_t       *ov = &ops->values[0];
    uint8_t                    cmp;
    uint32_t                   count;

    while (*count_text == ' ') {
        count_text++;
    }
    if (kw->bitmask || bgp_ribout_flowspec_parse_u32(count_text, &count) < 0 || count == 0 ||
        bgp_ribout_flowspec_parse_expression(expr, kw, ops) < 0 || ops->num_values != 1) {
        fprintf(stderr, "Error: %s <value> x <count> needs one numeric comparison and a count\n", kw->keyword);
        return -1;
    }
    cmp = (uint8_t)(ov->op & (FLOWSPEC_OP_LT | FLOWSPEC_OP_GT | FLOWSPEC_OP_EQ));
    if (cmp == 0 || cmp == (FLOWSPEC_OP_LT | FLOWSPEC_OP_GT | FLOWSPEC_OP_EQ) ||
        (uint64_t)ov->value + count - 1 > UINT32_MAX) {
        fprintf(stderr, "Error: %s sequence must step a value that stays within 32 bits\n", kw->keyword);
        return -1;
    }
    if (!strchr(expr, ':')) {
        ov->op = (uint8_t)((ov->op & ~FLOWSPEC_OP_LEN_8) |
                           bgp_ribout_flowspec_len_bits(bgp_ribout_flowspec_auto_width(ov->value + count - 1)));
    }
    comp->alternative_count = 1;
    comp->step_count = count;
    return 0;
}

/*
 * Parse the arguments of an operator component into comp. Every NLRI value must pass the library's RFC checks (for a
 * step, the first and the last value).
 */
static int bgp_ribout_flowspec_parse_component_args(const char *args, const bgp_ribout_flowspec_component_kw_t *kw,
                                                    bgp_ribout_flowspec_component_t *comp) {
    char     buffer[512];
    char    *text = buffer;
    char    *x;
    size_t   len;
    uint32_t count;
    uint8_t  rotate = 0;

    memset(comp, 0, sizeof(*comp));
    if (!args || strlen(args) >= sizeof(buffer)) {
        fprintf(stderr, "Error: Invalid %s arguments\n", kw->keyword);
        return -1;
    }
    snprintf(buffer, sizeof(buffer), "%s", args);
    while (*text == ' ' || *text == '\t') {
        text++;
    }
    // "rotate <values>": the values go one per path in turn instead of one NLRI each.
    if (strncmp(text, "rotate", 6) == 0 && (text[6] == '\0' || isspace((unsigned char)text[6]))) {
        rotate = 1;
        text += 6;
        while (*text == ' ' || *text == '\t') {
            text++;
        }
        if (*text == '\0') {
            fprintf(stderr, "Error: %s rotate needs values\n", kw->keyword);
            return -1;
        }
    }
    len = strlen(text);
    while (len > 0 && (text[len - 1] == ' ' || text[len - 1] == '\t' || text[len - 1] == '\n')) {
        text[--len] = '\0';
    }

    if (strncmp(text, "each(", 5) == 0) {
        char *save = NULL;

        if (len < 7 || text[len - 1] != ')') {
            fprintf(stderr, "Error: Invalid %s each(): %s\n", kw->keyword, args);
            return -1;
        }
        text[len - 1] = '\0';
        text += 5;
        if (bgp_ribout_flowspec_has_empty_field(text, ',')) {
            fprintf(stderr, "Error: Invalid %s each(): %s\n", kw->keyword, args);
            return -1;
        }
        for (char *item = strtok_r(text, ",", &save); item; item = strtok_r(NULL, ",", &save)) {
            if (comp->alternative_count >= MAX_FLOWSPEC_ALTERNATIVES) {
                fprintf(stderr, "Error: %s each() takes at most %d values\n", kw->keyword, MAX_FLOWSPEC_ALTERNATIVES);
                return -1;
            }
            if (bgp_ribout_flowspec_parse_expression(item, kw, &comp->alternatives[comp->alternative_count]) < 0) {
                return -1;
            }
            comp->alternative_count++;
        }
        if (comp->alternative_count < 2) {
            fprintf(stderr, "Error: %s each() needs at least two values\n", kw->keyword);
            return -1;
        }
        comp->step_count = 1;
    } else if ((x = strstr(text, " x ")) != NULL) {
        *x = '\0';
        if (bgp_ribout_flowspec_parse_stepped(text, x + 3, kw, comp) < 0) {
            return -1;
        }
    } else {
        if (bgp_ribout_flowspec_parse_expression(text, kw, &comp->alternatives[0]) < 0) {
            return -1;
        }
        comp->alternative_count = 1;
        comp->step_count = 1;
    }

    count = bgp_ribout_flowspec_component_count(comp);
    for (uint32_t i = 0; i < count; i++) {
        bgp_ribout_flowspec_ops_t ops;

        if (comp->step_count > 1 && i > 0 && i + 1 < count) {
            continue;
        }
        bgp_ribout_flowspec_component_ops(comp, i, &ops);
        if (!bgp_ribout_flowspec_ops_valid(kw->type, &ops)) {
            fprintf(stderr, "Error: %s operators break RFC 8955 / RFC 8956 encoding rules\n", kw->keyword);
            return -1;
        }
    }
    comp->rotate = rotate;
    return 0;
}

/*
 * Rebuild the list of set component types after a change: the per-NLRI loops walk this short list, because each
 * component is large (its alternatives are inline) and a walk over all of them reads many cache lines.
 */
static void bgp_ribout_flowspec_index_components(bgp_ribout_flowspec_t *fs) {
    fs->set_count = 0;
    fs->rotating = 0;
    for (uint8_t type = FLOWSPEC_IP_PROTOCOL; type <= FLOWSPEC_FLOW_LABEL; type++) {
        if (fs->components[type].alternative_count > 0) {
            fs->set_types[fs->set_count++] = type;
            fs->rotating |= fs->components[type].rotate;
        }
    }
}

/*
 * Set one component from "<keyword> <args>". The block changes only when the whole line is valid.
 */
int bgp_ribout_flowspec_parse_component(bgp_ribout_config_t *block, const char *keyword, const char *args) {
    const bgp_ribout_flowspec_component_kw_t *kw;
    bgp_ribout_flowspec_component_t           comp;
    bgp_ribout_flowspec_t                    *fs;

    if (!block || !keyword) {
        return -1;
    }

    if (strcmp(keyword, "src-prefix") == 0) {
        char              line[160];
        bgp_prefix_spec_t spec;
        uint8_t           offset = 0;

        snprintf(line, sizeof(line), "src-prefix %s", args ? args : "");
        if (bgp_ribout_parse_prefix_spec("src-prefix", line, &spec, &offset) < 0 ||
            !(fs = bgp_ribout_flowspec_get(block))) {
            return -1;
        }
        fs->src_prefix = spec;
        fs->src_offset = offset;
        return 0;
    }

    kw = bgp_ribout_flowspec_component_by_keyword(keyword);
    if (!kw) {
        fprintf(stderr, "Error: Unknown FlowSpec component: %s\n", keyword);
        return -1;
    }
    if (bgp_ribout_flowspec_parse_component_args(args, kw, &comp) < 0 || !(fs = bgp_ribout_flowspec_get(block))) {
        return -1;
    }
    fs->components[kw->type] = comp;
    bgp_ribout_flowspec_index_components(fs);
    return 0;
}

/*
 * Remove one component ("no <keyword>"). Returns -1 for an unknown keyword.
 */
int bgp_ribout_flowspec_clear_component(bgp_ribout_config_t *block, const char *keyword) {
    const bgp_ribout_flowspec_component_kw_t *kw = bgp_ribout_flowspec_component_by_keyword(keyword);
    int                                       src = (strcmp(keyword, "src-prefix") == 0);

    if (!src && !kw) {
        return -1;
    }
    if (!block->flowspec) {
        return 0;
    }
    if (src) {
        memset(&block->flowspec->src_prefix, 0, sizeof(block->flowspec->src_prefix));
        block->flowspec->src_offset = 0;
    } else {
        memset(&block->flowspec->components[kw->type], 0, sizeof(block->flowspec->components[kw->type]));
        bgp_ribout_flowspec_index_components(block->flowspec);
    }
    return 0;
}

// Canonical text

/*
 * Append printf-style text to the string in buf; text that does not fit is cut.
 */
static void bgp_ribout_appendf(char *buf, size_t len, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

static void bgp_ribout_appendf(char *buf, size_t len, const char *fmt, ...) {
    size_t  used = strnlen(buf, len);
    va_list ap;

    if (used + 1 >= len) {
        return;
    }
    va_start(ap, fmt);
    vsnprintf(buf + used, len - used, fmt, ap);
    va_end(ap);
}

/*
 * Append the canonical expression of an operator list: the inverse of
 * bgp_ribout_flowspec_parse_expression(). A width is written only when
 * it differs from the smallest width of the value.
 */
static void bgp_ribout_flowspec_render_ops(const bgp_ribout_flowspec_component_kw_t *kw,
                                           const bgp_ribout_flowspec_ops_t *ops, char *buf, size_t len) {
    for (uint8_t i = 0; i < ops->num_values; i++) {
        const flowspec_op_value_t *ov = &ops->values[i];
        unsigned                   width = bgp_ribout_flowspec_op_width(ov->op);

        if (i > 0) {
            bgp_ribout_appendf(buf, len, "%s", (ov->op & FLOWSPEC_OP_AND) ? "&" : " ");
        }

        if (kw->bitmask) {
            size_t                                name_count;
            const bgp_ribout_flowspec_bit_name_t *names = bgp_ribout_flowspec_bit_names(kw->type, &name_count);
            uint32_t                              named = 0;
            int                                   first = 1;

            bgp_ribout_appendf(buf, len, "%s%s", (ov->op & FLOWSPEC_OP_NOT) ? "!" : "",
                      (ov->op & FLOWSPEC_OP_MATCH) ? "" : "any(");
            for (size_t n = 0; n < name_count; n++) {
                named |= names[n].bit;
            }
            if (ov->value != 0 && (ov->value & ~named) == 0) {
                for (size_t n = 0; n < name_count; n++) {
                    if (ov->value & names[n].bit) {
                        bgp_ribout_appendf(buf, len, "%s%s", first ? "" : "+", names[n].name);
                        first = 0;
                    }
                }
            } else {
                bgp_ribout_appendf(buf, len, "%u", ov->value);
            }
            if (!(ov->op & FLOWSPEC_OP_MATCH)) {
                bgp_ribout_appendf(buf, len, ")");
            }
        } else {
            uint8_t cmp = (uint8_t)(ov->op & (FLOWSPEC_OP_LT | FLOWSPEC_OP_GT | FLOWSPEC_OP_EQ));
            static const char *cmp_text[8] = {"false", "", ">", ">=", "<", "<=", "!=", "true"};

            // lt=4, gt=2, eq=1 index the table.
            if (cmp == 0 || cmp == 7) {
                bgp_ribout_appendf(buf, len, "%s", cmp_text[cmp]);
                continue;
            }
            bgp_ribout_appendf(buf, len, "%s%u", cmp_text[cmp], ov->value);
        }

        if (width != bgp_ribout_flowspec_auto_width(ov->value)) {
            bgp_ribout_appendf(buf, len, ":%u", width);
        }
    }
}

/*
 * Append prefix number index of a prefix spec, with "/offset-length" for an IPv6 offset and " x count" when with_count
 * is set.
 */
static void bgp_ribout_flowspec_render_prefix(const bgp_prefix_spec_t *spec, uint8_t offset, uint32_t index,
                                              int with_count, char *buf, size_t len) {
    char    addr[INET6_ADDRSTRLEN];
    uint8_t bytes[16];

    memcpy(bytes, &spec->base_addr, sizeof(bytes));
    if (index > 0) {
        (void)bgp_ribout_prefix_advance(spec->af, bytes, spec->prefix_len, index);
    }
    inet_ntop(spec->af, bytes, addr, sizeof(addr));
    if (offset > 0) {
        bgp_ribout_appendf(buf, len, "%s/%u-%u", addr, offset, spec->prefix_len);
    } else {
        bgp_ribout_appendf(buf, len, "%s/%u", addr, spec->prefix_len);
    }
    if (with_count && spec->count > 1) {
        bgp_ribout_appendf(buf, len, " x %u", spec->count);
    }
}

/*
 * Append the canonical arguments of a component: "each(<expr>, ...)", or the expression and " x <count>" for a step.
 */
static void bgp_ribout_flowspec_render_component(const bgp_ribout_flowspec_component_kw_t *kw,
                                                 const bgp_ribout_flowspec_component_t *comp, char *buf, size_t len) {
    if (comp->rotate) {
        bgp_ribout_appendf(buf, len, "rotate ");
    }
    if (comp->alternative_count > 1) {
        bgp_ribout_appendf(buf, len, "each(");
        for (uint32_t i = 0; i < comp->alternative_count; i++) {
            bgp_ribout_appendf(buf, len, "%s", (i > 0) ? ", " : "");
            bgp_ribout_flowspec_render_ops(kw, &comp->alternatives[i], buf, len);
        }
        bgp_ribout_appendf(buf, len, ")");
        return;
    }
    bgp_ribout_flowspec_render_ops(kw, &comp->alternatives[0], buf, len);
    if (comp->step_count > 1) {
        bgp_ribout_appendf(buf, len, " x %u", comp->step_count);
    }
}

/*
 * The running-config line of src-prefix (type 2) or one operator component.
 */
int bgp_ribout_flowspec_component_to_string(const bgp_ribout_config_t *block, uint8_t type, char *buf, size_t len) {
    const bgp_ribout_flowspec_t              *fs = block->flowspec;
    const bgp_ribout_flowspec_component_kw_t *kw;

    buf[0] = '\0';
    if (!fs) {
        return 0;
    }
    if (type == FLOWSPEC_SRC_PREFIX) {
        if (fs->src_prefix.count == 0) {
            return 0;
        }
        bgp_ribout_appendf(buf, len, "src-prefix ");
        bgp_ribout_flowspec_render_prefix(&fs->src_prefix, fs->src_offset, 0, 1, buf, len);
        return 1;
    }

    kw = bgp_ribout_flowspec_component_by_type(type);
    if (!kw || fs->components[type].alternative_count == 0) {
        return 0;
    }
    bgp_ribout_appendf(buf, len, "%s ", kw->keyword);
    bgp_ribout_flowspec_render_component(kw, &fs->components[type], buf, len);
    return 1;
}

/*
 * One NLRI for the preview: "prefix <dst>", then src-prefix and the components with the values of this instance.
 */
void bgp_ribout_flowspec_nlri_to_string(const bgp_ribout_config_t *block, uint64_t instance, char *buf, size_t len) {
    const bgp_ribout_flowspec_t *fs = block->flowspec;
    uint32_t                     index[FLOWSPEC_FLOW_LABEL + 1];

    buf[0] = '\0';
    bgp_ribout_flowspec_decode(block, instance, index);
    if (block->prefix_spec.count > 0) {
        bgp_ribout_appendf(buf, len, "prefix ");
        bgp_ribout_flowspec_render_prefix(&block->prefix_spec, block->prefix_offset, index[FLOWSPEC_DEST_PREFIX], 0,
                                          buf, len);
    }
    if (fs && fs->src_prefix.count > 0) {
        bgp_ribout_appendf(buf, len, "%ssrc-prefix ", buf[0] ? " " : "");
        bgp_ribout_flowspec_render_prefix(&fs->src_prefix, fs->src_offset, index[FLOWSPEC_SRC_PREFIX], 0, buf, len);
    }
    for (size_t i = 0; fs && i < BGP_RIBOUT_FLOWSPEC_OP_COMPONENT_COUNT; i++) {
        const bgp_ribout_flowspec_component_kw_t *kw = &bgp_ribout_flowspec_op_components[i];
        bgp_ribout_flowspec_ops_t                 ops;

        if (fs->components[kw->type].alternative_count == 0) {
            continue;
        }
        bgp_ribout_flowspec_component_ops(&fs->components[kw->type], index[kw->type], &ops);
        bgp_ribout_appendf(buf, len, "%s%s ", buf[0] ? " " : "", kw->keyword);
        bgp_ribout_flowspec_render_ops(kw, &ops, buf, len);
    }
}

/*
 * Append the text of the value an action line has on one path: "redirect-ip <addr>[ copy]", "redirect-vrf <rt>" or
 * "mark <dscp>".
 */
static void bgp_ribout_flowspec_render_action_value(const bgp_ribout_flowspec_line_t *line, uint64_t path_index,
                                                    char *buf, size_t len) {
    const uint8_t *v = bgp_ribout_flowspec_action_value(line, path_index);
    char           addr[INET6_ADDRSTRLEN];
    int            ipv6 = (line->value_len == 20);

    if (line->kind == BGP_RIBOUT_FLOWSPEC_ACTION_MARK) {
        bgp_ribout_appendf(buf, len, "mark %u", v[7] & 0x3Fu);
        return;
    }
    inet_ntop(ipv6 ? AF_INET6 : AF_INET, v + 2, addr, sizeof(addr));
    if (line->kind == BGP_RIBOUT_FLOWSPEC_ACTION_REDIRECT_IP) {
        bgp_ribout_appendf(buf, len, "redirect-ip %s%s", addr, (v[ipv6 ? 19 : 7] & 0x01u) ? " copy" : "");
    } else if (ipv6) {
        bgp_ribout_appendf(buf, len, "redirect-vrf %s:%u", addr, ((unsigned)v[18] << 8) | v[19]);
    } else if (v[0] == 0x81) {
        bgp_ribout_appendf(buf, len, "redirect-vrf %s:%u", addr, ((unsigned)v[6] << 8) | v[7]);
    } else if (v[0] == 0x82) {
        bgp_ribout_appendf(buf, len, "redirect-vrf %u:%u", ((unsigned)v[2] << 24) | ((unsigned)v[3] << 16) |
                           ((unsigned)v[4] << 8) | v[5], ((unsigned)v[6] << 8) | v[7]);
    } else {
        bgp_ribout_appendf(buf, len, "redirect-vrf %u:%u", ((unsigned)v[2] << 8) | v[3],
                           ((unsigned)v[4] << 24) | ((unsigned)v[5] << 16) | ((unsigned)v[6] << 8) | v[7]);
    }
}

/*
 * The action values of path number path_index, "; "-joined, for the preview: the rotating value of a line with several
 * values, else the line text without "action ". buf must start as a string (it is appended to).
 */
void bgp_ribout_flowspec_actions_to_string(const bgp_ribout_config_t *block, uint64_t path_index, char *buf,
                                           size_t len) {
    const bgp_ribout_flowspec_t *fs = block->flowspec;

    for (uint32_t i = 0; fs && i < fs->actions.line_count; i++) {
        const bgp_ribout_flowspec_line_t *line = &fs->actions.lines[i];

        bgp_ribout_appendf(buf, len, "%s", buf[0] ? "; " : "");
        if (line->value_count > 1) {
            bgp_ribout_flowspec_render_action_value(line, path_index, buf, len);
        } else {
            // "action mark 46" shows as "mark 46".
            bgp_ribout_appendf(buf, len, "%s", line->text + strlen("action "));
        }
    }
}

// Action lines

/*
 * Take the one community of a library attribute (8 octets in attribute 16, or 20 in attribute 25) as the next value
 * of line. All values of a line have the same size. Frees attr.
 */
static int bgp_ribout_flowspec_line_add_value(bgp_ribout_flowspec_line_t *line, bgp_path_attr_t *attr) {
    int ret = -1;

    if (attr && !attr->next && line->value_count < MAX_FLOWSPEC_ACTION_VALUES &&
        ((attr->type_code == BGP_ATTR_EXT_COMM && attr->length == 8) ||
         (attr->type_code == BGP_ATTR_IPV6_EXT_COMM && attr->length == 20)) &&
        (line->value_count == 0 || line->value_len == attr->length)) {
        memcpy(line->values[line->value_count++], attr->value, attr->length);
        line->value_len = (uint8_t)attr->length;
        ret = 0;
    }
    bgp_path_attr_list_free(attr);
    return ret;
}

/*
 * Parse an IPv4 or IPv6 address into a bgp_next_hop_t.
 */
static int bgp_ribout_flowspec_parse_address(const char *text, bgp_next_hop_t *addr_out) {
    memset(addr_out, 0, sizeof(*addr_out));
    if (text && inet_pton(AF_INET, text, &addr_out->address.ipv4) == 1) {
        addr_out->af = AF_INET;
        return 0;
    }
    if (text && inet_pton(AF_INET6, text, &addr_out->address.ipv6) == 1) {
        addr_out->af = AF_INET6;
        return 0;
    }
    return -1;
}

/*
 * Parse a traffic-rate value: a finite decimal float, 0 or more (RFC 8955 section 7.1, IEEE 754 single), such as
 * 1250, 1.5 or 1e6. No sign, and no hex float (strtof alone takes "+1" and "0x10").
 */
static int bgp_ribout_flowspec_parse_rate(const char *text, float *rate_out) {
    char *end = NULL;
    float rate;

    if (!text || !(isdigit((unsigned char)text[0]) || (text[0] == '.' && isdigit((unsigned char)text[1]))) ||
        strpbrk(text, "xX")) {
        return -1;
    }
    errno = 0;
    rate = strtof(text, &end);
    if (*end != '\0' || errno != 0 || !isfinite(rate) || rate < 0.0f) {
        return -1;
    }
    *rate_out = rate;
    return 0;
}

/*
 * Tokens of one line; the parsers below read them in order.
 */
typedef struct {
    char *tok[MAX_FLOWSPEC_ACTION_VALUES + 8];
    int   count;
    int   pos;
} bgp_ribout_flowspec_tokens_t;

/*
 * Split buffer (changed in place) into words. Returns -1 when the line has too many words.
 */
static int bgp_ribout_flowspec_tokenize(char *buffer, bgp_ribout_flowspec_tokens_t *t) {
    char *save = NULL;

    t->count = 0;
    t->pos = 0;
    for (char *tok = strtok_r(buffer, " \t", &save); tok; tok = strtok_r(NULL, " \t", &save)) {
        if (t->count >= (int)(sizeof(t->tok) / sizeof(t->tok[0]))) {
            return -1;
        }
        t->tok[t->count++] = tok;
    }
    return 0;
}

/*
 * Next word, or NULL at the end.
 */
static const char *bgp_ribout_flowspec_next(bgp_ribout_flowspec_tokens_t *t) {
    return (t->pos < t->count) ? t->tok[t->pos++] : NULL;
}

/*
 * Take the next word when it is word; return 1 when taken.
 */
static int bgp_ribout_flowspec_accept(bgp_ribout_flowspec_tokens_t *t, const char *word) {
    if (t->pos < t->count && strcmp(t->tok[t->pos], word) == 0) {
        t->pos++;
        return 1;
    }
    return 0;
}

/*
 * "<value> x <count>" after the first value: returns count (1 without "x"), or 0 for a bad count.
 */
static uint32_t bgp_ribout_flowspec_accept_count(bgp_ribout_flowspec_tokens_t *t) {
    uint32_t count;

    if (!bgp_ribout_flowspec_accept(t, "x")) {
        return 1;
    }
    if (bgp_ribout_flowspec_parse_u32(bgp_ribout_flowspec_next(t), &count) < 0 ||
        count == 0 || count > MAX_FLOWSPEC_ACTION_VALUES) {
        return 0;
    }
    return count;
}

/*
 * redirect-ip <addr>... [copy] | redirect-ip <addr> x <count> [copy]: Redirect-to-IP (draft-ietf-idr-flowspec-redirect-
 * ip); an IPv6 address goes to attribute 25. A sequence steps the address by 1.
 */
static int bgp_ribout_flowspec_parse_redirect_ip(bgp_ribout_flowspec_tokens_t *t, bgp_ribout_flowspec_line_t *line,
                                                 char *text, size_t text_len) {
    bgp_next_hop_t addrs[MAX_FLOWSPEC_ACTION_VALUES];
    uint32_t       addr_count = 0;
    uint32_t       count = 1;
    int            copy;

    while (t->pos < t->count && strcmp(t->tok[t->pos], "copy") != 0 && strcmp(t->tok[t->pos], "x") != 0) {
        if (addr_count >= MAX_FLOWSPEC_ACTION_VALUES ||
            bgp_ribout_flowspec_parse_address(t->tok[t->pos], &addrs[addr_count]) < 0) {
            return -1;
        }
        bgp_ribout_appendf(text, text_len, " %s", t->tok[t->pos++]);
        addr_count++;
    }
    if (addr_count == 1) {
        count = bgp_ribout_flowspec_accept_count(t);
        if (count == 0) {
            return -1;
        }
        if (count > 1) {
            bgp_ribout_appendf(text, text_len, " x %u", count);
        }
    }
    copy = bgp_ribout_flowspec_accept(t, "copy");
    if (copy) {
        bgp_ribout_appendf(text, text_len, " copy");
    }
    if (addr_count == 0) {
        return -1;
    }

    for (uint32_t i = 0; i < addr_count * count; i++) {
        bgp_next_hop_t addr = addrs[(addr_count > 1) ? i : 0];

        if (count > 1 && bgp_ribout_prefix_advance(addr.af, &addr.address, (addr.af == AF_INET) ? 32 : 128, i) < 0) {
            return -1;
        }
        if (bgp_ribout_flowspec_line_add_value(line, (addr.af == AF_INET) ?
                bgp_attr_create_flowspec_redirect_ipv4(ntohl(addr.address.ipv4.s_addr), copy) :
                bgp_attr_create_flowspec_redirect_ipv6(&addr.address.ipv6, copy)) < 0) {
            return -1;
        }
    }
    line->kind = BGP_RIBOUT_FLOWSPEC_ACTION_REDIRECT_IP;
    return 0;
}

/*
 * redirect-vrf <rt>...: Route Target redirect (RFC 8955 section 7.4, types 0x8008 / 0x8108 / 0x8208); an IPv6
 * administrator gives the rt-redirect-ipv6 community in attribute 25 (RFC 8956 section 6.1).
 */
static int bgp_ribout_flowspec_parse_redirect_vrf(bgp_ribout_flowspec_tokens_t *t, bgp_ribout_flowspec_line_t *line,
                                                  char *text, size_t text_len) {
    while (t->pos < t->count) {
        const char      *value = bgp_ribout_flowspec_next(t);
        const char      *colon = strrchr(value, ':');
        char             admin[64];
        struct in6_addr  admin6;
        uint32_t         assigned;
        bgp_path_attr_t *attr;

        if (!colon || (size_t)(colon - value) >= sizeof(admin)) {
            return -1;
        }
        memcpy(admin, value, (size_t)(colon - value));
        admin[colon - value] = '\0';
        if (inet_pton(AF_INET6, admin, &admin6) == 1) {
            if (bgp_ribout_flowspec_parse_u32(colon + 1, &assigned) < 0 || assigned > 0xFFFF) {
                return -1;
            }
            attr = bgp_attr_create_flowspec_redirect_rt_ipv6(&admin6, (uint16_t)assigned);
        } else {
            bgp_ribout_admin_pair_t pair;

            if (bgp_ribout_parse_admin_pair(value, &pair) < 0) {
                return -1;
            }
            attr = bgp_ribout_admin_pair_ext_comm(&pair, 0x80, 0x08);
        }
        if (bgp_ribout_flowspec_line_add_value(line, attr) < 0) {
            return -1;
        }
        bgp_ribout_appendf(text, text_len, " %s", value);
    }
    line->kind = BGP_RIBOUT_FLOWSPEC_ACTION_REDIRECT_VRF;
    return line->value_count > 0 ? 0 : -1;
}

/*
 * mark <dscp>... | mark <dscp> x <count>: Traffic Marking (RFC 8955 section 7.5); DSCP 0-63.
 */
static int bgp_ribout_flowspec_parse_mark(bgp_ribout_flowspec_tokens_t *t, bgp_ribout_flowspec_line_t *line,
                                          char *text, size_t text_len) {
    uint32_t dscp;

    if (bgp_ribout_flowspec_parse_u32(bgp_ribout_flowspec_next(t), &dscp) < 0) {
        return -1;
    }
    if (t->pos < t->count && strcmp(t->tok[t->pos], "x") == 0) {
        uint32_t count = bgp_ribout_flowspec_accept_count(t);

        if (count == 0 || dscp + count - 1 > 63) {
            return -1;
        }
        for (uint32_t i = 0; i < count; i++) {
            if (bgp_ribout_flowspec_line_add_value(line, bgp_attr_create_flowspec_marking((uint8_t)(dscp + i))) < 0) {
                return -1;
            }
        }
        bgp_ribout_appendf(text, text_len, " %u x %u", dscp, count);
    } else {
        t->pos--;
        while (t->pos < t->count) {
            if (bgp_ribout_flowspec_parse_u32(bgp_ribout_flowspec_next(t), &dscp) < 0 || dscp > 63 ||
                bgp_ribout_flowspec_line_add_value(line, bgp_attr_create_flowspec_marking((uint8_t)dscp)) < 0) {
                return -1;
            }
            bgp_ribout_appendf(text, text_len, " %u", dscp);
        }
    }
    line->kind = BGP_RIBOUT_FLOWSPEC_ACTION_MARK;
    return 0;
}

/*
 * One action line from its words:
 *   traffic-rate bytes|packets <rate> [as <asn16>] | traffic-action [terminal] [sample] |
 *   redirect-ip <addr>... [copy] | redirect-ip <addr> x <count> [copy] | redirect-vrf <rt>... |
 *   mark <dscp>... | mark <dscp> x <count> | redirect-next-hop [copy] |
 *   interface-set <asn>:<group> [in] [out] [non-transitive]
 * A line with several values rotates them, one value per path.
 */
static int bgp_ribout_flowspec_parse_action_tokens(bgp_ribout_flowspec_tokens_t *t, bgp_ribout_flowspec_line_t *line) {
    const char      *kind = bgp_ribout_flowspec_next(t);
    char             text[MAX_FLOWSPEC_LINE_TEXT];
    bgp_path_attr_t *attr = NULL;

    text[0] = '\0';
    if (!kind) {
        return -1;
    }
    bgp_ribout_appendf(text, sizeof(text), "action %s", kind);

    if (strcmp(kind, "redirect-ip") == 0) {
        if (bgp_ribout_flowspec_parse_redirect_ip(t, line, text, sizeof(text)) < 0) {
            return -1;
        }
    } else if (strcmp(kind, "redirect-vrf") == 0) {
        if (bgp_ribout_flowspec_parse_redirect_vrf(t, line, text, sizeof(text)) < 0) {
            return -1;
        }
    } else if (strcmp(kind, "mark") == 0) {
        if (bgp_ribout_flowspec_parse_mark(t, line, text, sizeof(text)) < 0) {
            return -1;
        }
    } else {
        if (strcmp(kind, "traffic-rate") == 0) {
            const char *unit = bgp_ribout_flowspec_next(t);
            float       rate;
            uint32_t    asn = 0;

            if (!unit || (strcmp(unit, "bytes") != 0 && strcmp(unit, "packets") != 0) ||
                bgp_ribout_flowspec_parse_rate(bgp_ribout_flowspec_next(t), &rate) < 0) {
                return -1;
            }
            if (bgp_ribout_flowspec_accept(t, "as") &&
                (bgp_ribout_flowspec_parse_u32(bgp_ribout_flowspec_next(t), &asn) < 0 || asn > 0xFFFF)) {
                return -1;
            }
            attr = (unit[0] == 'b') ? bgp_attr_create_flowspec_rate((uint16_t)asn, rate) :
                                      bgp_attr_create_flowspec_rate_pkts((uint16_t)asn, rate);
            bgp_ribout_appendf(text, sizeof(text), " %s %.9g", unit, rate);
            if (asn) {
                bgp_ribout_appendf(text, sizeof(text), " as %u", asn);
            }
        } else if (strcmp(kind, "traffic-action") == 0) {
            int terminal = bgp_ribout_flowspec_accept(t, "terminal");
            int sample = bgp_ribout_flowspec_accept(t, "sample");

            attr = bgp_attr_create_flowspec_action(terminal, sample);
            bgp_ribout_appendf(text, sizeof(text), "%s%s", terminal ? " terminal" : "", sample ? " sample" : "");
        } else if (strcmp(kind, "redirect-next-hop") == 0) {
            int copy = bgp_ribout_flowspec_accept(t, "copy");

            attr = bgp_attr_create_flowspec_redirect_nexthop(copy);
            line->redirect_next_hop = 1;
            bgp_ribout_appendf(text, sizeof(text), "%s", copy ? " copy" : "");
        } else if (strcmp(kind, "interface-set") == 0) {
            const char *value = bgp_ribout_flowspec_next(t);
            const char *colon = value ? strrchr(value, ':') : NULL;
            char        asn_text[16];
            uint32_t    asn;
            uint32_t    group;
            int         in = 0;
            int         out = 0;
            int         non_transitive = 0;

            if (!colon || (size_t)(colon - value) >= sizeof(asn_text)) {
                return -1;
            }
            memcpy(asn_text, value, (size_t)(colon - value));
            asn_text[colon - value] = '\0';
            if (bgp_ribout_flowspec_parse_u32(asn_text, &asn) < 0 ||
                bgp_ribout_flowspec_parse_u32(colon + 1, &group) < 0 || group > 0x3FFF) {
                return -1;
            }
            for (;;) {
                if (bgp_ribout_flowspec_accept(t, "in")) {
                    in = 1;
                } else if (bgp_ribout_flowspec_accept(t, "out")) {
                    out = 1;
                } else if (bgp_ribout_flowspec_accept(t, "non-transitive")) {
                    non_transitive = 1;
                } else {
                    break;
                }
            }
            attr = bgp_attr_create_flowspec_interface_set(asn, (uint16_t)group, in, out, !non_transitive);
            bgp_ribout_appendf(text, sizeof(text), " %u:%u%s%s%s", asn, group, in ? " in" : "", out ? " out" : "",
                               non_transitive ? " non-transitive" : "");
        } else {
            return -1;
        }

        // Trailing words: the attribute is built already, so free it here.
        if (t->pos != t->count) {
            bgp_path_attr_list_free(attr);
            return -1;
        }
        if (bgp_ribout_flowspec_line_add_value(line, attr) < 0) {
            return -1;
        }
        line->kind = BGP_RIBOUT_FLOWSPEC_ACTION_FIXED;
    }

    if (t->pos != t->count) {
        return -1;
    }
    snprintf(line->text, sizeof(line->text), "%s", text);
    return 0;
}

/*
 * Parse one "action" line and add it to the block. Returns -1 with an error for bad text or when the block has its
 * maximum of lines; the block does not change then.
 */
int bgp_ribout_flowspec_parse_action(bgp_ribout_config_t *block, const char *args) {
    char                         buffer[MAX_FLOWSPEC_LINE_TEXT];
    bgp_ribout_flowspec_tokens_t tokens;
    bgp_ribout_flowspec_line_t   line;
    bgp_ribout_flowspec_t       *fs;

    if (!block || !args || strlen(args) >= sizeof(buffer)) {
        fprintf(stderr, "Error: Invalid action\n");
        return -1;
    }

    memset(&line, 0, sizeof(line));
    snprintf(buffer, sizeof(buffer), "%s", args);
    if (bgp_ribout_flowspec_tokenize(buffer, &tokens) < 0 ||
        bgp_ribout_flowspec_parse_action_tokens(&tokens, &line) < 0) {
        fprintf(stderr, "Error: Invalid action: %s\n", args);
        return -1;
    }
    fs = bgp_ribout_flowspec_get(block);
    if (!fs) {
        return -1;
    }
    if (fs->actions.line_count >= MAX_FLOWSPEC_LINES) {
        fprintf(stderr, "Error: at most %d action lines\n", MAX_FLOWSPEC_LINES);
        return -1;
    }
    fs->actions.lines[fs->actions.line_count++] = line;
    return 0;
}

/*
 * Remove all action lines ("no action").
 */
void bgp_ribout_flowspec_clear_actions(bgp_ribout_config_t *block) {
    if (block && block->flowspec) {
        memset(&block->flowspec->actions, 0, sizeof(block->flowspec->actions));
    }
}

// Generation support

/*
 * Library prefix component for prefix number index of a spec.
 */
static void bgp_ribout_flowspec_materialize_prefix(const bgp_prefix_spec_t *spec, uint8_t type, uint8_t offset,
                                                   uint32_t index, flowspec_component_t *comp) {
    memset(comp, 0, sizeof(*comp));
    comp->type = type;
    comp->prefix_len = spec->prefix_len;
    comp->prefix_offset = offset;
    memcpy(comp->prefix, &spec->base_addr, sizeof(comp->prefix));
    if (index > 0) {
        (void)bgp_ribout_prefix_advance(spec->af, comp->prefix, spec->prefix_len, index);
    }
}

/*
 * Build the NLRI at the given field positions (see bgp_ribout_flowspec_decode()): prefix components first, then the
 * operator components in type order.
 */
static int bgp_ribout_flowspec_materialize_at(const bgp_ribout_config_t *block,
                                              const uint32_t index[FLOWSPEC_FLOW_LABEL + 1],
                                              bgp_ribout_flowspec_nlri_t *out) {
    const bgp_ribout_flowspec_t *fs = block->flowspec;
    int                          n = 0;

    if (block->prefix_spec.count > 0) {
        bgp_ribout_flowspec_materialize_prefix(&block->prefix_spec, FLOWSPEC_DEST_PREFIX, block->prefix_offset,
                                               index[FLOWSPEC_DEST_PREFIX], &out->comps[n++]);
    }
    if (fs && fs->src_prefix.count > 0) {
        bgp_ribout_flowspec_materialize_prefix(&fs->src_prefix, FLOWSPEC_SRC_PREFIX, fs->src_offset,
                                               index[FLOWSPEC_SRC_PREFIX], &out->comps[n++]);
    }
    for (uint8_t i = 0; fs && i < fs->set_count; i++) {
        uint8_t                                type = fs->set_types[i];
        const bgp_ribout_flowspec_component_t *comp = &fs->components[type];
        const bgp_ribout_flowspec_ops_t       *ops;

        memset(&out->comps[n], 0, sizeof(out->comps[n]));
        out->comps[n].type = type;
        if (comp->step_count > 1) {
            // A stepped value changes per NLRI, so it is a copy.
            ops = &comp->alternatives[0];
            memcpy(out->values[n], ops->values, sizeof(ops->values[0]) * ops->num_values);
            out->values[n][0].value += index[type];
            out->comps[n].values = out->values[n];
        } else {
            // The library encoder reads the values; it does not change them.
            ops = &comp->alternatives[index[type]];
            out->comps[n].values = (flowspec_op_value_t *)ops->values;
        }
        out->comps[n].num_values = ops->num_values;
        n++;
    }

    out->rule.components = out->comps;
    out->rule.num_components = n;
    return (n > 0) ? 0 : -1;
}

/*
 * Build NLRI number instance: decode it into field positions, then build at those positions.
 */
int bgp_ribout_flowspec_materialize(const bgp_ribout_config_t *block, uint64_t instance,
                                    bgp_ribout_flowspec_nlri_t *out) {
    uint32_t index[FLOWSPEC_FLOW_LABEL + 1];

    bgp_ribout_flowspec_decode(block, instance, index);
    return bgp_ribout_flowspec_materialize_at(block, index, out);
}

/*
 * Octets an operator list takes on the wire (RFC 8955 section 4.2.1): one operator byte and the value per pair.
 */
static unsigned bgp_ribout_flowspec_ops_wire_len(const bgp_ribout_flowspec_ops_t *ops) {
    unsigned len = 0;

    for (uint8_t i = 0; i < ops->num_values; i++) {
        len += 1 + bgp_ribout_flowspec_op_width(ops->values[i].op);
    }
    return len;
}

/*
 * Prefix lengths do not change in a sequence, and a step keeps one width, so only the alternatives decide which NLRI
 * is the longest.
 */
int bgp_ribout_flowspec_materialize_longest(const bgp_ribout_config_t *block, bgp_ribout_flowspec_nlri_t *out) {
    const bgp_ribout_flowspec_t *fs = block->flowspec;
    uint32_t                     index[FLOWSPEC_FLOW_LABEL + 1];

    memset(index, 0, sizeof(index));
    for (uint8_t type = FLOWSPEC_IP_PROTOCOL; fs && type <= FLOWSPEC_FLOW_LABEL; type++) {
        const bgp_ribout_flowspec_component_t *comp = &fs->components[type];

        for (uint32_t i = 1; comp->step_count <= 1 && i < comp->alternative_count; i++) {
            if (bgp_ribout_flowspec_ops_wire_len(&comp->alternatives[i]) >
                bgp_ribout_flowspec_ops_wire_len(&comp->alternatives[index[type]])) {
                index[type] = i;
            }
        }
    }
    return bgp_ribout_flowspec_materialize_at(block, index, out);
}

/*
 * Destination count x source count x the count of every component (with rotating ones counted once:
 * rotating_once); 0 when the product overflows.
 */
static uint64_t bgp_ribout_flowspec_product(const bgp_ribout_config_t *block, int rotating_once) {
    const bgp_ribout_flowspec_t *fs = block->flowspec;
    uint64_t                     instances = bgp_ribout_effective_count(block->prefix_spec.count);

    for (uint8_t type = FLOWSPEC_SRC_PREFIX; fs && type <= FLOWSPEC_FLOW_LABEL; type++) {
        const bgp_ribout_flowspec_component_t *comp = &fs->components[type];
        uint64_t count = (type == FLOWSPEC_SRC_PREFIX) ? bgp_ribout_effective_count(fs->src_prefix.count) :
                         (rotating_once && comp->rotate) ? 1 : bgp_ribout_flowspec_component_count(comp);

        if (instances > UINT64_MAX / count) {
            return 0;
        }
        instances *= count;
    }
    return instances;
}

uint64_t bgp_ribout_flowspec_instances(const bgp_ribout_config_t *block) {
    return bgp_ribout_flowspec_product(block, 0);
}

uint64_t bgp_ribout_flowspec_rules(const bgp_ribout_config_t *block) {
    return bgp_ribout_flowspec_product(block, 1);
}

/*
 * Rule numbers count the components that do not rotate (the last one fastest, the destination slowest); the instance
 * space counts every component in the same order. Decode the rule's digits, put each rotating component's value in,
 * and encode them again.
 */
uint64_t bgp_ribout_flowspec_rule_instance(const bgp_ribout_config_t *block, uint64_t rule, uint64_t rotation) {
    const bgp_ribout_flowspec_t *fs = block->flowspec;
    uint32_t                     digit[FLOWSPEC_FLOW_LABEL + 1];
    uint64_t                     instance;

    if (!fs || !fs->rotating) {
        return rule;  /* Every component counts in both: rule numbers are instance numbers */
    }
    for (int i = (int)fs->set_count - 1; i >= 0; i--) {
        const bgp_ribout_flowspec_component_t *comp = &fs->components[fs->set_types[i]];
        uint32_t                               count = bgp_ribout_flowspec_component_count(comp);

        if (comp->rotate) {
            digit[i] = (uint32_t)(rotation % count);
        } else {
            digit[i] = (uint32_t)(rule % count);
            rule /= count;
        }
    }
    instance = rule;  /* The prefix positions: destination x source count + source */
    for (uint8_t i = 0; i < fs->set_count; i++) {
        instance = instance * bgp_ribout_flowspec_component_count(&fs->components[fs->set_types[i]]) + digit[i];
    }
    return instance;
}

/*
 * The values of a line rotate with the path number.
 */
const uint8_t *bgp_ribout_flowspec_action_value(const bgp_ribout_flowspec_line_t *line, uint64_t path_index) {
    return line->values[path_index % line->value_count];
}

/*
 * AF of the destination and source prefixes; -1 when they differ.
 */
int bgp_ribout_flowspec_af(const bgp_ribout_config_t *block) {
    const bgp_prefix_spec_t *specs[2] = {&block->prefix_spec, block->flowspec ? &block->flowspec->src_prefix : NULL};
    int                      af = 0;

    for (int i = 0; i < 2; i++) {
        if (!specs[i] || specs[i]->count == 0) {
            continue;
        }
        if (af != 0 && af != specs[i]->af) {
            return -1;
        }
        af = specs[i]->af;
    }
    return af;
}
