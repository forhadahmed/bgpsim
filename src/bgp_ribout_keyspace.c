/*
 * Route-key comparison of two snapshots, from their frozen configurations.
 *
 * The generator emits the cross product of its NLRI-side dimensions, so the set of route keys of a block is the cross
 * product of its route-key dimensions. Two blocks share a key exactly when every key dimension of one intersects the
 * same dimension of the other. Dimensions that the generator multiplies but that are not part of the route key
 * (labels, ESI, EVPN Type 5 gateway IP) are left out: they repeat keys inside one block.
 *
 * Route keys: prefix for unicast and labeled-unicast (RFC 8277); RD and prefix for VPN (RFC 4364); RD, Ethernet tag,
 * MAC and IP for EVPN Type 2 (RFC 7432 section 7.2); RD, Ethernet tag and IP prefix for EVPN Type 5 (RFC 9136);
 * distinguisher, color and endpoint for SR Policy (RFC 9830); the whole rule and the RD for FlowSpec (RFC 8955). The
 * Add-Path ID is part of every key when Add-Path is on (RFC 7911).
 */
#include <string.h>
#include <sys/socket.h>
#include "util.h"
#include "bgp_ribout_snapshot.h"

// Dimension helpers

/*
 * Clear the bits of a 16-octet address outside [from, to).
 */
static void keep_bits(uint8_t addr[16], unsigned from, unsigned to) {
    // Bit zero is the high bit on the wire; only the first/last retained bytes need individual masks.
    unsigned first = from / 8, end = (to + 7) / 8;
    memset(addr, 0, first);
    memset(addr + end, 0, 16 - end);
    if (from >= to) {
        memset(addr, 0, 16);
        return;
    }
    addr[first] &= (uint8_t)(0xffu >> (from % 8));
    if (to % 8) addr[end - 1] &= (uint8_t)(0xffu << (8 - to % 8));
}

/*
 * The keys of a sequence of count values that starts at base and steps by 2^(bits - step_len), as up to two address
 * ranges [first, last] with the bits outside [offset, step_len) cleared. Returns the number of ranges.
 *
 * offset is the IPv6 FlowSpec prefix offset (RFC 8956 section 3.1): only the bits from the offset to the length are on
 * the wire, so two prefixes that differ before the offset are the same key. A sequence that carries into those bits
 * wraps to the start of the 2^(step_len - offset) values the wire form has: its keys are two ranges, or all of them
 * when it runs through every value. Without an offset the parser keeps a sequence inside the address space.
 */
static int sequence_ranges(int af, const void *base, uint8_t offset, uint8_t step_len, uint32_t count,
                           uint8_t ranges[2][2][16]) {
    size_t   bytes = (af == AF_INET) ? 4 : 16;
    unsigned bits = (unsigned)bytes * 8;
    unsigned width = step_len > offset ? step_len - offset : 0;
    uint8_t *first = ranges[0][0], *last = ranges[0][1];

    memset(ranges, 0, sizeof(uint8_t[2][2][16]));
    memcpy(first, base, bytes);
    keep_bits(first, offset, step_len);
    if (width < 32 && count > 0 && (uint64_t)count - 1 >= (1ULL << width) - 1) {
        // Every value of the wire form: the range from all zeros to all ones between the offset and the length.
        memset(first, 0, 16);
        memset(last, 0xff, 16);
        keep_bits(last, offset, step_len);
        return 1;
    }
    memcpy(last, first, 16);
    (void)bytes_be_add(last, bytes, count > 0 ? count - 1 : 0, bits - step_len);
    if (offset > 0 && (last[(offset - 1) / 8] & (0x80u >> ((offset - 1) % 8)))) {
        // Carried past the top of the wire form: [first, all ones] and [all zeros, last].
        keep_bits(last, offset, step_len);
        memcpy(ranges[1][1], last, 16);
        memset(last, 0xff, 16);
        keep_bits(last, offset, step_len);
        return 2;
    }
    return 1;
}

/*
 * Some range of one list meets some range of the other.
 */
static int ranges_meet(const uint8_t a[2][2][16], int a_count, const uint8_t b[2][2][16], int b_count) {
    for (int i = 0; i < a_count; i++) {
        for (int j = 0; j < b_count; j++) {
            if (memcmp(a[i][0], b[j][1], 16) <= 0 && memcmp(b[j][0], a[i][1], 16) <= 0) {
                return 1;
            }
        }
    }
    return 0;
}

/*
 * Prefix sequences intersect when they have the same family, length and offset and their keys meet.
 */
static int prefix_overlap(const bgp_prefix_spec_t *a, uint8_t a_offset, const bgp_prefix_spec_t *b, uint8_t b_offset) {
    uint8_t a_ranges[2][2][16], b_ranges[2][2][16];
    int a_count, b_count;

    if ((a->count == 0) != (b->count == 0)) {
        return 0;  /* A component that only one rule has */
    }
    if (a->count == 0) {
        return 1;
    }
    if (a->af != b->af || a->prefix_len != b->prefix_len || a_offset != b_offset) {
        return 0;
    }
    a_count = sequence_ranges(a->af, &a->base_addr, a_offset, a->prefix_len, a->count, a_ranges);
    b_count = sequence_ranges(b->af, &b->base_addr, b_offset, b->prefix_len, b->count, b_ranges);
    return ranges_meet((const uint8_t (*)[2][16])a_ranges, a_count, (const uint8_t (*)[2][16])b_ranges, b_count);
}

/*
 * The same count of keys from the same first key is the same keys (a false "differs" only withdraws and advertises
 * again).
 */
static int prefix_equal(const bgp_prefix_spec_t *a, uint8_t a_offset, const bgp_prefix_spec_t *b, uint8_t b_offset) {
    uint8_t a_ranges[2][2][16], b_ranges[2][2][16];

    if (a->count != b->count) {
        return 0;
    }
    if (a->count == 0) {
        return 1;
    }
    if (a->af != b->af || a->prefix_len != b->prefix_len || a_offset != b_offset) {
        return 0;
    }
    sequence_ranges(a->af, &a->base_addr, a_offset, a->prefix_len, a->count, a_ranges);
    sequence_ranges(b->af, &b->base_addr, b_offset, b->prefix_len, b->count, b_ranges);
    return memcmp(a_ranges, b_ranges, sizeof(a_ranges)) == 0;
}

/*
 * Host sequences (base + i): EVPN IP and SR Policy endpoints. count 0 means the dimension is absent.
 */
static int host_overlap(const bgp_next_hop_spec_t *a, const bgp_next_hop_spec_t *b) {
    uint8_t a_ranges[2][2][16], b_ranges[2][2][16];
    uint8_t bits = (a->af == AF_INET) ? 32 : 128;
    int a_count, b_count;

    if ((a->count == 0) != (b->count == 0)) {
        return 0;
    }
    if (a->count == 0) {
        return 1;
    }
    if (a->af != b->af) {
        return 0;
    }
    a_count = sequence_ranges(a->af, &a->base_addr, 0, bits, a->count, a_ranges);
    b_count = sequence_ranges(b->af, &b->base_addr, 0, bits, b->count, b_ranges);
    return ranges_meet((const uint8_t (*)[2][16])a_ranges, a_count, (const uint8_t (*)[2][16])b_ranges, b_count);
}

/*
 * EVPN Type 2 IP keys: none (MAC-only routes), or the IPs of one or two address families. MAC-only keys never meet
 * MAC/IP keys.
 */
static int type2_ips_overlap(const bgp_ribout_config_t *a, const bgp_ribout_config_t *b) {
    const bgp_next_hop_spec_t *as[2] = {&a->ip_spec, &a->ip2_spec};
    const bgp_next_hop_spec_t *bs[2] = {&b->ip_spec, &b->ip2_spec};

    if (a->ip_spec.count == 0 || b->ip_spec.count == 0) {
        return a->ip_spec.count == b->ip_spec.count;
    }
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            if (as[i]->count > 0 && bs[j]->count > 0 && host_overlap(as[i], bs[j])) {
                return 1;
            }
        }
    }
    return 0;
}

static int host_equal(const bgp_next_hop_spec_t *a, const bgp_next_hop_spec_t *b) {
    size_t bytes = (a->af == AF_INET) ? 4 : 16;

    return a->count == b->count &&
           (a->count == 0 || (a->af == b->af && memcmp(&a->base_addr, &b->base_addr, bytes) == 0));
}

/*
 * 48-bit MAC sequences.
 */
static uint64_t mac_value(const uint8_t mac[6]) {
    uint64_t value = 0;

    for (int i = 0; i < 6; i++) {
        value = (value << 8) | mac[i];
    }
    return value;
}

static int mac_overlap(const bgp_mac_spec_t *a, const bgp_mac_spec_t *b) {
    uint64_t a_first = mac_value(a->base_addr), b_first = mac_value(b->base_addr);
    uint64_t a_last = a_first + bgp_ribout_effective_count(a->count) - 1;
    uint64_t b_last = b_first + bgp_ribout_effective_count(b->count) - 1;

    return a_first <= b_last && b_first <= a_last;
}

/*
 * uint32 value lists; an empty list stands for the generator's default (0).
 */
static int u32_list_overlap(const uint32_t *a, uint32_t a_count, uint32_t a_step,
                            const uint32_t *b, uint32_t b_count, uint32_t b_step) {
    static const uint32_t zero = 0;

    if (a_count == 0) {
        a = &zero;
        a_count = 1;
        a_step = 0;
    }
    if (b_count == 0) {
        b = &zero;
        b_count = 1;
        b_step = 0;
    }
    /*
     * Generated inventories are consecutive integer ranges. Compare those in constant time;
     * an explicit list still needs inspection, but never expand a range to do it.
     */
    if (a_step && b_step) return a[0] <= (uint64_t)b[0] + b_count - 1 &&
                                 b[0] <= (uint64_t)a[0] + a_count - 1;
    if (a_step) return u32_list_overlap(b, b_count, b_step, a, a_count, a_step);
    for (uint32_t i = 0; i < a_count; i++) {
        if (b_step) {
            if (a[i] >= b[0] && (uint64_t)a[i] < (uint64_t)b[0] + b_count) return 1;
            continue;
        }
        for (uint32_t j = 0; j < b_count; j++) {
            if (a[i] == b[j]) {
                return 1;
            }
        }
    }
    return 0;
}

static int u32_list_equal(const uint32_t *a, uint32_t a_count, uint32_t a_step,
                          const uint32_t *b, uint32_t b_count, uint32_t b_step) {
    if (a_count != b_count) return 0;
    if (!a_count) return 1;
    if (a_step && b_step) return a[0] == b[0];
    for (uint32_t i = 0; i < a_count; i++)
        if (bgp_u32_value(a, a_step, i) != bgp_u32_value(b, b_step, i)) return 0;
    return 1;
}

/*
 * Ethernet tag lists; an empty list generates tag 0.
 */
static int tag_list_equal(const bgp_ribout_config_t *a, const bgp_ribout_config_t *b) {
    static const uint32_t zero = 0;

    return a->ethernet_tag_rotate == b->ethernet_tag_rotate &&
           u32_list_equal(a->ethernet_tag_count ? a->ethernet_tags : &zero,
                          bgp_ribout_effective_count(a->ethernet_tag_count), a->ethernet_tags_step,
                          b->ethernet_tag_count ? b->ethernet_tags : &zero,
                          bgp_ribout_effective_count(b->ethernet_tag_count), b->ethernet_tags_step);
}

static int rd_equal_one(const route_distinguisher_t *a, const route_distinguisher_t *b) {
    return a->type == b->type && memcmp(a->value, b->value, sizeof(a->value)) == 0;
}

/*
 * Type + wire value is an ordered integer key. A parsed RD sequence cannot carry
 * into its administrator, so its complete key set is one consecutive range.
 */
static uint64_t rd_key(route_distinguisher_t rd) {
    uint64_t key = rd.type;
    for (size_t i = 0; i < sizeof(rd.value); i++) key = (key << 8) | rd.value[i];
    return key;
}

static int rd_list_overlap(const bgp_ribout_config_t *a, const bgp_ribout_config_t *b) {
    if (!a->rd_count || !b->rd_count) return a->rd_count == b->rd_count;
    if (a->rds_step && b->rds_step) {
        uint64_t first_a = rd_key(a->rds[0]), first_b = rd_key(b->rds[0]);
        return first_a <= first_b + b->rd_count - 1 && first_b <= first_a + a->rd_count - 1;
    }
    if (a->rds_step) return rd_list_overlap(b, a);
    for (uint32_t i = 0; i < a->rd_count; i++) {
        if (b->rds_step) {
            uint64_t key = rd_key(a->rds[i]), base = rd_key(b->rds[0]);
            if (key >= base && key - base < b->rd_count) return 1;
            continue;
        }
        for (uint32_t j = 0; j < b->rd_count; j++) {
            if (rd_equal_one(&a->rds[i], &b->rds[j])) {
                return 1;
            }
        }
    }
    return a->rd_count == 0 && b->rd_count == 0;
}

static int rd_list_equal(const bgp_ribout_config_t *a, const bgp_ribout_config_t *b) {
    if (a->rd_count != b->rd_count || a->rd_rotate != b->rd_rotate) {
        return 0;
    }
    if (a->rds_step && b->rds_step) return rd_equal_one(&a->rds[0], &b->rds[0]);
    for (uint32_t i = 0; i < a->rd_count; i++) {
        route_distinguisher_t av = bgp_ribout_rds_at(a, i), bv = bgp_ribout_rds_at(b, i);
        if (!rd_equal_one(&av, &bv)) {
            return 0;
        }
    }
    return 1;
}

/*
 * A rotating key list (rd, ethernet-tag, path-id, distinguisher, color, endpoint, FlowSpec component). color rotate
 * changes nothing outside SR Policy; counting it anyway only makes equality stricter.
 */
static int key_list_rotates(const bgp_ribout_config_t *c) {
    return c->rd_rotate || c->ethernet_tag_rotate || c->path_id_rotate || c->distinguisher_rotate || c->color_rotate ||
           c->endpoint_rotate || (c->flowspec && c->flowspec->rotating);
}

/*
 * A rotating key list pairs its values with paths by position, which rotate-every and the size of every other key
 * dimension shift. With one rotating on either side all of that must match too, so that equal lists give equal key
 * sets (a false "differs" only withdraws and advertises again).
 */
static int rotation_layout_equal(const bgp_ribout_config_t *a, const bgp_ribout_config_t *b) {
    const bgp_ribout_flowspec_t *af = a->flowspec, *bf = b->flowspec;

    if (!key_list_rotates(a) && !key_list_rotates(b)) {
        return 1;
    }
    if (bgp_ribout_effective_count(a->rotate_every) != bgp_ribout_effective_count(b->rotate_every) ||
        a->prefix_spec.count != b->prefix_spec.count || a->rd_count != b->rd_count || a->rd_rotate != b->rd_rotate ||
        a->label_count != b->label_count || a->label_rotate != b->label_rotate || a->esi_count != b->esi_count ||
        a->gateway_ip_spec.count != b->gateway_ip_spec.count || a->path_id_count != b->path_id_count ||
        a->path_id_rotate != b->path_id_rotate || a->ethernet_tag_count != b->ethernet_tag_count ||
        a->ethernet_tag_rotate != b->ethernet_tag_rotate || a->mac_spec.count != b->mac_spec.count ||
        a->ip_spec.count != b->ip_spec.count || a->ip_rotate != b->ip_rotate || a->ip2_spec.count != b->ip2_spec.count ||
        a->ip2_rotate != b->ip2_rotate || a->distinguisher_count != b->distinguisher_count ||
        a->distinguisher_rotate != b->distinguisher_rotate || a->color_count != b->color_count ||
        a->color_rotate != b->color_rotate || a->endpoint_spec.count != b->endpoint_spec.count ||
        a->endpoint_rotate != b->endpoint_rotate || (af ? af->src_prefix.count : 0) != (bf ? bf->src_prefix.count : 0)) {
        return 0;
    }
    for (uint8_t type = FLOWSPEC_IP_PROTOCOL; (af || bf) && type <= FLOWSPEC_FLOW_LABEL; type++) {
        static const bgp_ribout_flowspec_component_t unset;
        const bgp_ribout_flowspec_component_t *ac = af ? &af->components[type] : &unset;
        const bgp_ribout_flowspec_component_t *bc = bf ? &bf->components[type] : &unset;

        if (ac->alternative_count != bc->alternative_count || ac->step_count != bc->step_count ||
            ac->rotate != bc->rotate) {
            return 0;
        }
    }
    return 1;
}

/*
 * Add-Path IDs are a key dimension only when both snapshots carry them. A mismatch cannot be bound on one session
 * (the compatibility check withholds it), so it is reported as overlapping, the safe answer.
 */
static int path_id_overlap(const bgp_ribout_snapshot_t *a, const bgp_ribout_snapshot_t *b) {
    if (a->profile.add_path && b->profile.add_path) {
        return u32_list_overlap(a->config->path_ids, a->config->path_id_count, a->config->path_ids_step,
                                b->config->path_ids, b->config->path_id_count, b->config->path_ids_step);
    }
    return 1;
}

static int path_id_equal(const bgp_ribout_snapshot_t *a, const bgp_ribout_snapshot_t *b) {
    return a->profile.add_path == b->profile.add_path &&
           (!a->profile.add_path || (a->config->path_id_rotate == b->config->path_id_rotate &&
                                     u32_list_equal(a->config->path_ids, a->config->path_id_count, a->config->path_ids_step,
                                                    b->config->path_ids, b->config->path_id_count, b->config->path_ids_step)));
}

// FlowSpec rules

static int ops_equal(const bgp_ribout_flowspec_ops_t *a, const bgp_ribout_flowspec_ops_t *b, int from) {
    if (a->num_values != b->num_values) {
        return 0;
    }
    for (int i = from; i < a->num_values; i++) {
        if (a->values[i].op != b->values[i].op || a->values[i].value != b->values[i].value) {
            return 0;
        }
    }
    return 1;
}

/*
 * Value range [first, last] that the first comparison of a stepped component takes.
 */
static void step_range(const bgp_ribout_flowspec_component_t *comp, uint64_t *first, uint64_t *last) {
    *first = comp->alternatives[0].values[0].value;
    *last = *first + comp->step_count - 1;
}

/*
 * Do some instance of component a and some instance of component b encode the same operator list? A stepped
 * component is its first alternative with the value of the first comparison running over the step range.
 */
static int component_overlap(const bgp_ribout_flowspec_component_t *a, const bgp_ribout_flowspec_component_t *b) {
    int a_step = a->step_count > 1, b_step = b->step_count > 1;

    if (a_step && b_step) {
        uint64_t a_first, a_last, b_first, b_last;
        const bgp_ribout_flowspec_ops_t *ao = &a->alternatives[0], *bo = &b->alternatives[0];

        step_range(a, &a_first, &a_last);
        step_range(b, &b_first, &b_last);
        return ao->num_values > 0 && ops_equal(ao, bo, 1) && ao->values[0].op == bo->values[0].op &&
               a_first <= b_last && b_first <= a_last;
    }
    if (a_step || b_step) {
        const bgp_ribout_flowspec_component_t *stepped = a_step ? a : b, *listed = a_step ? b : a;
        const bgp_ribout_flowspec_ops_t       *so = &stepped->alternatives[0];
        uint64_t first, last;

        step_range(stepped, &first, &last);
        for (uint32_t k = 0; k < listed->alternative_count; k++) {
            const bgp_ribout_flowspec_ops_t *lo = &listed->alternatives[k];

            if (so->num_values > 0 && ops_equal(so, lo, 1) && so->values[0].op == lo->values[0].op &&
                lo->values[0].value >= first && lo->values[0].value <= last) {
                return 1;
            }
        }
        return 0;
    }
    for (uint32_t i = 0; i < a->alternative_count; i++) {
        for (uint32_t j = 0; j < b->alternative_count; j++) {
            if (ops_equal(&a->alternatives[i], &b->alternatives[j], 0)) {
                return 1;
            }
        }
    }
    return 0;
}

static int component_equal(const bgp_ribout_flowspec_component_t *a, const bgp_ribout_flowspec_component_t *b) {
    if (a->alternative_count != b->alternative_count || a->step_count != b->step_count || a->rotate != b->rotate) {
        return 0;
    }
    for (uint32_t i = 0; i < a->alternative_count; i++) {
        if (!ops_equal(&a->alternatives[i], &b->alternatives[i], 0)) {
            return 0;
        }
    }
    return 1;
}

/*
 * The rule dimensions: destination and source prefixes and every operator component. A component that only one rule
 * has makes the rules differ.
 */
static int flowspec_rule_overlap(const bgp_ribout_config_t *a, const bgp_ribout_config_t *b) {
    static const bgp_prefix_spec_t none;
    const bgp_ribout_flowspec_t *af = a->flowspec, *bf = b->flowspec;

    if (!prefix_overlap(&a->prefix_spec, a->prefix_offset, &b->prefix_spec, b->prefix_offset) ||
        !prefix_overlap(af ? &af->src_prefix : &none, af ? af->src_offset : 0,
                        bf ? &bf->src_prefix : &none, bf ? bf->src_offset : 0)) {
        return 0;
    }
    for (uint8_t type = FLOWSPEC_IP_PROTOCOL; type <= FLOWSPEC_FLOW_LABEL; type++) {
        uint32_t a_count = af ? af->components[type].alternative_count : 0;
        uint32_t b_count = bf ? bf->components[type].alternative_count : 0;

        if ((a_count == 0) != (b_count == 0)) {
            return 0;
        }
        if (a_count > 0 && !component_overlap(&af->components[type], &bf->components[type])) {
            return 0;
        }
    }
    return 1;
}

static int flowspec_rule_equal(const bgp_ribout_config_t *a, const bgp_ribout_config_t *b) {
    static const bgp_prefix_spec_t none;
    const bgp_ribout_flowspec_t *af = a->flowspec, *bf = b->flowspec;

    if (!prefix_equal(&a->prefix_spec, a->prefix_offset, &b->prefix_spec, b->prefix_offset) ||
        !prefix_equal(af ? &af->src_prefix : &none, af ? af->src_offset : 0,
                      bf ? &bf->src_prefix : &none, bf ? bf->src_offset : 0)) {
        return 0;
    }
    for (uint8_t type = FLOWSPEC_IP_PROTOCOL; type <= FLOWSPEC_FLOW_LABEL; type++) {
        static const bgp_ribout_flowspec_component_t unset;
        const bgp_ribout_flowspec_component_t *ac = af ? &af->components[type] : &unset;
        const bgp_ribout_flowspec_component_t *bc = bf ? &bf->components[type] : &unset;

        if (!component_equal(ac, bc)) {
            return 0;
        }
    }
    return 1;
}

// Snapshot comparison

int bgp_ribout_snapshot_keys_overlap(const bgp_ribout_snapshot_t *a, const bgp_ribout_snapshot_t *b) {
    const bgp_ribout_config_t *ac = a->config, *bc = b->config;

    /*
     * Different families never share a key: they differ in AFI/SAFI, EVPN route type, or the IP length of an EVPN
     * Type 5 prefix.
     */
    if (a->profile.family != b->profile.family) {
        return 0;
    }
    if (!path_id_overlap(a, b)) {
        return 0;
    }
    if (bgp_ribout_family_is_template((bgp_ribout_family_t)a->profile.family)) {
        return bgp_ribout_template_compare_keys(&ac->nlri_template, &bc->nlri_template, 0);
    }
    switch ((bgp_ribout_family_t)a->profile.family) {
        case BGP_RIBOUT_FAMILY_IPV4_UNICAST:
        case BGP_RIBOUT_FAMILY_IPV6_UNICAST:
        case BGP_RIBOUT_FAMILY_LABELED_IPV4:
        case BGP_RIBOUT_FAMILY_LABELED_IPV6:
            return prefix_overlap(&ac->prefix_spec, 0, &bc->prefix_spec, 0);
        case BGP_RIBOUT_FAMILY_VPNV4:
        case BGP_RIBOUT_FAMILY_VPNV6:
            return rd_list_overlap(ac, bc) && prefix_overlap(&ac->prefix_spec, 0, &bc->prefix_spec, 0);
        case BGP_RIBOUT_FAMILY_EVPN_TYPE5_IPV4:
        case BGP_RIBOUT_FAMILY_EVPN_TYPE5_IPV6:
            return rd_list_overlap(ac, bc) &&
                   u32_list_overlap(ac->ethernet_tags, ac->ethernet_tag_count, ac->ethernet_tags_step,
                                    bc->ethernet_tags, bc->ethernet_tag_count, bc->ethernet_tags_step) &&
                   prefix_overlap(&ac->prefix_spec, 0, &bc->prefix_spec, 0);
        case BGP_RIBOUT_FAMILY_EVPN_TYPE2:
            // With ip rotate the keys are MAC/IP pairs, a subset of the cross product: still sound.
            return rd_list_overlap(ac, bc) &&
                   u32_list_overlap(ac->ethernet_tags, ac->ethernet_tag_count, ac->ethernet_tags_step,
                                    bc->ethernet_tags, bc->ethernet_tag_count, bc->ethernet_tags_step) &&
                   mac_overlap(&ac->mac_spec, &bc->mac_spec) && type2_ips_overlap(ac, bc);
        case BGP_RIBOUT_FAMILY_SR_POLICY_IPV4:
        case BGP_RIBOUT_FAMILY_SR_POLICY_IPV6:
            return u32_list_overlap(ac->distinguishers, ac->distinguisher_count, ac->distinguishers_step,
                                    bc->distinguishers, bc->distinguisher_count, bc->distinguishers_step) &&
                   u32_list_overlap(ac->colors, ac->color_count, ac->colors_step, bc->colors, bc->color_count, bc->colors_step) &&
                   host_overlap(&ac->endpoint_spec, &bc->endpoint_spec);
        case BGP_RIBOUT_FAMILY_FLOWSPEC_IPV4:
        case BGP_RIBOUT_FAMILY_FLOWSPEC_IPV6:
            return flowspec_rule_overlap(ac, bc);
        case BGP_RIBOUT_FAMILY_FLOWSPEC_VPN_IPV4:
        case BGP_RIBOUT_FAMILY_FLOWSPEC_VPN_IPV6:
            return rd_list_overlap(ac, bc) && flowspec_rule_overlap(ac, bc);
        default:
            return 1;
    }
}

int bgp_ribout_snapshot_same_keys(const bgp_ribout_snapshot_t *a, const bgp_ribout_snapshot_t *b) {
    const bgp_ribout_config_t *ac = a->config, *bc = b->config;

    if (a->profile.family != b->profile.family || !path_id_equal(a, b) || !rotation_layout_equal(ac, bc)) {
        return 0;
    }
    if (bgp_ribout_family_is_template((bgp_ribout_family_t)a->profile.family)) {
        return bgp_ribout_template_compare_keys(&ac->nlri_template, &bc->nlri_template, 1);
    }
    switch ((bgp_ribout_family_t)a->profile.family) {
        case BGP_RIBOUT_FAMILY_IPV4_UNICAST:
        case BGP_RIBOUT_FAMILY_IPV6_UNICAST:
        case BGP_RIBOUT_FAMILY_LABELED_IPV4:
        case BGP_RIBOUT_FAMILY_LABELED_IPV6:
            return prefix_equal(&ac->prefix_spec, 0, &bc->prefix_spec, 0);
        case BGP_RIBOUT_FAMILY_VPNV4:
        case BGP_RIBOUT_FAMILY_VPNV6:
            return rd_list_equal(ac, bc) && prefix_equal(&ac->prefix_spec, 0, &bc->prefix_spec, 0);
        case BGP_RIBOUT_FAMILY_EVPN_TYPE5_IPV4:
        case BGP_RIBOUT_FAMILY_EVPN_TYPE5_IPV6:
            return rd_list_equal(ac, bc) && tag_list_equal(ac, bc) &&
                   prefix_equal(&ac->prefix_spec, 0, &bc->prefix_spec, 0);
        case BGP_RIBOUT_FAMILY_EVPN_TYPE2:
            return rd_list_equal(ac, bc) && tag_list_equal(ac, bc) &&
                   memcmp(ac->mac_spec.base_addr, bc->mac_spec.base_addr, 6) == 0 &&
                   bgp_ribout_effective_count(ac->mac_spec.count) == bgp_ribout_effective_count(bc->mac_spec.count) &&
                   host_equal(&ac->ip_spec, &bc->ip_spec) && ac->ip_rotate == bc->ip_rotate &&
                   host_equal(&ac->ip2_spec, &bc->ip2_spec) && ac->ip2_rotate == bc->ip2_rotate;
        case BGP_RIBOUT_FAMILY_SR_POLICY_IPV4:
        case BGP_RIBOUT_FAMILY_SR_POLICY_IPV6:
            return ac->distinguisher_rotate == bc->distinguisher_rotate && ac->color_rotate == bc->color_rotate &&
                   ac->endpoint_rotate == bc->endpoint_rotate &&
                   u32_list_equal(ac->distinguishers, ac->distinguisher_count, ac->distinguishers_step,
                                  bc->distinguishers, bc->distinguisher_count, bc->distinguishers_step) &&
                   u32_list_equal(ac->colors, ac->color_count, ac->colors_step, bc->colors, bc->color_count, bc->colors_step) &&
                   host_equal(&ac->endpoint_spec, &bc->endpoint_spec);
        case BGP_RIBOUT_FAMILY_FLOWSPEC_IPV4:
        case BGP_RIBOUT_FAMILY_FLOWSPEC_IPV6:
            return flowspec_rule_equal(ac, bc);
        case BGP_RIBOUT_FAMILY_FLOWSPEC_VPN_IPV4:
        case BGP_RIBOUT_FAMILY_FLOWSPEC_VPN_IPV6:
            return rd_list_equal(ac, bc) && flowspec_rule_equal(ac, bc);
        default:
            return 0;
    }
}
