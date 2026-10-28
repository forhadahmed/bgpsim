#define OUTPUT_STDIO_REMAP

#include <time.h>
#include <ctype.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "bgp.h"
#include "log.h"
#include "util.h"
#include "output.h"
#include "bgp_ribout.h"
#include "bgp_update.h"
#include "bgp_ribout_config.h"
#include "bgp_ribout_snapshot.h"

// Optimization: Use stack allocation for common AS-path sizes
#define MAX_ASPATH_SEGMENTS_STACK         10
#define BGP_RIBOUT_ARENA_CHUNK_SIZE       16384
#define BGP_RIBOUT_NLRI_CHUNK_TARGET_SIZE 1024
/*
 * Many stress workloads collapse to one NLRI per attribute entry. Allocating
 * a full ~1KB chunk for the very first NLRI in every entry dominates map
 * memory in those cases, so start each entry with a single-record chunk and
 * keep the existing larger target only for follow-on growth.
 */
#define BGP_RIBOUT_NLRI_CHUNK_FIRST_CAPACITY 1

// Hash Function

/*
 * Group-key hash. One running 64-bit state takes each field in turn, 8 octets at a time, so equal values in two
 * fields do not cancel (as they do when separate field hashes are XORed) and a field costs one multiply per 8 octets
 * instead of one per octet.
 *
 * The hash only selects a bucket: path_attr_equal() compares the full attributes, so a collision costs time, not a
 * wrong group. The map uses the low bits (hash & bucket_mask), so every step must also move high bits down.
 *
 * The seed is the first 64 bits of the fraction of pi. Any fixed nonzero value works; a well-known value shows that
 * nobody tuned it.
 */
#define RIBOUT_HASH_SEED 0x243F6A8885A308D3ull

/*
 * Mix one 64-bit word into the state. The multiplier is 2^64 divided by the golden ratio (the odd constant of
 * Fibonacci hashing): the multiply spreads each input bit into all the higher bits. A multiply cannot move a bit down,
 * so the shift then folds the high half into the low half, where the bucket mask looks.
 */
static inline uint64_t ribout_hash_mix(uint64_t h, uint64_t v) {
    h ^= v;
    h *= 0x9E3779B97F4A7C15ull;
    return h ^ (h >> 32);
}

/*
 * Add len octets to the state, one 8-octet word at a time. memcpy() reads a word at any alignment (the compiler makes
 * it one load). The last 0 to 7 octets go into a zeroed word, with the length in its top octet: so "ab" + "c" differs
 * from "a" + "bc", and an extra zero octet changes the hash. A word value depends on the host byte order; that is
 * correct because the hash never leaves this process.
 */
static uint64_t ribout_hash_bytes(uint64_t h, const void *data, size_t len) {
    const uint8_t *p = data;
    uint64_t       last = 0;

    for (; len >= 8; p += 8, len -= 8) {
        uint64_t v;

        memcpy(&v, p, 8);
        h = ribout_hash_mix(h, v);
    }
    memcpy(&last, p, len);
    return ribout_hash_mix(h, last ^ ((uint64_t)len << 56));
}

/*
 * Reduce the state to the 32-bit hash that the map keeps (path_attr_entry_t.attr_hash). ribout_hash_mix() already
 * folded the halves once; a second fold at a different shift mixes the low 32 bits again.
 */
static inline uint32_t ribout_hash_fold(uint64_t h) {
    return (uint32_t)(h ^ (h >> 29));
}

static uint32_t ribout_seed_from_name(const char *name) {
    uint32_t hash = 2166136261u;

    if (!name || name[0] == '\0') {
        return 0xA341316Cu;
    }

    while (*name) {
        hash ^= (uint8_t)*name++;
        hash *= 16777619u;
    }

    return (hash == 0) ? 0xA341316Cu : hash;
}

static int ribout_parse_env_seed(uint32_t *seed) {
    const char *value;
    char       *endptr = NULL;
    unsigned long parsed;

    if (!seed) {
        return 0;
    }

    value = getenv("RANDSEED");
    if (!value || *value == '\0') {
        return 0;
    }

    parsed = strtoul(value, &endptr, 10);
    if (endptr == value || *endptr != '\0' || parsed > UINT32_MAX) {
        return 0;
    }

    *seed = (uint32_t)parsed;
    return 1;
}

static uint32_t ribout_initial_seed(const char *name) {
    uint32_t env_seed;
    uint32_t name_seed = ribout_seed_from_name(name);

    /*
     * A process-wide RANDSEED keeps configs uncluttered while still deriving
     * independent per-ribout streams from the ribout name. The stream stays
     * stable regardless of ribout execution order because the generator owns
     * its local random state after initialization.
     */
    if (!ribout_parse_env_seed(&env_seed)) {
        return name_seed;
    }

    name_seed ^= env_seed + 0x9e3779b9u + (name_seed << 6) + (name_seed >> 2);
    return (name_seed == 0) ? 0xA341316Cu : name_seed;
}

static uint32_t ribout_seed_state(uint32_t seed) {
    return (seed == 0) ? 0xA341316Cu : seed;
}

static uint32_t ribout_next_random(bgp_ribout_gen_t *gen) {
    uint32_t x;

    if (!gen) {
        return 0xA341316Cu;
    }

    x = ribout_seed_state(gen->random_state);
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    gen->random_state = ribout_seed_state(x);
    return gen->random_state;
}

static uint32_t ribout_random_bounded(bgp_ribout_gen_t *gen, uint32_t max) {
    if (max == 0) {
        return 0;
    }

    return (ribout_next_random(gen) % max) + 1;
}

static uint32_t ribout_random_bounded_range(bgp_ribout_gen_t *gen, uint32_t start, uint32_t end) {
    uint64_t span;

    if (end < start) {
        return start;
    }

    span = (uint64_t)end - (uint64_t)start + 1ULL;
    return start + (uint32_t)(ribout_next_random(gen) % span);
}

static uint32_t ribout_u32_val(const bgp_u32_spec_t *spec, bgp_ribout_gen_t *gen, uint32_t *index) {
    uint64_t span;
    uint32_t current = 0;

    if (!spec) {
        return 0;
    }

    switch (spec->mode) {
        case BGP_U32_MODE_FIXED:
            return spec->value;
        case BGP_U32_MODE_RANDOM:
            return ribout_random_bounded(gen, spec->value);
        case BGP_U32_MODE_RANGE:
            if (spec->range_end < spec->range_start) {
                return spec->range_start;
            }
            span = (uint64_t)spec->range_end - (uint64_t)spec->range_start + 1ULL;
            if (index) {
                current = *index;
                (*index)++;
            }
            return spec->range_start + (uint32_t)(current % span);
        case BGP_U32_MODE_RANDOM_RANGE:
            return ribout_random_bounded_range(gen, spec->range_start, spec->range_end);
        default:
            return spec->value;
    }
}

static uint32_t ribout_u32_opt_val(const bgp_u32_optional_spec_t *spec, bgp_ribout_gen_t *gen, uint32_t *index) {
    bgp_u32_spec_t base;

    if (!spec) {
        return 0;
    }

    base.mode = spec->mode;
    base.value = spec->value;
    base.range_start = spec->range_start;
    base.range_end = spec->range_end;
    return ribout_u32_val(&base, gen, index);
}

static size_t round_up_power_of_two(size_t value) {
    size_t rounded = 1;

    while (rounded < value) {
        if (rounded > (SIZE_MAX / 2)) {
            return 0;
        }
        rounded <<= 1;
    }

    return rounded;
}

static size_t bgp_ribout_map_bucket_hint(uint64_t total_paths) {
    uint64_t target;

    if (total_paths <= RIBOUT_HASHMAP_DEFAULT_SIZE) {
        return RIBOUT_HASHMAP_DEFAULT_SIZE;
    }

    /*
     * The generator knows an upper bound on emitted paths before map
     * construction starts. Size buckets from that bound so adversarial
     * one-path-per-group workloads do not spend most of their time walking
     * long hash chains from the tiny default 256-bucket map.
     */
    target = total_paths * 2ULL;
    if (target < total_paths) {
        target = total_paths;
    }
    if (target > (uint64_t)SIZE_MAX) {
        return (size_t)total_paths;
    }

    return (size_t)target;
}

static size_t bgp_ribout_map_bucket_compact_target(size_t entry_count) {
    uint64_t target;
    size_t   rounded;

    if (entry_count <= (RIBOUT_HASHMAP_DEFAULT_SIZE / 2)) {
        return RIBOUT_HASHMAP_DEFAULT_SIZE;
    }

    target = (uint64_t)entry_count * 2ULL;
    if (target < entry_count) {
        return 0;
    }
    if (target > (uint64_t)SIZE_MAX) {
        return 0;
    }

    rounded = round_up_power_of_two((size_t)target);
    return rounded;
}

static inline size_t bgp_ribout_bucket_index(const bgp_ribout_map_t *map, uint32_t hash) {
    return ((size_t)hash) & map->bucket_mask;
}

typedef struct {
    const uint8_t *aspath_data;           /* Serialized AS path bytes   */
    uint16_t       aspath_data_len;       /* Size of aspath_data        */
    uint16_t       aspath_segment_count;  /* Number of AS path segments */
    uint32_t       aspath_hash;           /* Precomputed AS path hash   */
    int            has_aspath;            /* AS path present if set     */
} bgp_attr_hash_cache_t;

typedef struct {
    const route_distinguisher_t *rd;                 /* Route distinguisher        */
    const evpn_esi_t            *esi;                /* EVPN ESI                   */
    const void                  *prefix_addr;        /* Prefix address             */
    const uint8_t               *mac_addr;           /* EVPN Type 2 MAC            */
    const void                  *ip_addr;            /* EVPN Type 2 optional IP    */
    const void                  *gateway_ip_addr;    /* EVPN gateway IP            */
    const void                  *endpoint_addr;      /* SR Policy endpoint         */
    uint32_t                     label;              /* MPLS label                 */
    uint32_t                     label2;             /* EVPN Type 2 Label2         */
    uint32_t                     ethernet_tag_id;    /* EVPN Ethernet Tag ID       */
    uint32_t                     distinguisher;      /* SR Policy distinguisher    */
    uint32_t                     color;              /* SR Policy color            */
    uint32_t                     path_id;            /* Path ID                    */
    uint8_t                      prefix_len;         /* Prefix length              */
    uint8_t                      prefix_af;          /* Address family             */
    uint8_t                      ip_af;              /* EVPN Type 2 IP AF          */
    uint8_t                      gateway_ip_af;      /* Gateway IP address family  */
    uint8_t                      endpoint_af;        /* SR endpoint address family */
    uint8_t                      nlri_type;          /* Explicit NLRI type         */
    uint8_t                      has_rd;             /* RD present if set          */
    uint8_t                      has_label;          /* Label present if set       */
    uint8_t                      has_label2;         /* Label2 present if set      */
    uint8_t                      label_vni;          /* EVPN labels are VNIs       */
    uint8_t                      has_esi;            /* ESI present if set         */
    uint8_t                      has_mac;            /* MAC present if set         */
    uint8_t                      has_ip;             /* IP present if set          */
    uint8_t                      has_ethernet_tag;   /* Ethernet Tag if set        */
    uint8_t                      has_gateway_ip;     /* Gateway IP if set          */
    uint8_t                      has_endpoint;       /* SR endpoint if set         */
    uint64_t                     flowspec_instance;  /* FlowSpec NLRI instance     */
    uint8_t                      has_flowspec;       /* FlowSpec NLRI if set       */
    uint64_t                     template_instance;
} bgp_nlri_input_t;

typedef struct bgp_ribout_arena_chunk {
    struct bgp_ribout_arena_chunk *next;
    size_t                         used;
    size_t                         size;
    uint8_t                        data[];
} bgp_ribout_arena_chunk_t;

typedef struct {
    uint8_t  type;
    uint8_t  length;
    uint16_t reserved;
} bgp_aspath_seg_hdr_t;

typedef struct {
    const uint8_t *data;             /* Active data pointer (stack or heap) */
    uint8_t       *heap_data;        /* Heap-allocated data (NULL if stack) */
    uint16_t       data_len;         /* Size of serialized AS path data     */
    uint16_t       segment_count;    /* Number of AS path segments          */
    uint32_t       hash;             /* Precomputed AS path hash            */
    int            has_aspath;       /* AS path present if set              */
    uint8_t        stack_data[512];  /* Inline buffer for small AS paths    */
} bgp_temp_aspath_t;

static void bgp_ribout_temp_aspath_init(bgp_temp_aspath_t *temp) {
    temp->data = NULL;
    temp->heap_data = NULL;
    temp->data_len = 0;
    temp->segment_count = 0;
    temp->hash = 0;
    temp->has_aspath = 0;
}

static void bgp_ribout_temp_aspath_release(bgp_temp_aspath_t *temp) {
    free(temp->heap_data);
    bgp_ribout_temp_aspath_init(temp);
}

static size_t bgp_ribout_arena_align(size_t value, size_t align) {
    return (value + (align - 1)) & ~(align - 1);
}

static void bgp_ribout_arena_release(bgp_ribout_map_t *map) {
    bgp_ribout_arena_chunk_t *chunk = map->arena_chunks;

    while (chunk) {
        bgp_ribout_arena_chunk_t *next = chunk->next;
        free(chunk);
        chunk = next;
    }

    map->arena_chunks = NULL;
}

static void *bgp_ribout_arena_alloc(bgp_ribout_map_t *map, size_t size, size_t align) {
    bgp_ribout_arena_chunk_t *chunk;
    size_t                    offset;

    if (!map || size == 0) {
        return NULL;
    }

    if (align == 0) {
        align = sizeof(void *);
    }

    chunk = map->arena_chunks;
    if (chunk) {
        offset = bgp_ribout_arena_align(chunk->used, align);
        if (offset + size <= chunk->size) {
            void *ptr = chunk->data + offset;
            chunk->used = offset + size;
            return ptr;
        }
    }

    size_t chunk_size = map->arena_chunk_size;
    size_t min_size = bgp_ribout_arena_align(size, align);
    if (chunk_size < min_size) {
        chunk_size = min_size;
    }

    chunk = malloc(sizeof(*chunk) + chunk_size);
    if (!chunk) {
        return NULL;
    }

    chunk->next = map->arena_chunks;
    chunk->used = 0;
    chunk->size = chunk_size;
    map->arena_chunks = chunk;
    map->memory_usage += sizeof(*chunk) + chunk_size;

    offset = bgp_ribout_arena_align(chunk->used, align);
    chunk->used = offset + size;

    return chunk->data + offset;
}

static uint8_t bgp_ribout_nlri_type(const bgp_nlri_input_t *nlri) {
    if (nlri->nlri_type != 0) {
        return nlri->nlri_type;
    }

    if (nlri->has_rd) {
        if (nlri->has_mac) {
            return BGP_RIBOUT_NLRI_TYPE_EVPN_TYPE2;
        }
        if (nlri->has_ethernet_tag || nlri->has_gateway_ip || nlri->has_esi) {
            return (nlri->prefix_af == AF_INET) ?
                BGP_RIBOUT_NLRI_TYPE_EVPN_TYPE5_IPV4 :
                BGP_RIBOUT_NLRI_TYPE_EVPN_TYPE5_IPV6;
        }

        return (nlri->prefix_af == AF_INET) ?
            BGP_RIBOUT_NLRI_TYPE_VPNV4 :
            BGP_RIBOUT_NLRI_TYPE_VPNV6;
    }

    if (nlri->prefix_af == AF_INET) {
        return nlri->has_label ? BGP_RIBOUT_NLRI_TYPE_LABELED_IPV4 :
                                 BGP_RIBOUT_NLRI_TYPE_IPV4;
    }

    return nlri->has_label ? BGP_RIBOUT_NLRI_TYPE_LABELED_IPV6 :
                             BGP_RIBOUT_NLRI_TYPE_IPV6;
}

/*
 * The bgp_ribout_families[] row of an NLRI type (types and families share
 * their numbers).
 */
static const bgp_ribout_family_info_t *bgp_ribout_nlri_info(uint8_t nlri_type) {
    return bgp_ribout_family_info((bgp_ribout_family_t)nlri_type);
}

/*
 * Grouped-map NLRI type of a family: the same number, or 0 for BGP_RIBOUT_FAMILY_NONE.
 */
static uint8_t bgp_ribout_family_nlri_type(bgp_ribout_family_t family) {
    return bgp_ribout_family_info(family)->kind != BGP_RIBOUT_KIND_NONE ? (uint8_t)family : 0;
}

/*
 * Return 1 for the SR Policy families.
 */
static int bgp_ribout_family_is_srpolicy(bgp_ribout_family_t family) {
    return bgp_ribout_family_info(family)->kind == BGP_RIBOUT_KIND_SR_POLICY;
}

/*
 * Return 1 for the EVPN Type 2 family.
 */
static int bgp_ribout_family_is_evpn_type2(bgp_ribout_family_t family) {
    return bgp_ribout_family_info(family)->kind == BGP_RIBOUT_KIND_EVPN_TYPE2;
}

/*
 * Return 1 for the EVPN families: Type 2 and Type 5.
 */
static int bgp_ribout_family_is_evpn(bgp_ribout_family_t family) {
    return family == BGP_RIBOUT_FAMILY_EVPN_TYPE2 || family == BGP_RIBOUT_FAMILY_EVPN_TYPE5_IPV4 ||
           family == BGP_RIBOUT_FAMILY_EVPN_TYPE5_IPV6;
}

/*
 * Return 1 when an Encapsulation extended community (RFC 9012) names a tunnel whose EVPN label fields carry a 24-bit
 * VNI rather than an MPLS label: VXLAN (8), NVGRE (9) and VXLAN-GPE (12) (RFC 8365 section 5.1.3), and Geneve (19).
 */
static int bgp_ribout_encap_carries_vni(const bgp_ext_comm_t *encap) {
    uint16_t tunnel_type = (uint16_t)((encap->bytes[6] << 8) | encap->bytes[7]);

    return tunnel_type == 8 || tunnel_type == 9 || tunnel_type == 12 || tunnel_type == 19;
}

/*
 * Return 1 when every path of the block carries a VNI encapsulation, so that its labels are VNIs.
 */
static int bgp_ribout_labels_are_vnis(const bgp_ribout_config_t *block, bgp_ribout_family_t family) {
    if (!bgp_ribout_family_is_evpn(family) || block->encap_count == 0) {
        return 0;
    }
    for (uint32_t i = 0; i < block->encap_count; i++) {
        if (!bgp_ribout_encap_carries_vni(&block->encap_values[i])) {
            return 0;
        }
    }
    return 1;
}

/*
 * RDs along the key dimension: all of them, or one per path with rd rotate.
 */
static uint32_t bgp_ribout_rd_dimension(const bgp_ribout_config_t *block) {
    return bgp_ribout_effective_count(block->rd_rotate ? 0 : block->rd_count);
}

/*
 * The other key lists the same way: a rotating list is one value per path, a dimension of 1. An empty Ethernet tag
 * or path-ID list is one value too (tag 0, no path ID).
 */
static uint32_t bgp_ribout_tag_dimension(const bgp_ribout_config_t *block) {
    return bgp_ribout_effective_count(block->ethernet_tag_rotate ? 0 : block->ethernet_tag_count);
}

static uint32_t bgp_ribout_path_id_dimension(const bgp_ribout_config_t *block) {
    return bgp_ribout_effective_count(block->path_id_rotate ? 0 : block->path_id_count);
}

/*
 * SR Policy needs all three lists: an empty one stays a dimension of 0, so the block makes no paths.
 */
static uint32_t bgp_ribout_distinguisher_dimension(const bgp_ribout_config_t *block) {
    return block->distinguisher_rotate ? 1 : block->distinguisher_count;
}

static uint32_t bgp_ribout_color_dimension(const bgp_ribout_config_t *block) {
    return block->color_rotate ? 1 : block->color_count;
}

static uint32_t bgp_ribout_endpoint_dimension(const bgp_ribout_config_t *block) {
    return block->endpoint_rotate ? 1 : block->endpoint_spec.count;
}

/*
 * The rotation step of path number paths: rotations advance once every rotate_every paths.
 */
static uint64_t bgp_ribout_rotation(const bgp_ribout_config_t *block, uint64_t paths) {
    return paths / (block->rotate_every ? block->rotate_every : 1);
}

/*
 * EVPN Type 2 IPs along the key dimension: per address family (ip_spec, then ip2_spec), all its IPs, or one per
 * MAC with ip rotate; 1 for MAC-only routes.
 */
static uint32_t bgp_ribout_type2_ip_width(const bgp_ribout_config_t *block, int slot) {
    const bgp_next_hop_spec_t *spec = slot ? &block->ip2_spec : &block->ip_spec;

    if (spec->count == 0) {
        return 0;
    }
    return (slot ? block->ip2_rotate : block->ip_rotate) ? 1 : spec->count;
}

static uint64_t bgp_ribout_type2_ip_dimension(const bgp_ribout_config_t *block) {
    uint64_t count = (uint64_t)bgp_ribout_type2_ip_width(block, 0) + bgp_ribout_type2_ip_width(block, 1);
    return count ? count : 1;
}

/*
 * Return the largest configured label or label2 value.
 */
static uint32_t bgp_ribout_max_label(const bgp_ribout_config_t *block) {
    uint32_t max = 0;

    if (block->labels_step && block->label_count) max = bgp_ribout_labels_at(block, block->label_count - 1);
    for (uint32_t i = 0; !block->labels_step && i < block->label_count; i++) {
        max = (bgp_ribout_labels_at(block, i) > max) ? bgp_ribout_labels_at(block, i) : max;
    }
    if (block->label2s_step && block->label2_count) {
        uint32_t last = bgp_ribout_label2s_at(block, block->label2_count - 1);
        if (last > max) max = last;
    }
    for (uint32_t i = 0; !block->label2s_step && i < block->label2_count; i++) {
        max = (bgp_ribout_label2s_at(block, i) > max) ? bgp_ribout_label2s_at(block, i) : max;
    }
    return max;
}

/*
 * Return 1 for labeled-unicast NLRI records.
 */
static int bgp_ribout_nlri_is_labeled(uint8_t nlri_type) {
    return bgp_ribout_nlri_info(nlri_type)->has_label;
}

/*
 * Return 1 for SR Policy NLRI records.
 */
static int bgp_ribout_nlri_is_srpolicy(uint8_t nlri_type) {
    return bgp_ribout_nlri_info(nlri_type)->kind == BGP_RIBOUT_KIND_SR_POLICY;
}

/*
 * Return 1 for EVPN Type 2 NLRI records.
 */
static int bgp_ribout_nlri_is_evpn_type2(uint8_t nlri_type) {
    return bgp_ribout_nlri_info(nlri_type)->kind == BGP_RIBOUT_KIND_EVPN_TYPE2;
}

/*
 * Return 1 for FlowSpec NLRI records.
 */
static int bgp_ribout_nlri_is_flowspec(uint8_t nlri_type) {
    return bgp_ribout_nlri_info(nlri_type)->kind == BGP_RIBOUT_KIND_FLOWSPEC;
}

/*
 * Return 1 when the record holds an IP prefix (unicast, labeled-unicast, VPN, EVPN Type 5). Type 0 counts as a prefix
 * record.
 */
static int bgp_ribout_nlri_uses_prefix(uint8_t nlri_type) {
    return !bgp_ribout_nlri_is_srpolicy(nlri_type) &&
           !bgp_ribout_nlri_is_evpn_type2(nlri_type) &&
           !bgp_ribout_nlri_is_flowspec(nlri_type) &&
           bgp_ribout_nlri_info(nlri_type)->kind != BGP_RIBOUT_KIND_TEMPLATE;
}

/*
 * Most ribout families are keyed by a conventional prefix. Today there are
 * two exceptions: SR Policy NLRIs are keyed by endpoint, and EVPN type 2
 * host-bindings are keyed by MAC/IP payload rather than prefix. Keep that
 * shape switch in one helper so the generic map path does not open-code
 * family-specific pointer selection at every call site.
 */
static int bgp_ribout_nlri_input_validate(uint8_t nlri_type, const bgp_nlri_input_t *nlri_in) {
    if (bgp_ribout_nlri_uses_prefix(nlri_type)) {
        return (nlri_in->prefix_addr != NULL) ? 0 : -1;
    }
    if (bgp_ribout_nlri_is_srpolicy(nlri_type)) {
        return (nlri_in->endpoint_addr != NULL) ? 0 : -1;
    }
    if (bgp_ribout_nlri_is_evpn_type2(nlri_type)) {
        return (nlri_in->mac_addr != NULL) ? 0 : -1;
    }
    if (bgp_ribout_nlri_is_flowspec(nlri_type)) {
        return nlri_in->has_flowspec ? 0 : -1;
    }

    return 0;
}

static const void *bgp_ribout_path_prefix_addr(const bgp_gen_path_t *path, uint8_t nlri_type) {
    if (!bgp_ribout_nlri_uses_prefix(nlri_type)) {
        return NULL;
    }

    return (path->prefix_af == AF_INET) ?
        (const void *)&path->prefix_addr.ipv4 :
        (const void *)&path->prefix_addr.ipv6;
}

/*
 * Copy the NLRI fields of one generated path into the map insert input for nlri_type.
 */
static void bgp_ribout_build_nlri_input(const bgp_gen_path_t *path, uint8_t nlri_type, bgp_nlri_input_t *nlri_in) {
    memset(nlri_in, 0, sizeof(*nlri_in));

    nlri_in->prefix_addr = bgp_ribout_path_prefix_addr(path, nlri_type);
    nlri_in->prefix_len = path->prefix_len;
    nlri_in->prefix_af = path->prefix_af;
    nlri_in->rd = path->has_rd ? &path->rd : NULL;
    nlri_in->has_rd = path->has_rd;
    nlri_in->label = path->label;
    nlri_in->has_label = path->has_label;
    nlri_in->label2 = path->label2;
    nlri_in->has_label2 = path->has_label2;
    nlri_in->label_vni = path->label_vni;
    nlri_in->esi = path->has_esi ? &path->esi : NULL;
    nlri_in->has_esi = path->has_esi;
    nlri_in->mac_addr = path->has_mac ? path->mac_addr : NULL;
    nlri_in->has_mac = path->has_mac;
    nlri_in->ip_addr = path->has_ip ?
                           ((path->ip_af == AF_INET) ?
                               (const void *)&path->ip_addr.ipv4 :
                               (const void *)&path->ip_addr.ipv6) :
                           NULL;
    nlri_in->ip_af = path->ip_af;
    nlri_in->has_ip = path->has_ip;
    nlri_in->ethernet_tag_id = path->ethernet_tag_id;
    nlri_in->has_ethernet_tag = path->has_ethernet_tag;
    nlri_in->gateway_ip_addr = path->has_gateway_ip ?
                                   ((path->gateway_ip_af == AF_INET) ?
                                       (const void *)&path->gateway_ip_addr.ipv4 :
                                       (const void *)&path->gateway_ip_addr.ipv6) :
                                   NULL;
    nlri_in->gateway_ip_af = path->gateway_ip_af;
    nlri_in->has_gateway_ip = path->has_gateway_ip;
    nlri_in->endpoint_addr = path->has_endpoint ?
                                 ((path->endpoint_af == AF_INET) ?
                                     (const void *)&path->endpoint_addr.ipv4 :
                                     (const void *)&path->endpoint_addr.ipv6) :
                                 NULL;
    nlri_in->endpoint_af = path->endpoint_af;
    nlri_in->has_endpoint = path->has_endpoint;
    nlri_in->distinguisher = path->distinguisher;
    nlri_in->color = path->color;
    nlri_in->flowspec_instance = path->flowspec_instance;
    nlri_in->template_instance = path->template_instance;
    nlri_in->has_flowspec = path->has_flowspec;
    nlri_in->nlri_type = nlri_type;
    nlri_in->path_id = path->path_id;
}

/*
 * Size of one grouped-map record of nlri_type, from bgp_ribout_families[]; 0 for an unknown type.
 */
static size_t bgp_ribout_nlri_stride(uint8_t nlri_type) {
    return bgp_ribout_nlri_info(nlri_type)->nlri_stride;
}

static uint16_t bgp_ribout_nlri_chunk_capacity(size_t stride) {
    size_t capacity;

    if (stride == 0) {
        return 0;
    }

    capacity = BGP_RIBOUT_NLRI_CHUNK_TARGET_SIZE / stride;
    if (capacity == 0) {
        capacity = 1;
    }

    return (uint16_t)capacity;
}

static bgp_ribout_nlri_chunk_t *bgp_ribout_nlri_chunk_create(
    bgp_ribout_map_t *map,
    uint8_t nlri_type,
    uint16_t capacity_override) {
    size_t stride = bgp_ribout_nlri_stride(nlri_type);
    uint16_t capacity = capacity_override ?
        capacity_override :
        bgp_ribout_nlri_chunk_capacity(stride);
    size_t                   bytes = sizeof(bgp_ribout_nlri_chunk_t) + ((size_t)capacity * stride);
    bgp_ribout_nlri_chunk_t *chunk;

    if (stride == 0 || capacity == 0) {
        return NULL;
    }

    chunk = bgp_ribout_arena_alloc(map, bytes, _Alignof(bgp_ribout_nlri_chunk_t));
    if (!chunk) {
        return NULL;
    }

    chunk->next = NULL;
    chunk->count = 0;
    chunk->capacity = capacity;
    chunk->stride = (uint16_t)stride;
    chunk->reserved = 0;

    return chunk;
}

static int bgp_ribout_aspath_has_random(const bgp_aspath_segment_t *aspath_segments, uint32_t aspath_segment_count) {
    uint32_t i;

    for (i = 0; i < aspath_segment_count; i++) {
        if (aspath_segments[i].type == ASPATH_RANDOM) {
            return 1;
        }
    }

    return 0;
}

static size_t bgp_ribout_aspath_packed_size(
    const bgp_aspath_segment_t *aspath_segments,
    uint32_t aspath_segment_count) {
    size_t   total = 0;
    uint32_t i;

    for (i = 0; i < aspath_segment_count; i++) {
        const bgp_aspath_segment_t *seg = &aspath_segments[i];
        uint32_t value_count =
            (seg->type == ASPATH_RANDOM) ? seg->rand_count : seg->value_count;

        total += sizeof(bgp_aspath_seg_hdr_t) +
                 ((size_t)value_count * sizeof(uint32_t));
    }

    return total;
}

static int bgp_ribout_temp_aspath_build(
    const bgp_aspath_segment_t *aspath_segments,
    uint32_t aspath_segment_count,
    bgp_temp_aspath_t *temp) {
    uint8_t *cursor;
    size_t   packed_size;
    uint32_t i;

    bgp_ribout_temp_aspath_init(temp);

    if (!aspath_segments || aspath_segment_count == 0) {
        return 0;
    }

    packed_size = bgp_ribout_aspath_packed_size(aspath_segments, aspath_segment_count);
    if (packed_size == 0) {
        return 0;
    }
    if (packed_size > UINT16_MAX) {
        return -1;
    }

    if (packed_size <= sizeof(temp->stack_data)) {
        temp->data = temp->stack_data;
    } else {
        temp->heap_data = malloc(packed_size);
        if (!temp->heap_data) {
            return -1;
        }
        temp->data = temp->heap_data;
    }

    temp->data_len = (uint16_t)packed_size;
    temp->segment_count = (uint16_t)aspath_segment_count;
    temp->has_aspath = 1;
    cursor = (uint8_t *)temp->data;

    for (i = 0; i < aspath_segment_count; i++) {
        const bgp_aspath_segment_t *seg = &aspath_segments[i];
        bgp_aspath_seg_hdr_t *hdr =
            (bgp_aspath_seg_hdr_t *)cursor;
        uint32_t value_count =
            (seg->type == ASPATH_RANDOM) ? seg->rand_count : seg->value_count;
        uint32_t *values;

        hdr->type = (seg->type == ASPATH_SET) ? ASPATH_SET : ASPATH_SEQUENCE;
        hdr->length = (uint8_t)value_count;
        hdr->reserved = 0;
        cursor += sizeof(*hdr);

        values = (uint32_t *)cursor;
        if (seg->type == ASPATH_RANDOM) {
            memcpy(values, seg->as_values, value_count * sizeof(uint32_t));
        } else if (value_count > 0) {
            memcpy(values, seg->as_values, value_count * sizeof(uint32_t));
        }

        cursor += (size_t)value_count * sizeof(uint32_t);
    }

    /*
     * The AS path gets its own hash here. The group hash takes it as one 32-bit value, so a block with a fixed AS
     * path hashes the AS path once (hash_cache), not once per path.
     */
    temp->hash = ribout_hash_fold(ribout_hash_bytes(RIBOUT_HASH_SEED, temp->data, temp->data_len));

    return 0;
}

/*
 * Hash of every attribute that splits groups: next hop (with link-local), AS path (taken from hash_cache when given),
 * MED, the SR Policy tunnel fields, extended communities, attribute 25 communities, LOCAL_PREF and ORIGIN.
 * path_attr_equal() settles hash collisions.
 */
static uint32_t bgp_ribout_map_hash_attributes_internal(
    const bgp_path_attrs_t *attrs,
    const bgp_attr_hash_cache_t *hash_cache) {
    uint64_t h = RIBOUT_HASH_SEED;
    uint32_t aspath_hash = 0;

    if (attrs->next_hop_addr) {
        h = ribout_hash_bytes(h, attrs->next_hop_addr,
                              (attrs->next_hop_af == AF_INET) ? sizeof(struct in_addr) : sizeof(struct in6_addr));
    }
    if (attrs->next_hop_has_link_local && attrs->next_hop_link_local) {
        h = ribout_hash_bytes(h, attrs->next_hop_link_local, sizeof(struct in6_addr));
    }

    if (hash_cache && hash_cache->has_aspath) {
        aspath_hash = hash_cache->aspath_hash;
    } else if (attrs->aspath_segments && attrs->aspath_segment_count > 0) {
        bgp_temp_aspath_t temp;

        if (bgp_ribout_temp_aspath_build(attrs->aspath_segments,
                                         attrs->aspath_segment_count,
                                         &temp) == 0 && temp.has_aspath) {
            aspath_hash = temp.hash;
        }
        bgp_ribout_temp_aspath_release(&temp);
    }

    /*
     * The small fields go in packed into 64-bit words, so a word costs one multiply for two or more fields. Each
     * "has" flag sits above its value: then "MED 0" and "no MED" give different words.
     *   word 1: LOCAL_PREF (bits 63-32), AS path hash (31-0)
     *   word 2: ORIGIN (63-56), has_med (55-48), has link-local (47-40), has tunnel encap (39-32), MED (31-0)
     */
    h = ribout_hash_mix(h, ((uint64_t)attrs->local_pref << 32) | aspath_hash);
    h = ribout_hash_mix(h, ((uint64_t)attrs->origin << 56) | ((uint64_t)attrs->has_med << 48) |
                           ((uint64_t)attrs->next_hop_has_link_local << 40) |
                           ((uint64_t)attrs->has_tunnel_encap << 32) | (attrs->has_med ? attrs->med : 0));
    if (attrs->has_tunnel_encap) {
        uint32_t enlp = attrs->has_enlp ? attrs->enlp : 0;
        uint32_t priority = attrs->has_priority ? attrs->priority : 0;
        uint32_t label = (attrs->binding_sid.type == SRPOLICY_BINDING_SID_MPLS) ? attrs->binding_sid.mpls_label : 0;

        /*
         * word 3: preference (63-32), has_enlp (31-24), ENLP (23-16), has_priority (15-8), priority (7-0)
         * word 4: Binding SID type (47-40), Binding SID flags (39-32), MPLS label (31-0)
         * An SRv6 Binding SID then adds its 16 octets.
         */
        h = ribout_hash_mix(h, ((uint64_t)attrs->preference << 32) | ((uint64_t)attrs->has_enlp << 24) |
                               ((uint64_t)enlp << 16) | ((uint64_t)attrs->has_priority << 8) | priority);
        h = ribout_hash_mix(h, ((uint64_t)attrs->binding_sid.type << 40) |
                               ((uint64_t)attrs->binding_sid.flags << 32) | label);
        if (attrs->binding_sid.type == SRPOLICY_BINDING_SID_SRV6) {
            h = ribout_hash_bytes(h, attrs->binding_sid.srv6_sid, sizeof(attrs->binding_sid.srv6_sid));
        }
    }
    if (attrs->ext_comm_data && attrs->ext_comm_len > 0) {
        h = ribout_hash_bytes(h, attrs->ext_comm_data, attrs->ext_comm_len);
    }
    if (attrs->ipv6_ext_comm_data && attrs->ipv6_ext_comm_len > 0) {
        h = ribout_hash_bytes(h, attrs->ipv6_ext_comm_data, attrs->ipv6_ext_comm_len);
    }
    // The lengths go in too: a set of none and an empty set are told apart from the sets around them.
    if (attrs->community_data && attrs->community_len > 0) {
        h = ribout_hash_mix(h, attrs->community_len);
        h = ribout_hash_bytes(h, attrs->community_data, attrs->community_len);
    }
    if (attrs->large_community_data && attrs->large_community_len > 0) {
        h = ribout_hash_mix(h, (uint64_t)attrs->large_community_len << 16);
        h = ribout_hash_bytes(h, attrs->large_community_data, attrs->large_community_len);
    }

    return ribout_hash_fold(h);
}

/*
 * Compute hash for a set of path attributes
 */
uint32_t bgp_ribout_map_hash_attributes(const bgp_path_attrs_t *attrs) {
    return bgp_ribout_map_hash_attributes_internal(attrs, NULL);
}

// Path Attribute Entry Functions

static int path_attr_equal(const path_attr_entry_t *entry,
                           const bgp_path_attrs_t *attrs,
                           const bgp_attr_hash_cache_t *hash_cache) {
    bgp_temp_aspath_t temp;
    const uint8_t    *aspath_data = NULL;
    uint16_t          aspath_data_len = 0;
    uint16_t          aspath_segment_count = 0;
    int               temp_built = 0;

    // Compare local_pref and origin first (quick checks)
    if (entry->local_pref != attrs->local_pref ||
        entry->origin != attrs->origin) {
        return 0;
    }
    if (entry->has_med != attrs->has_med) {
        return 0;
    }
    if (entry->has_med && entry->med != attrs->med) {
        return 0;
    }
    if (entry->has_tunnel_encap != attrs->has_tunnel_encap) {
        return 0;
    }
    if (entry->has_tunnel_encap &&
        (entry->preference != attrs->preference ||
         entry->has_enlp != attrs->has_enlp ||
         entry->enlp != attrs->enlp ||
         entry->has_priority != attrs->has_priority ||
         entry->priority != attrs->priority ||
         entry->binding_sid.type != attrs->binding_sid.type ||
         entry->binding_sid.flags != attrs->binding_sid.flags)) {
        return 0;
    }
    if (entry->has_tunnel_encap &&
        entry->binding_sid.type == SRPOLICY_BINDING_SID_MPLS &&
        entry->binding_sid.mpls_label != attrs->binding_sid.mpls_label) {
        return 0;
    }
    if (entry->has_tunnel_encap &&
        entry->binding_sid.type == SRPOLICY_BINDING_SID_SRV6 &&
        memcmp(entry->binding_sid.srv6_sid,
               attrs->binding_sid.srv6_sid,
               sizeof(entry->binding_sid.srv6_sid)) != 0) {
        return 0;
    }

    // Compare next_hop address family
    if (entry->next_hop_af != attrs->next_hop_af) {
        return 0;
    }

    // Compare binary next_hop
    size_t nh_size = (attrs->next_hop_af == AF_INET) ?
        sizeof(struct in_addr) : sizeof(struct in6_addr);
    if (memcmp(&entry->next_hop, attrs->next_hop_addr, nh_size) != 0) {
        return 0;
    }
    if (entry->next_hop_has_link_local != attrs->next_hop_has_link_local) {
        return 0;
    }
    if (entry->next_hop_has_link_local &&
        (!attrs->next_hop_link_local ||
         memcmp(&entry->next_hop_link_local,
                attrs->next_hop_link_local,
                sizeof(struct in6_addr)) != 0)) {
        return 0;
    }

    if (hash_cache && hash_cache->has_aspath) {
        aspath_data = hash_cache->aspath_data;
        aspath_data_len = hash_cache->aspath_data_len;
        aspath_segment_count = hash_cache->aspath_segment_count;
    } else if (attrs->aspath_segments && attrs->aspath_segment_count > 0) {
        bgp_ribout_temp_aspath_init(&temp);
        if (bgp_ribout_temp_aspath_build(attrs->aspath_segments,
                                         attrs->aspath_segment_count,
                                         &temp) < 0) {
            return 0;
        }
        temp_built = 1;
        if (temp.has_aspath) {
            aspath_data = temp.data;
            aspath_data_len = temp.data_len;
            aspath_segment_count = temp.segment_count;
        }
    }

    if (entry->aspath_segment_count != aspath_segment_count ||
        entry->aspath_data_len != aspath_data_len) {
        if (temp_built) {
            bgp_ribout_temp_aspath_release(&temp);
        }
        return 0;
    }
    if (entry->ext_comm_len != attrs->ext_comm_len ||
        entry->ipv6_ext_comm_len != attrs->ipv6_ext_comm_len ||
        entry->community_len != attrs->community_len ||
        entry->large_community_len != attrs->large_community_len ||
        (attrs->community_len > 0 && memcmp(entry->community_data, attrs->community_data, attrs->community_len)) ||
        (attrs->large_community_len > 0 &&
         memcmp(entry->large_community_data, attrs->large_community_data, attrs->large_community_len))) {
        if (temp_built) {
            bgp_ribout_temp_aspath_release(&temp);
        }
        return 0;
    }
    if (aspath_data_len > 0 &&
        memcmp(entry->aspath_data, aspath_data, aspath_data_len) != 0) {
        if (temp_built) {
            bgp_ribout_temp_aspath_release(&temp);
        }
        return 0;
    }
    if (attrs->ext_comm_len > 0 &&
        memcmp(entry->ext_comm_data, attrs->ext_comm_data,
               attrs->ext_comm_len) != 0) {
        if (temp_built) {
            bgp_ribout_temp_aspath_release(&temp);
        }
        return 0;
    }
    if (attrs->ipv6_ext_comm_len > 0 &&
        memcmp(entry->ipv6_ext_comm_data, attrs->ipv6_ext_comm_data,
               attrs->ipv6_ext_comm_len) != 0) {
        if (temp_built) {
            bgp_ribout_temp_aspath_release(&temp);
        }
        return 0;
    }

    if (temp_built) {
        bgp_ribout_temp_aspath_release(&temp);
    }
    return 1;
}

/*
 * Create a new path_attr_entry from an attributes tuple
 */
static path_attr_entry_t* path_attr_entry_create(bgp_ribout_map_t *map,
                                                 const bgp_path_attrs_t *attrs,
                                                 uint32_t attr_hash,
                                                 const bgp_attr_hash_cache_t *hash_cache) {
    path_attr_entry_t *entry;
    bgp_temp_aspath_t  temp;
    const uint8_t     *aspath_data = NULL;
    uint16_t           aspath_data_len = 0;
    uint16_t           aspath_segment_count = 0;
    int                temp_built = 0;

    entry = bgp_ribout_arena_alloc(map, sizeof(path_attr_entry_t), _Alignof(path_attr_entry_t));
    if (!entry) {
        return NULL;
    }
    memset(entry, 0, sizeof(*entry));

    // Copy binary next_hop
    entry->next_hop_af = attrs->next_hop_af;
    if (attrs->next_hop_af == AF_INET) {
        memcpy(&entry->next_hop.ipv4, attrs->next_hop_addr, sizeof(struct in_addr));
    } else {
        memcpy(&entry->next_hop.ipv6, attrs->next_hop_addr, sizeof(struct in6_addr));
        if (attrs->next_hop_has_link_local && attrs->next_hop_link_local) {
            entry->next_hop_has_link_local = 1;
            entry->next_hop_link_local = *attrs->next_hop_link_local;
        }
    }

    // Copy compact AS-path bytes
    if (hash_cache && hash_cache->has_aspath) {
        aspath_data = hash_cache->aspath_data;
        aspath_data_len = hash_cache->aspath_data_len;
        aspath_segment_count = hash_cache->aspath_segment_count;
    } else if (attrs->aspath_segments && attrs->aspath_segment_count > 0) {
        bgp_ribout_temp_aspath_init(&temp);
        if (bgp_ribout_temp_aspath_build(attrs->aspath_segments,
                                         attrs->aspath_segment_count,
                                         &temp) < 0) {
            return NULL;
        }
        temp_built = 1;
        if (temp.has_aspath) {
            aspath_data = temp.data;
            aspath_data_len = temp.data_len;
            aspath_segment_count = temp.segment_count;
        }
    }

    if (aspath_data_len > 0) {
        uint8_t *copy = bgp_ribout_arena_alloc(map, aspath_data_len, _Alignof(uint32_t));
        if (!copy) {
            if (temp_built) {
                bgp_ribout_temp_aspath_release(&temp);
            }
            return NULL;
        }

        memcpy(copy, aspath_data, aspath_data_len);
        entry->aspath_data = copy;
        entry->aspath_data_len = aspath_data_len;
        entry->aspath_segment_count = aspath_segment_count;
    }

    if (attrs->ext_comm_len > 0 && attrs->ext_comm_data) {
        uint8_t *copy = bgp_ribout_arena_alloc(map, attrs->ext_comm_len, _Alignof(uint32_t));
        if (!copy) {
            if (temp_built) {
                bgp_ribout_temp_aspath_release(&temp);
            }
            return NULL;
        }

        memcpy(copy, attrs->ext_comm_data, attrs->ext_comm_len);
        entry->ext_comm_data = copy;
        entry->ext_comm_len = attrs->ext_comm_len;
    }

    if (attrs->ipv6_ext_comm_len > 0 && attrs->ipv6_ext_comm_data) {
        uint8_t *copy = bgp_ribout_arena_alloc(map, attrs->ipv6_ext_comm_len, _Alignof(uint32_t));
        if (!copy) {
            if (temp_built) {
                bgp_ribout_temp_aspath_release(&temp);
            }
            return NULL;
        }

        memcpy(copy, attrs->ipv6_ext_comm_data, attrs->ipv6_ext_comm_len);
        entry->ipv6_ext_comm_data = copy;
        entry->ipv6_ext_comm_len = attrs->ipv6_ext_comm_len;
    }

    // Both community values in one arena piece.
    if (attrs->community_len + attrs->large_community_len > 0) {
        uint8_t *copy = bgp_ribout_arena_alloc(map, (size_t)attrs->community_len + attrs->large_community_len,
                                               _Alignof(uint32_t));
        if (!copy) {
            if (temp_built) {
                bgp_ribout_temp_aspath_release(&temp);
            }
            return NULL;
        }
        if (attrs->community_len > 0) {
            memcpy(copy, attrs->community_data, attrs->community_len);
            entry->community_data = copy;
            entry->community_len = attrs->community_len;
        }
        if (attrs->large_community_len > 0) {
            memcpy(copy + attrs->community_len, attrs->large_community_data, attrs->large_community_len);
            entry->large_community_data = copy + attrs->community_len;
            entry->large_community_len = attrs->large_community_len;
        }
    }
    // Set other attributes
    entry->local_pref = attrs->local_pref;
    entry->med = attrs->med;
    entry->has_med = attrs->has_med;
    entry->has_tunnel_encap = attrs->has_tunnel_encap;
    entry->preference = attrs->preference;
    entry->has_enlp = attrs->has_enlp;
    entry->enlp = attrs->enlp;
    entry->has_priority = attrs->has_priority;
    entry->priority = attrs->priority;
    entry->binding_sid = attrs->binding_sid;
    entry->origin = attrs->origin;
    entry->attr_hash = attr_hash;

    // Initialize chunked NLRI storage
    entry->nlri_type = 0;
    entry->nlri_chunks = NULL;
    entry->nlri_chunks_tail = NULL;
    entry->nlri_count = 0;
    entry->next = NULL;

    if (temp_built) {
        bgp_ribout_temp_aspath_release(&temp);
    }
    return entry;
}

/*
 * Add an NLRI to a path_attr_entry
 */
static int path_attr_entry_add_nlri(bgp_ribout_map_t *map, path_attr_entry_t *entry, const bgp_nlri_input_t *nlri_in) {
    uint8_t                  nlri_type = bgp_ribout_nlri_type(nlri_in);
    bgp_ribout_nlri_chunk_t *chunk = entry->nlri_chunks_tail;
    uint8_t                 *slot;

    if (entry->nlri_type == 0) {
        entry->nlri_type = nlri_type;
    } else if (entry->nlri_type != nlri_type) {
        return -1;
    }

    if (!chunk || chunk->count >= chunk->capacity) {
        /*
         * Sparse adversarial maps often end up with one NLRI per attribute
         * entry. Use a single-record first chunk so those entries do not each
         * pre-reserve ~1KB of storage; once an entry proves dense, overflow
         * chunks still use the larger target size for amortized efficiency.
         */
        uint16_t capacity_override = (entry->nlri_count == 0) ?
            BGP_RIBOUT_NLRI_CHUNK_FIRST_CAPACITY : 0;

        chunk = bgp_ribout_nlri_chunk_create(map, entry->nlri_type, capacity_override);
        if (!chunk) {
            return -1;
        }

        if (entry->nlri_chunks_tail) {
            entry->nlri_chunks_tail->next = chunk;
        } else {
            entry->nlri_chunks = chunk;
        }
        entry->nlri_chunks_tail = chunk;
    }

    slot = chunk->data + ((size_t)chunk->count * chunk->stride);
    switch (entry->nlri_type) {
        case BGP_RIBOUT_NLRI_TYPE_IPV4: {
            bgp_ribout_nlri_v4_t *nlri = (bgp_ribout_nlri_v4_t *)slot;

            memset(nlri, 0, sizeof(*nlri));
            nlri->prefix = ((const struct in_addr *)nlri_in->prefix_addr)->s_addr;
            nlri->path_id = nlri_in->path_id;
            nlri->prefix_len = nlri_in->prefix_len;
            break;
        }
        case BGP_RIBOUT_NLRI_TYPE_IPV6: {
            bgp_ribout_nlri_v6_t *nlri = (bgp_ribout_nlri_v6_t *)slot;

            memset(nlri, 0, sizeof(*nlri));
            memcpy(nlri->prefix, nlri_in->prefix_addr, sizeof(nlri->prefix));
            nlri->path_id = nlri_in->path_id;
            nlri->prefix_len = nlri_in->prefix_len;
            break;
        }
        case BGP_RIBOUT_NLRI_TYPE_LABELED_IPV4: {
            bgp_ribout_nlri_lu4_t *nlri = (bgp_ribout_nlri_lu4_t *)slot;

            memset(nlri, 0, sizeof(*nlri));
            nlri->prefix = ((const struct in_addr *)nlri_in->prefix_addr)->s_addr;
            nlri->label = nlri_in->label;
            nlri->path_id = nlri_in->path_id;
            nlri->prefix_len = nlri_in->prefix_len;
            break;
        }
        case BGP_RIBOUT_NLRI_TYPE_LABELED_IPV6: {
            bgp_ribout_nlri_lu6_t *nlri = (bgp_ribout_nlri_lu6_t *)slot;

            memset(nlri, 0, sizeof(*nlri));
            memcpy(nlri->prefix, nlri_in->prefix_addr, sizeof(nlri->prefix));
            nlri->label = nlri_in->label;
            nlri->path_id = nlri_in->path_id;
            nlri->prefix_len = nlri_in->prefix_len;
            break;
        }
        case BGP_RIBOUT_NLRI_TYPE_VPNV4: {
            bgp_ribout_nlri_vpnv4_t *nlri = (bgp_ribout_nlri_vpnv4_t *)slot;

            memset(nlri, 0, sizeof(*nlri));
            nlri->rd = *nlri_in->rd;
            nlri->prefix = ((const struct in_addr *)nlri_in->prefix_addr)->s_addr;
            nlri->label = nlri_in->label;
            nlri->path_id = nlri_in->path_id;
            nlri->prefix_len = nlri_in->prefix_len;
            break;
        }
        case BGP_RIBOUT_NLRI_TYPE_VPNV6: {
            bgp_ribout_nlri_vpnv6_t *nlri = (bgp_ribout_nlri_vpnv6_t *)slot;

            memset(nlri, 0, sizeof(*nlri));
            nlri->rd = *nlri_in->rd;
            memcpy(nlri->prefix, nlri_in->prefix_addr, sizeof(nlri->prefix));
            nlri->label = nlri_in->label;
            nlri->path_id = nlri_in->path_id;
            nlri->prefix_len = nlri_in->prefix_len;
            break;
        }
        case BGP_RIBOUT_NLRI_TYPE_EVPN_TYPE5_IPV4: {
            bgp_ribout_nlri_evpn4_t *nlri = (bgp_ribout_nlri_evpn4_t *)slot;

            memset(nlri, 0, sizeof(*nlri));
            nlri->rd = *nlri_in->rd;
            if (nlri_in->has_esi) {
                nlri->esi = *nlri_in->esi;
            }
            nlri->ethernet_tag_id = nlri_in->ethernet_tag_id;
            nlri->label = nlri_in->label;
            nlri->label_vni = nlri_in->label_vni;
            nlri->path_id = nlri_in->path_id;
            nlri->prefix = ((const struct in_addr *)nlri_in->prefix_addr)->s_addr;
            if (nlri_in->has_gateway_ip) {
                nlri->gateway_ip =
                    ((const struct in_addr *)nlri_in->gateway_ip_addr)->s_addr;
            }
            nlri->prefix_len = nlri_in->prefix_len;
            break;
        }
        case BGP_RIBOUT_NLRI_TYPE_EVPN_TYPE5_IPV6: {
            bgp_ribout_nlri_evpn6_t *nlri = (bgp_ribout_nlri_evpn6_t *)slot;

            memset(nlri, 0, sizeof(*nlri));
            nlri->rd = *nlri_in->rd;
            if (nlri_in->has_esi) {
                nlri->esi = *nlri_in->esi;
            }
            nlri->ethernet_tag_id = nlri_in->ethernet_tag_id;
            nlri->label = nlri_in->label;
            nlri->label_vni = nlri_in->label_vni;
            nlri->path_id = nlri_in->path_id;
            memcpy(nlri->prefix, nlri_in->prefix_addr, sizeof(nlri->prefix));
            if (nlri_in->has_gateway_ip) {
                memcpy(nlri->gateway_ip, nlri_in->gateway_ip_addr, sizeof(nlri->gateway_ip));
            }
            nlri->prefix_len = nlri_in->prefix_len;
            break;
        }
        case BGP_RIBOUT_NLRI_TYPE_SR_POLICY_IPV4: {
            bgp_ribout_nlri_sr4_t *nlri = (bgp_ribout_nlri_sr4_t *)slot;

            memset(nlri, 0, sizeof(*nlri));
            nlri->distinguisher = nlri_in->distinguisher;
            nlri->color = nlri_in->color;
            nlri->path_id = nlri_in->path_id;
            nlri->endpoint =
                ((const struct in_addr *)nlri_in->endpoint_addr)->s_addr;
            break;
        }
        case BGP_RIBOUT_NLRI_TYPE_SR_POLICY_IPV6: {
            bgp_ribout_nlri_sr6_t *nlri = (bgp_ribout_nlri_sr6_t *)slot;

            memset(nlri, 0, sizeof(*nlri));
            nlri->distinguisher = nlri_in->distinguisher;
            nlri->color = nlri_in->color;
            nlri->path_id = nlri_in->path_id;
            memcpy(nlri->endpoint, nlri_in->endpoint_addr, sizeof(nlri->endpoint));
            break;
        }
        case BGP_RIBOUT_NLRI_TYPE_EVPN_TYPE2: {
            bgp_ribout_nlri_evpn2_t *nlri = (bgp_ribout_nlri_evpn2_t *)slot;

            memset(nlri, 0, sizeof(*nlri));
            nlri->rd = *nlri_in->rd;
            if (nlri_in->has_esi) {
                nlri->esi = *nlri_in->esi;
            }
            nlri->ethernet_tag_id = nlri_in->ethernet_tag_id;
            nlri->label1 = nlri_in->label;
            nlri->label2 = nlri_in->label2;
            nlri->path_id = nlri_in->path_id;
            nlri->has_label2 = nlri_in->has_label2;
            nlri->label_vni = nlri_in->label_vni;
            memcpy(nlri->mac, nlri_in->mac_addr, sizeof(nlri->mac));
            if (nlri_in->has_ip) {
                nlri->ip_addr_len = (nlri_in->ip_af == AF_INET6) ? 128 : 32;
                if (nlri_in->ip_af == AF_INET) {
                    memcpy(nlri->ip_addr, nlri_in->ip_addr, sizeof(struct in_addr));
                } else {
                    memcpy(nlri->ip_addr, nlri_in->ip_addr, sizeof(struct in6_addr));
                }
            }
            break;
        }
        case BGP_RIBOUT_NLRI_TYPE_FLOWSPEC_IPV4:
        case BGP_RIBOUT_NLRI_TYPE_FLOWSPEC_IPV6:
        case BGP_RIBOUT_NLRI_TYPE_FLOWSPEC_VPN_IPV4:
        case BGP_RIBOUT_NLRI_TYPE_FLOWSPEC_VPN_IPV6: {
            bgp_ribout_nlri_flowspec_t *nlri = (bgp_ribout_nlri_flowspec_t *)slot;

            memset(nlri, 0, sizeof(*nlri));
            if (nlri_in->has_rd) {
                nlri->rd = *nlri_in->rd;
            }
            nlri->path_id = nlri_in->path_id;
            nlri->instance = nlri_in->flowspec_instance;
            break;
        }
        default: {
            if (bgp_ribout_nlri_info(nlri_type)->kind != BGP_RIBOUT_KIND_TEMPLATE) return -1;
            bgp_ribout_nlri_template_t *nlri = (bgp_ribout_nlri_template_t *)slot;
            *nlri = (bgp_ribout_nlri_template_t){.instance = nlri_in->template_instance, .path_id = nlri_in->path_id};
            break;
        }
    }

    chunk->count++;
    entry->nlri_count++;

    return 0;
}

// RibOut Map Functions

/*
 * Create a new ribout
 */
bgp_ribout_map_t* bgp_ribout_map_create(size_t bucket_count) {
    if (bucket_count == 0) {
        bucket_count = RIBOUT_HASHMAP_DEFAULT_SIZE;
    }
    bucket_count = round_up_power_of_two(bucket_count);
    if (bucket_count == 0) {
        return NULL;
    }

    bgp_ribout_map_t *map = calloc(1, sizeof(bgp_ribout_map_t));
    if (!map) {
        return NULL;
    }

    map->buckets = calloc(bucket_count, sizeof(path_attr_entry_t *));
    if (!map->buckets) {
        free(map);
        return NULL;
    }

    map->bucket_count = bucket_count;
    map->bucket_mask = bucket_count - 1;
    map->entry_count = 0;
    map->total_nlri_count = 0;
    map->arena_chunks = NULL;
    map->arena_chunk_size = BGP_RIBOUT_ARENA_CHUNK_SIZE;

    // Initialize memory usage: map structure + buckets array
    map->memory_usage = sizeof(bgp_ribout_map_t) +
                        (bucket_count * sizeof(path_attr_entry_t *));

    return map;
}

/*
 * Destroy a ribout
 */
void bgp_ribout_map_destroy(bgp_ribout_map_t *map) {
    if (!map) {
        return;
    }

    bgp_ribout_arena_release(map);
    free(map->buckets);
    free(map);
}

/*
 * Clear all entries from the map
 */
void bgp_ribout_map_clear(bgp_ribout_map_t *map) {
    if (!map) {
        return;
    }

    bgp_ribout_arena_release(map);
    memset(map->buckets, 0, map->bucket_count * sizeof(path_attr_entry_t *));
    map->order_head = NULL;
    map->order_tail = NULL;
    map->entry_count = 0;
    map->total_nlri_count = 0;

    // Reset memory usage to base (structure + buckets array)
    map->memory_usage = sizeof(bgp_ribout_map_t) +
                        (map->bucket_count * sizeof(path_attr_entry_t *));
}

/*
 * Find a path_attr_entry matching the given attributes
 */
path_attr_entry_t* bgp_ribout_map_find(bgp_ribout_map_t *map, const bgp_path_attrs_t *attrs) {
    bgp_temp_aspath_t     temp;
    bgp_attr_hash_cache_t lookup = {0};
    uint32_t              hash;
    size_t                bucket_idx;
    path_attr_entry_t    *entry;
    int                   temp_built = 0;

    if (!map) {
        return NULL;
    }

    if (attrs->aspath_segments && attrs->aspath_segment_count > 0) {
        if (bgp_ribout_temp_aspath_build(attrs->aspath_segments,
                                         attrs->aspath_segment_count,
                                         &temp) < 0) {
            return NULL;
        }
        temp_built = 1;

        if (temp.has_aspath) {
            lookup.aspath_data = temp.data;
            lookup.aspath_data_len = temp.data_len;
            lookup.aspath_segment_count = temp.segment_count;
            lookup.aspath_hash = temp.hash;
            lookup.has_aspath = 1;
        }
    }

    // Compute hash and find bucket
    hash = bgp_ribout_map_hash_attributes_internal(attrs, lookup.has_aspath ? &lookup : NULL);
    bucket_idx = bgp_ribout_bucket_index(map, hash);

    // Search chain in bucket
    entry = map->buckets[bucket_idx];
    while (entry) {
        if (entry->attr_hash == hash && path_attr_equal(entry, attrs, &lookup)) {
            if (temp_built) {
                bgp_ribout_temp_aspath_release(&temp);
            }
            return entry;
        }
        entry = entry->next;
    }

    if (temp_built) {
        bgp_ribout_temp_aspath_release(&temp);
    }
    return NULL;
}

static int bgp_ribout_map_insert_internal(
    bgp_ribout_map_t *map,
    const bgp_nlri_input_t *nlri_in,
    const bgp_path_attrs_t *attrs,
    const bgp_attr_hash_cache_t *hash_cache) {
    uint32_t              hash;
    uint8_t               nlri_type;
    bgp_temp_aspath_t     temp;
    bgp_attr_hash_cache_t lookup = {0};
    path_attr_entry_t    *entry;
    size_t                bucket_idx;
    int                   temp_built = 0;

    if (!map || !nlri_in || !attrs->next_hop_addr) {
        return -1;
    }

    nlri_type = bgp_ribout_nlri_type(nlri_in);
    if (bgp_ribout_nlri_input_validate(nlri_type, nlri_in) < 0) {
        return -1;
    }

    if (hash_cache && hash_cache->has_aspath) {
        lookup = *hash_cache;
    } else if (attrs->aspath_segments && attrs->aspath_segment_count > 0) {
        bgp_ribout_temp_aspath_init(&temp);
        if (bgp_ribout_temp_aspath_build(attrs->aspath_segments,
                                         attrs->aspath_segment_count,
                                         &temp) < 0) {
            return -1;
        }
        temp_built = 1;
        if (temp.has_aspath) {
            lookup.aspath_data = temp.data;
            lookup.aspath_data_len = temp.data_len;
            lookup.aspath_segment_count = temp.segment_count;
            lookup.aspath_hash = temp.hash;
            lookup.has_aspath = 1;
        }
    }

    hash = bgp_ribout_map_hash_attributes_internal(attrs, lookup.has_aspath ? &lookup : NULL);
    bucket_idx = bgp_ribout_bucket_index(map, hash);

    // Search for existing entry with same attributes
    entry = map->buckets[bucket_idx];

    while (entry) {
        if (entry->attr_hash == hash &&
            path_attr_equal(entry, attrs,
                            lookup.has_aspath ? &lookup : NULL)) {
            // Found existing entry - add NLRI to it
            if (path_attr_entry_add_nlri(map, entry, nlri_in) < 0) {
                if (temp_built) {
                    bgp_ribout_temp_aspath_release(&temp);
                }
                return -1;
            }
            map->total_nlri_count++;
            if (temp_built) {
                bgp_ribout_temp_aspath_release(&temp);
            }
            return 0;
        }
        entry = entry->next;
    }

    // No existing entry found - create new one
    entry = path_attr_entry_create(map, attrs, hash, lookup.has_aspath ? &lookup : NULL);
    if (!entry) {
        if (temp_built) {
            bgp_ribout_temp_aspath_release(&temp);
        }
        return -1;
    }

    // Add NLRI to new entry
    if (path_attr_entry_add_nlri(map, entry, nlri_in) < 0) {
        if (temp_built) {
            bgp_ribout_temp_aspath_release(&temp);
        }
        return -1;
    }

    /*
     * Insert at the head of the bucket chain, for lookups, and at the end of the insertion order, for the walks in
     * bgp_ribout_map_compact_buckets() and bgp_ribout_generate_messages()
     */
    entry->next = map->buckets[bucket_idx];
    map->buckets[bucket_idx] = entry;
    if (map->order_tail) {
        map->order_tail->order_next = entry;
    } else {
        map->order_head = entry;
    }
    map->order_tail = entry;

    map->entry_count++;
    map->total_nlri_count++;
    if (temp_built) {
        bgp_ribout_temp_aspath_release(&temp);
    }

    return 0;
}

/*
 * Insert or update an NLRI with given path attributes
 */
int bgp_ribout_map_insert(bgp_ribout_map_t *map,
                          const void *prefix_addr,
                          uint8_t prefix_len,
                          uint8_t prefix_af,
                          uint32_t path_id,
                          const bgp_path_attrs_t *attrs) {
    bgp_nlri_input_t nlri_in;

    memset(&nlri_in, 0, sizeof(nlri_in));
    nlri_in.prefix_addr = prefix_addr;
    nlri_in.prefix_len = prefix_len;
    nlri_in.prefix_af = prefix_af;
    nlri_in.path_id = path_id;

    return bgp_ribout_map_insert_internal(map, &nlri_in, attrs, NULL);
}

static int bgp_ribout_map_compact_buckets(bgp_ribout_map_t *map) {
    path_attr_entry_t **new_buckets;
    size_t              new_bucket_count;
    size_t              old_bucket_bytes;
    size_t              new_bucket_bytes;

    if (!map || !map->buckets) {
        return -1;
    }

    new_bucket_count = bgp_ribout_map_bucket_compact_target(map->entry_count);
    if (new_bucket_count == 0 || new_bucket_count >= map->bucket_count) {
        return 0;
    }

    new_buckets = calloc(new_bucket_count, sizeof(*new_buckets));
    if (!new_buckets) {
        return -1;
    }

    /*
     * Map construction intentionally over-allocates buckets from the emitted
     * path upper bound so insertion stays close to O(1) even in worst-case
     * one-path-per-group workloads. Once generation finishes we know the real
     * attribute-group cardinality, so rehash into a tighter table before the
     * map is retained for verification/serialization. The walk is in
     * insertion order, so it reads the arena forward.
     */
    for (path_attr_entry_t *entry = map->order_head; entry; entry = entry->order_next) {
        size_t bucket_idx = ((size_t)entry->attr_hash) & (new_bucket_count - 1);

        entry->next = new_buckets[bucket_idx];
        new_buckets[bucket_idx] = entry;
    }

    old_bucket_bytes = map->bucket_count * sizeof(*map->buckets);
    new_bucket_bytes = new_bucket_count * sizeof(*map->buckets);

    free(map->buckets);
    map->buckets = new_buckets;
    map->bucket_count = new_bucket_count;
    map->bucket_mask = new_bucket_count - 1;
    map->memory_usage -= old_bucket_bytes;
    map->memory_usage += new_bucket_bytes;

    return 0;
}

/*
 * Get statistics about the map
 */
void bgp_ribout_map_get_stats(bgp_ribout_map_t *map,
                              size_t *out_entries,
                              size_t *out_total_nlris,
                              size_t *out_bucket_count) {
    if (!map) {
        return;
    }

    if (out_entries) {
        *out_entries = map->entry_count;
    }
    if (out_total_nlris) {
        *out_total_nlris = map->total_nlri_count;
    }
    if (out_bucket_count) {
        *out_bucket_count = map->bucket_count;
    }
}

/*
 * Get memory usage of the map in bytes (O(1) - tracked during insert/clear)
 */
size_t bgp_ribout_map_get_memory_usage(bgp_ribout_map_t *map) {
    if (!map) {
        return 0;
    }

    return map->memory_usage;
}

/*
 * Print the ribout
 */
void bgp_ribout_map_print(bgp_ribout_map_t *map) {
    if (!map) {
        printf("ribout map: (null)\n");
        return;
    }

    printf("ribout map statistics:\n");
    printf("  Buckets: %zu\n", map->bucket_count);
    printf("  Path Attribute Entries: %zu\n", map->entry_count);
    printf("  Total NLRIs: %zu\n", map->total_nlri_count);
    printf("\n");

    // Print each non-empty bucket
    for (size_t i = 0; i < map->bucket_count; i++) {
        path_attr_entry_t *entry = map->buckets[i];
        if (!entry) {
            continue;
        }

        while (entry) {
            const uint8_t *aspath_cursor = entry->aspath_data;

            printf("Path Attributes:\n");

            // Convert binary next_hop to string
            char next_hop_str[INET6_ADDRSTRLEN];
            if (entry->next_hop_af == AF_INET) {
                inet_ntop(AF_INET, &entry->next_hop.ipv4, next_hop_str, sizeof(next_hop_str));
            } else {
                inet_ntop(AF_INET6, &entry->next_hop.ipv6, next_hop_str, sizeof(next_hop_str));
            }
            printf("  Next-hop: %s\n", next_hop_str);

            printf("  AS-Path: ");
            if (entry->aspath_segment_count > 0 && entry->aspath_data) {
                for (uint32_t j = 0; j < entry->aspath_segment_count; j++) {
                    const bgp_aspath_seg_hdr_t *hdr =
                        (const bgp_aspath_seg_hdr_t *)aspath_cursor;
                    const uint32_t *values =
                        (const uint32_t *)(aspath_cursor + sizeof(*hdr));

                    if (hdr->type == ASPATH_SET) {
                        printf("{ ");
                    }
                    for (uint32_t k = 0; k < hdr->length; k++) {
                        printf("%u ", values[k]);
                    }
                    if (hdr->type == ASPATH_SET) {
                        printf("} ");
                    }

                    aspath_cursor += sizeof(*hdr) +
                                     ((size_t)hdr->length * sizeof(uint32_t));
                }
            } else {
                printf("(empty)");
            }
            printf("\n");
            printf("  Local Preference: %u\n", entry->local_pref);
            if (entry->has_med) {
                printf("  MED: %u\n", entry->med);
            }
            if (entry->has_tunnel_encap) {
                printf("  Preference: %u\n", entry->preference);
                if (entry->has_enlp) {
                    printf("  ENLP: %u\n", entry->enlp);
                }
                if (entry->has_priority) {
                    printf("  Priority: %u\n", entry->priority);
                }
                if (entry->binding_sid.type == SRPOLICY_BINDING_SID_MPLS) {
                    printf("  Binding SID: mpls %u\n", entry->binding_sid.mpls_label);
                } else if (entry->binding_sid.type == SRPOLICY_BINDING_SID_SRV6) {
                    char sid_str[INET6_ADDRSTRLEN];

                    inet_ntop(AF_INET6, entry->binding_sid.srv6_sid, sid_str, sizeof(sid_str));
                    printf("  Binding SID: srv6 %s\n", sid_str);
                } else {
                    printf("  Binding SID: none\n");
                }
            }
            printf("  Origin: %u\n", entry->origin);
            printf("  NLRI Count: %zu\n", entry->nlri_count);

            // Print NLRIs
            printf("  NLRIs:\n");
            for (bgp_ribout_nlri_chunk_t *chunk = entry->nlri_chunks;
                 chunk;
                 chunk = chunk->next) {
                for (uint16_t idx = 0; idx < chunk->count; idx++) {
                    const uint8_t *slot = chunk->data +
                        ((size_t)idx * chunk->stride);
                    char     prefix_str[INET6_ADDRSTRLEN];
                    char     extra_str[128];
                    uint8_t  prefix_len = 0;
                    uint32_t label = 0;
                    uint32_t path_id = 0;
                    uint32_t dist = 0;
                    uint32_t color = 0;

                    extra_str[0] = '\0';

                    switch (entry->nlri_type) {
                        case BGP_RIBOUT_NLRI_TYPE_IPV4: {
                            const bgp_ribout_nlri_v4_t *nlri =
                                (const bgp_ribout_nlri_v4_t *)slot;
                            struct in_addr prefix = {.s_addr = nlri->prefix};

                            inet_ntop(AF_INET, &prefix, prefix_str, sizeof(prefix_str));
                            prefix_len = nlri->prefix_len;
                            path_id = nlri->path_id;
                            break;
                        }
                        case BGP_RIBOUT_NLRI_TYPE_IPV6: {
                            const bgp_ribout_nlri_v6_t *nlri =
                                (const bgp_ribout_nlri_v6_t *)slot;
                            struct in6_addr prefix;

                            memcpy(&prefix, nlri->prefix, sizeof(prefix));
                            inet_ntop(AF_INET6, &prefix, prefix_str, sizeof(prefix_str));
                            prefix_len = nlri->prefix_len;
                            path_id = nlri->path_id;
                            break;
                        }
                        case BGP_RIBOUT_NLRI_TYPE_LABELED_IPV4: {
                            const bgp_ribout_nlri_lu4_t *nlri =
                                (const bgp_ribout_nlri_lu4_t *)slot;
                            struct in_addr prefix = {.s_addr = nlri->prefix};

                            inet_ntop(AF_INET, &prefix, prefix_str, sizeof(prefix_str));
                            prefix_len = nlri->prefix_len;
                            label = nlri->label;
                            path_id = nlri->path_id;
                            break;
                        }
                        case BGP_RIBOUT_NLRI_TYPE_LABELED_IPV6: {
                            const bgp_ribout_nlri_lu6_t *nlri =
                                (const bgp_ribout_nlri_lu6_t *)slot;
                            struct in6_addr prefix;

                            memcpy(&prefix, nlri->prefix, sizeof(prefix));
                            inet_ntop(AF_INET6, &prefix, prefix_str, sizeof(prefix_str));
                            prefix_len = nlri->prefix_len;
                            label = nlri->label;
                            path_id = nlri->path_id;
                            break;
                        }
                        case BGP_RIBOUT_NLRI_TYPE_SR_POLICY_IPV4: {
                            const bgp_ribout_nlri_sr4_t *nlri =
                                (const bgp_ribout_nlri_sr4_t *)slot;
                            struct in_addr endpoint = {.s_addr = nlri->endpoint};

                            inet_ntop(AF_INET, &endpoint, prefix_str, sizeof(prefix_str));
                            dist = nlri->distinguisher;
                            color = nlri->color;
                            path_id = nlri->path_id;
                            snprintf(extra_str, sizeof(extra_str),
                                     "dist=%u color=%u endpoint=%s",
                                     dist, color, prefix_str);
                            break;
                        }
                        case BGP_RIBOUT_NLRI_TYPE_SR_POLICY_IPV6: {
                            const bgp_ribout_nlri_sr6_t *nlri =
                                (const bgp_ribout_nlri_sr6_t *)slot;
                            struct in6_addr endpoint;

                            memcpy(&endpoint, nlri->endpoint, sizeof(endpoint));
                            inet_ntop(AF_INET6, &endpoint, prefix_str, sizeof(prefix_str));
                            dist = nlri->distinguisher;
                            color = nlri->color;
                            path_id = nlri->path_id;
                            snprintf(extra_str, sizeof(extra_str),
                                     "dist=%u color=%u endpoint=%s",
                                     dist, color, prefix_str);
                            break;
                        }
                        case BGP_RIBOUT_NLRI_TYPE_EVPN_TYPE2: {
                            const bgp_ribout_nlri_evpn2_t *nlri =
                                (const bgp_ribout_nlri_evpn2_t *)slot;
                            char mac_str[32];
                            char ip_str[INET6_ADDRSTRLEN];

                            snprintf(mac_str, sizeof(mac_str),
                                     "%02x:%02x:%02x:%02x:%02x:%02x",
                                     nlri->mac[0], nlri->mac[1], nlri->mac[2],
                                     nlri->mac[3], nlri->mac[4], nlri->mac[5]);

                            if (nlri->ip_addr_len == 32) {
                                struct in_addr ip;

                                memcpy(&ip, nlri->ip_addr, sizeof(ip));
                                inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));
                                snprintf(extra_str, sizeof(extra_str),
                                         "etag=%u mac=%s ip=%s label=%u",
                                         nlri->ethernet_tag_id, mac_str,
                                         ip_str, nlri->label1);
                            } else if (nlri->ip_addr_len == 128) {
                                struct in6_addr ip6;

                                memcpy(&ip6, nlri->ip_addr, sizeof(ip6));
                                inet_ntop(AF_INET6, &ip6, ip_str, sizeof(ip_str));
                                snprintf(extra_str, sizeof(extra_str),
                                         "etag=%u mac=%s ip=%s label=%u",
                                         nlri->ethernet_tag_id, mac_str,
                                         ip_str, nlri->label1);
                            } else {
                                snprintf(extra_str, sizeof(extra_str),
                                         "etag=%u mac=%s label=%u",
                                         nlri->ethernet_tag_id, mac_str,
                                         nlri->label1);
                            }
                            if (nlri->has_label2) {
                                size_t used = strlen(extra_str);

                                snprintf(extra_str + used, sizeof(extra_str) - used, " label2=%u", nlri->label2);
                            }
                            path_id = nlri->path_id;
                            break;
                        }
                        default:
                            prefix_str[0] = '\0';
                            break;
                    }

                    if (bgp_ribout_nlri_is_srpolicy(entry->nlri_type) ||
                        bgp_ribout_nlri_is_evpn_type2(entry->nlri_type)) {
                        printf("    <%s>", extra_str);
                    } else {
                        printf("    %s/%u", prefix_str, prefix_len);
                    }
                    if (bgp_ribout_nlri_is_labeled(entry->nlri_type)) {
                        printf(" (label: %u)", label);
                    }
                    if (path_id > 0) {
                        printf(" (path-id: %u)", path_id);
                    }
                    printf("\n");
                }
            }
            printf("\n");

            entry = entry->next;
        }
    }
}

// Generation Helper Functions

int bgp_ribout_generate_map(bgp_ribout_config_t *block) {
    struct timespec start_time, end_time;
    bgp_ribout_gen_t gen;
    size_t           bucket_hint;
    int              failed = 0;

    if (!block) {
        return -1;
    }

    clock_gettime(CLOCK_MONOTONIC, &start_time);

    // Clear existing ribout if present
    bgp_ribout_clear_map(block);

    // Initialize generator
    if (bgp_ribout_generator_init(&gen, block) < 0) {
        block->map_time_ms = 0.0;
        return -1;
    }

    /*
     * Create a map sized for the generator's upper-bound path count. This
     * keeps attribute-heavy stress cases near O(1) insertion instead of
     * degenerating into long per-bucket linked-list walks.
     */
    bucket_hint = bgp_ribout_map_bucket_hint(gen.total_paths);
    block->ribout = bgp_ribout_map_create(bucket_hint);
    if (!block->ribout) {
        block->map_time_ms = 0.0;
        return -1;
    }

    // Walk all paths and insert into ribout
    bgp_gen_path_t        path;
    bgp_attr_hash_cache_t hash_cache = {0};
    bgp_temp_aspath_t     cached_aspath;

    memset(&cached_aspath, 0, sizeof(cached_aspath));
    if (block->aspath_segment_count > 0 &&
        !bgp_ribout_aspath_has_random(block->aspath_segments,
                                      block->aspath_segment_count)) {
        if (bgp_ribout_temp_aspath_build(block->aspath_segments,
                                         block->aspath_segment_count,
                                         &cached_aspath) < 0) {
            bgp_ribout_map_destroy(block->ribout);
            block->ribout = NULL;
            block->map_time_ms = 0.0;
            return -1;
        }
        if (cached_aspath.has_aspath) {
            hash_cache.aspath_data = cached_aspath.data;
            hash_cache.aspath_data_len = cached_aspath.data_len;
            hash_cache.aspath_segment_count = cached_aspath.segment_count;
            hash_cache.aspath_hash = cached_aspath.hash;
            hash_cache.has_aspath = 1;
        }
    }

    while (bgp_ribout_generator_has_next(&gen)) {
        uint8_t          nlri_type;
        bgp_nlri_input_t nlri_in;

        if (bgp_ribout_generator_next(&gen, &path) < 0) {
            fprintf(stderr, "Error: ribout '%s': path generation failed\n", block->name);
            failed = 1;
            break;
        }

        nlri_type = bgp_ribout_family_nlri_type(path.family);

        // Build path attributes tuple from generated path
        const void *next_hop_addr = (path.next_hop_af == AF_INET) ?
            (const void *)&path.next_hop_addr.ipv4 :
            (const void *)&path.next_hop_addr.ipv6;
        bgp_path_attrs_t attrs = {
            .next_hop_addr          = next_hop_addr,
            .next_hop_af            = path.next_hop_af,
            .next_hop_link_local    = path.next_hop_has_link_local ?
                                          &path.next_hop_link_local : NULL,
            .next_hop_has_link_local = path.next_hop_has_link_local,
            .aspath_segments        = path.aspath_segments,
            .aspath_segment_count   = path.aspath_segment_count,
            .ext_comm_data          = path.ext_comm_len > 0 ? path.ext_comm_data : NULL,
            .ext_comm_len           = path.ext_comm_len,
            .ipv6_ext_comm_data     = path.ipv6_ext_comm_len > 0 ? path.ipv6_ext_comm_data : NULL,
            .ipv6_ext_comm_len      = path.ipv6_ext_comm_len,
            .community_data         = path.community_len > 0 ? path.community_data : NULL,
            .community_len          = path.community_len,
            .large_community_data   = path.large_community_len > 0 ? path.large_community_data : NULL,
            .large_community_len    = path.large_community_len,
            .local_pref             = path.local_pref,
            .med                    = path.med,
            .has_enlp              = path.has_enlp,
            .enlp                  = path.enlp,
            .has_priority          = path.has_priority,
            .priority              = path.priority,
            .preference             = path.preference,
            .binding_sid            = path.binding_sid,
            .origin                 = (uint8_t)path.origin,
            .has_med                = path.has_med,
            .has_tunnel_encap       = bgp_ribout_nlri_is_srpolicy(nlri_type),
        };
        bgp_ribout_build_nlri_input(&path, nlri_type, &nlri_in);

        /*
         * The current ribout stream reuses one configured AS-path template for
         * every emitted path, so the expensive AS-path hash is computed once
         * per generation and reused internally during map insertion.
         */
        int ret = bgp_ribout_map_insert_internal(
            block->ribout, &nlri_in, &attrs,
            hash_cache.has_aspath ? &hash_cache : NULL);

        if (ret < 0) {
            fprintf(stderr, "Error: ribout '%s': could not add a generated path to the map\n", block->name);
            failed = 1;
            break;
        }
    }

    bgp_ribout_temp_aspath_release(&cached_aspath);
    if (failed || gen.paths_generated != gen.total_paths) {
        bgp_ribout_map_destroy(block->ribout);
        block->ribout = NULL;
        block->map_time_ms = 0.0;
        return -1;
    }
    /*
     * Build with an insertion-friendly bucket table, then shrink it to the
     * final attribute-group cardinality so grouped workloads do not retain a
     * large mostly-empty bucket array after generation completes.
     */
    (void)bgp_ribout_map_compact_buckets(block->ribout);
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    block->map_time_ms = (double)(end_time.tv_sec - start_time.tv_sec) * 1000.0 +
                         (double)(end_time.tv_nsec - start_time.tv_nsec) / 1000000.0;
    return 0;
}

/*
 * Clear ribout from a ribout block
 */
void bgp_ribout_clear_map(bgp_ribout_config_t *block) {
    if (block && block->ribout) {
        bgp_ribout_map_destroy(block->ribout);
        block->ribout = NULL;
    }
}

static int bgp_ribout_ext_comm_is_ipv4_rt(const bgp_ext_comm_t *ext_comm) {
    return ext_comm != NULL &&
           ext_comm->bytes[0] == 0x01 &&
           ext_comm->bytes[1] == 0x02;
}

/*
 * SR Policy is the first ribout family where the existing generic RT surface
 * needs family-specific validation. RFC 9830 requires either NO_ADVERTISE or
 * at least one IPv4-address-specific Route Target extended community.
 *
 * The first ribout pass only models the Route Target path, not the future
 * NO_ADVERTISE-only path, so this helper makes that intent explicit by
 * validating the full configured RT surface:
 *   - direct `rt` entries
 *   - every member of every `rt-set`
 *
 * Keep this check close to generator validation rather than hiding it inside
 * the low-level SR Policy encoder. That way the ribout config gets a clear
 * error before generation starts, and later work can widen the policy here if
 * ribout grows NO_ADVERTISE support or fuzz/relaxed encode modes.
 */
static int bgp_ribout_rt_surface_is_ipv4_only(const bgp_ribout_config_t *block) {
    if (!block) {
        return 0;
    }

    for (uint32_t i = 0; i < block->rt_count; i++) {
        if (!bgp_ribout_ext_comm_is_ipv4_rt(&block->rt_values[i])) {
            return 0;
        }
    }

    for (uint32_t i = 0; i < block->rt_set_group_count; i++) {
        const bgp_rt_set_spec_t *set = &block->rt_sets[i];

        if (set->count == 0) {
            return 0;
        }
        for (uint32_t j = 0; j < set->count; j++) {
            if (!bgp_ribout_ext_comm_is_ipv4_rt(&set->values[j])) {
                return 0;
            }
        }
    }

    return 1;
}

// BGP UPDATE Message Generation

/*
 * Free BGP message list
 */
void bgp_msg_list_free(bgp_msg_t *list) {
    while (list) {
        bgp_msg_t *next = list->next;
        if (list->data) {
            free(list->data);
        }
        free(list);
        list = next;
    }
}

static int build_as_path_segments(const path_attr_entry_t *entry,
                                  as_path_segment_t *segments_stack,
                                  as_path_segment_t **segments_out,
                                  as_path_segment_t **segments_heap_out) {
    as_path_segment_t *segments;
    const uint8_t     *cursor;
    uint32_t           i;

    *segments_out = NULL;
    *segments_heap_out = NULL;

    if (entry->aspath_segment_count == 0 || !entry->aspath_data) {
        return 0;
    }

    if (entry->aspath_segment_count <= MAX_ASPATH_SEGMENTS_STACK) {
        segments = segments_stack;
    } else {
        *segments_heap_out = malloc(entry->aspath_segment_count * sizeof(as_path_segment_t));
        if (!*segments_heap_out) {
            return -1;
        }
        segments = *segments_heap_out;
    }

    cursor = entry->aspath_data;
    for (i = 0; i < entry->aspath_segment_count; i++) {
        const bgp_aspath_seg_hdr_t *hdr =
            (const bgp_aspath_seg_hdr_t *)cursor;
        as_path_segment_t *dst = &segments[i];

        dst->type = (hdr->type == ASPATH_SET) ? BGP_AS_SET :
                                                BGP_AS_SEQUENCE;
        dst->length = hdr->length;
        dst->as_numbers =
            (uint32_t *)(cursor + sizeof(*hdr));
        cursor += sizeof(*hdr) + ((size_t)hdr->length * sizeof(uint32_t));
    }

    *segments_out = segments;
    return 0;
}

/*
 * Append one attribute (header and value) at *offset in buf. Returns -1 when it is longer than the space left in cap.
 * *offset is never more than cap, so cap - *offset does not wrap.
 */
static int bgp_ribout_put_attr(uint8_t *buf, size_t cap, size_t *offset,
                               uint8_t flags, uint8_t type_code, uint16_t value_len, const void *value) {
    size_t attr_len = (size_t)bgp_marshaled_attr_size(flags, value_len);

    if (attr_len > cap - *offset) {
        return -1;
    }
    bgp_serialize_raw_path_attr(buf + *offset, flags, type_code, value_len, value);
    *offset += attr_len;
    return 0;
}

/*
 * Append the AS_PATH attribute of entry (empty when it has no segments). build_as_path_segments() makes segment views
 * that point into the compact entry bytes, so no ASN is copied; it uses the heap only for more than
 * MAX_ASPATH_SEGMENTS_STACK segments.
 */
static int bgp_ribout_put_as_path(const path_attr_entry_t *entry, uint8_t *buf, size_t cap, size_t *offset) {
    as_path_segment_t  segments_stack[MAX_ASPATH_SEGMENTS_STACK];
    as_path_segment_t *segments;
    as_path_segment_t *segments_heap;
    int                len;

    // Segments with no bytes is a broken entry. AS_PATH is mandatory (RFC 4271 section 5): do not send it empty.
    if (entry->aspath_segment_count > 0 && !entry->aspath_data) {
        return -1;
    }
    if (build_as_path_segments(entry, segments_stack, &segments, &segments_heap) < 0) {
        return -1;
    }

    len = bgp_serialize_as_path_attr(buf + *offset, cap - *offset, segments, (int)entry->aspath_segment_count);
    free(segments_heap);
    if (len < 0) {
        return -1;
    }
    *offset += (size_t)len;
    return 0;
}

/*
 * Append the SR Policy Tunnel Encapsulation attribute of entry, with the segment lists of block. Ribout always sends
 * the Preference and Binding SID sub-TLVs (the SR Policy compatibility behavior); with no binding-sid configured, the
 * Binding SID has the RFC "none" form.
 */
static int bgp_ribout_put_tunnel_encap(const bgp_ribout_config_t *block, const path_attr_entry_t *entry,
                                       uint8_t *buf, size_t cap, size_t *offset) {
    srpolicy_segment_list_t  stack_lists[8];
    srpolicy_segment_list_t *segment_lists = stack_lists;
    srpolicy_tunnel_encap_t  spec;
    int                      len;

    if (block->segment_list_count > sizeof(stack_lists) / sizeof(*stack_lists)) {
        segment_lists = calloc(block->segment_list_count, sizeof(*segment_lists));
        if (!segment_lists) return -1;
    }

    // The wrappers point at the segments in block. The encoder only reads them, so there is no copy.
    for (uint32_t i = 0; i < block->segment_list_count; i++) {
        segment_lists[i].weight = block->segment_lists[i].weight;
        segment_lists[i].num_segments = (int)block->segment_lists[i].segment_count;
        segment_lists[i].segments = block->segment_lists[i].segment_count > 0 ? block->segment_lists[i].segments : NULL;
    }

    memset(&spec, 0, sizeof(spec));
    spec.has_preference = 1;
    spec.preference = entry->preference;
    spec.has_binding_sid = 1;
    spec.binding_sid = entry->binding_sid;
    spec.has_enlp = entry->has_enlp;
    spec.enlp = entry->enlp;
    spec.has_priority = entry->has_priority;
    spec.priority = entry->priority;
    spec.segment_lists = segment_lists;
    spec.num_segment_lists = (int)block->segment_list_count;

    len = bgp_serialize_tunnel_encap_srpolicy_attr(buf + *offset, cap - *offset, &spec);
    if (segment_lists != stack_lists) free(segment_lists);
    if (len < 0) {
        return -1;
    }
    *offset += (size_t)len;
    return 0;
}

/*
 * Write the attributes of one grouped-map entry at buf. Every UPDATE of the entry copies these bytes. Returns their
 * length, or -1 when the entry has no usable AS path or IPv4 next hop, or the attributes are longer than cap.
 *
 * The order is ascending type code (1, 2, 3, 4, 5, 16, 23, 25), as RFC 4271 section 5 recommends. ORIGIN and AS_PATH
 * are always written and no type is written twice, so the checks of the library attribute-list path (mandatory
 * attributes, no duplicate type) are true by construction. The caller gives a stack buffer: the attributes of a group
 * cost no heap allocation.
 */
static int bgp_ribout_write_entry_attrs(const bgp_ribout_config_t *block, const path_attr_entry_t *entry,
                                        int include_ipv4_next_hop, uint8_t *buf, size_t cap) {
    const uint8_t optional_transitive = BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE;
    size_t        offset = 0;
    uint32_t      value_net;

    // ORIGIN (1) and AS_PATH (2): mandatory in every UPDATE that has NLRI.
    if (bgp_ribout_put_attr(buf, cap, &offset, BGP_ATTR_FLAG_TRANSITIVE, BGP_ATTR_ORIGIN, 1, &entry->origin) < 0 ||
        bgp_ribout_put_as_path(entry, buf, cap, &offset) < 0) {
        return -1;
    }

    // NEXT_HOP (3): only in the classic IPv4 format. MP families send the next hop in MP_REACH_NLRI.
    if (include_ipv4_next_hop &&
        (entry->next_hop_af != AF_INET ||
         bgp_ribout_put_attr(buf, cap, &offset, BGP_ATTR_FLAG_TRANSITIVE, BGP_ATTR_NEXT_HOP, 4,
                             &entry->next_hop.ipv4) < 0)) {
        return -1;
    }

    // MED (4) and LOCAL_PREF (5): 4-octet values in network byte order.
    if (entry->has_med) {
        value_net = htonl(entry->med);
        if (bgp_ribout_put_attr(buf, cap, &offset, BGP_ATTR_FLAG_OPTIONAL, BGP_ATTR_MULTI_EXIT_DISC, 4,
                                &value_net) < 0) {
            return -1;
        }
    }

    value_net = htonl(entry->local_pref);
    if (bgp_ribout_put_attr(buf, cap, &offset, BGP_ATTR_FLAG_TRANSITIVE, BGP_ATTR_LOCAL_PREF, 4, &value_net) < 0) {
        return -1;
    }

    // COMMUNITIES (8, RFC 1997): the set of this group, 4 octets per community.
    if (entry->community_len > 0 &&
        bgp_ribout_put_attr(buf, cap, &offset, optional_transitive, BGP_ATTR_COMMUNITIES, entry->community_len,
                            entry->community_data) < 0) {
        return -1;
    }

    // Extended communities (16): the generator already encoded them (RT, SoO, EVPN, Color, FlowSpec actions).
    if (entry->ext_comm_len > 0 && entry->ext_comm_data &&
        bgp_ribout_put_attr(buf, cap, &offset, optional_transitive, BGP_ATTR_EXT_COMM, entry->ext_comm_len,
                            entry->ext_comm_data) < 0) {
        return -1;
    }

    if (block->family_attr_type == BGP_ATTR_PMSI_TUNNEL &&
        bgp_ribout_put_attr(buf, cap, &offset, optional_transitive, BGP_ATTR_PMSI_TUNNEL,
                            block->family_attr_len, block->family_attr) < 0) return -1;

    // Tunnel Encapsulation (23): SR Policy only.
    if (entry->has_tunnel_encap && bgp_ribout_put_tunnel_encap(block, entry, buf, cap, &offset) < 0) {
        return -1;
    }

    /*
     * IPv6 Address Specific Extended Communities (25): the 20-octet FlowSpec action values, which hold an IPv6
     * address.
     */
    if (entry->ipv6_ext_comm_len > 0 && entry->ipv6_ext_comm_data &&
        bgp_ribout_put_attr(buf, cap, &offset, optional_transitive, BGP_ATTR_IPV6_EXT_COMM, entry->ipv6_ext_comm_len,
                            entry->ipv6_ext_comm_data) < 0) {
        return -1;
    }

    if (block->family_attr_type == BGP_ATTR_BGP_LS &&
        bgp_ribout_put_attr(buf, cap, &offset, BGP_ATTR_FLAG_OPTIONAL, BGP_ATTR_BGP_LS,
                            block->family_attr_len, block->family_attr) < 0) return -1;

    // LARGE_COMMUNITY (32, RFC 8092): 12 octets per large community.
    if (entry->large_community_len > 0 &&
        bgp_ribout_put_attr(buf, cap, &offset, optional_transitive, BGP_ATTR_LARGE_COMMUNITY,
                            entry->large_community_len, entry->large_community_data) < 0) {
        return -1;
    }

    return (int)offset;
}

typedef struct bgp_nlri_cursor {
    const bgp_ribout_nlri_chunk_t *chunk;
    const bgp_ribout_config_t     *block;      /* Owner of FlowSpec rule templates */
    uint16_t                       index;
    uint8_t                        nlri_type;  /* Record type of the entry         */
} bgp_nlri_cursor_t;

typedef int (*bgp_chunk_encoder_t)(bgp_nlri_cursor_t *cursor, uint8_t *buffer, int max_bytes, int add_path);

/*
 * Put a cursor on the first NLRI record of entry. block gives the FlowSpec encoder the rule templates.
 */
static void bgp_ribout_nlri_cursor_init(bgp_nlri_cursor_t *cursor,
                                        const bgp_ribout_config_t *block,
                                        const path_attr_entry_t *entry) {
    cursor->chunk = entry ? entry->nlri_chunks : NULL;
    cursor->block = block;
    cursor->index = 0;
    cursor->nlri_type = entry ? entry->nlri_type : 0;
}

static const void *bgp_ribout_nlri_cursor_data(const bgp_nlri_cursor_t *cursor) {
    return cursor->chunk ?
        (const void *)(cursor->chunk->data + ((size_t)cursor->index * cursor->chunk->stride)) :
        NULL;
}

static void bgp_ribout_nlri_cursor_advance(bgp_nlri_cursor_t *cursor) {
    if (!cursor->chunk) {
        return;
    }

    cursor->index++;
    while (cursor->chunk && cursor->index >= cursor->chunk->count) {
        cursor->chunk = cursor->chunk->next;
        cursor->index = 0;
    }
}

static void bgp_ribout_fill_next_hop(const path_attr_entry_t *entry, bgp_next_hop_t *next_hop) {
    memset(next_hop, 0, sizeof(*next_hop));
    next_hop->af = entry->next_hop_af;

    if (entry->next_hop_af == AF_INET) {
        next_hop->address.ipv4 = entry->next_hop.ipv4;
    } else if (entry->next_hop_af == AF_INET6) {
        next_hop->address.ipv6 = entry->next_hop.ipv6;
        next_hop->has_link_local = entry->next_hop_has_link_local;
        if (entry->next_hop_has_link_local) {
            next_hop->link_local = entry->next_hop_link_local;
        }
    }
}

static int bgp_ribout_encode_ipv4_nlri(uint8_t *buffer, const bgp_ribout_nlri_v4_t *nlri, int add_path) {
    ipv4_prefix_t prefix;
    int           offset = 0;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    prefix.prefix_len = nlri->prefix_len;
    prefix.prefix = nlri->prefix;
    return offset + bgp_encode_ipv4_prefix(buffer + offset, &prefix);
}

static int bgp_ribout_encode_ipv6_nlri(uint8_t *buffer, const bgp_ribout_nlri_v6_t *nlri, int add_path) {
    ipv6_prefix_t prefix;
    int           offset = 0;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    prefix.prefix_len = nlri->prefix_len;
    memcpy(prefix.prefix, nlri->prefix, sizeof(prefix.prefix));
    return offset + bgp_encode_ipv6_prefix(buffer + offset, &prefix);
}

static int bgp_ribout_encode_labeled_ipv4_nlri(uint8_t *buffer, const bgp_ribout_nlri_lu4_t *nlri, int add_path) {
    labeled_ipv4_prefix_t prefix;
    int                   offset = 0;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    prefix.prefix_len = (uint8_t)(24 + nlri->prefix_len);
    prefix.label.label = nlri->label;
    prefix.label.tc = 0;
    prefix.label.s = 1;
    prefix.label.ttl = 0;
    prefix.prefix = nlri->prefix;
    return offset + bgp_encode_labeled_ipv4_prefix(buffer + offset, &prefix);
}

static int bgp_ribout_encode_labeled_ipv6_nlri(uint8_t *buffer, const bgp_ribout_nlri_lu6_t *nlri, int add_path) {
    labeled_ipv6_prefix_t prefix;
    int                   offset = 0;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    prefix.prefix_len = (uint8_t)(24 + nlri->prefix_len);
    prefix.label.label = nlri->label;
    prefix.label.tc = 0;
    prefix.label.s = 1;
    prefix.label.ttl = 0;
    memcpy(prefix.prefix, nlri->prefix, sizeof(prefix.prefix));
    return offset + bgp_encode_labeled_ipv6_prefix(buffer + offset, &prefix);
}

static int bgp_ribout_encode_vpnv4_nlri(uint8_t *buffer, const bgp_ribout_nlri_vpnv4_t *nlri, int add_path) {
    vpnv4_prefix_t prefix;
    int            offset = 0;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    memset(&prefix, 0, sizeof(prefix));
    prefix.prefix_len = (uint8_t)(24 + 64 + nlri->prefix_len);
    prefix.label.label = nlri->label;
    prefix.label.tc = 0;
    prefix.label.s = 1;
    prefix.label.ttl = 0;
    prefix.rd = nlri->rd;
    prefix.prefix = nlri->prefix;
    return offset + bgp_encode_vpnv4_prefix(buffer + offset, &prefix);
}

static int bgp_ribout_encode_vpnv6_nlri(uint8_t *buffer, const bgp_ribout_nlri_vpnv6_t *nlri, int add_path) {
    vpnv6_prefix_t prefix;
    int            offset = 0;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    memset(&prefix, 0, sizeof(prefix));
    prefix.prefix_len = (uint8_t)(24 + 64 + nlri->prefix_len);
    prefix.label.label = nlri->label;
    prefix.label.tc = 0;
    prefix.label.s = 1;
    prefix.label.ttl = 0;
    prefix.rd = nlri->rd;
    memcpy(prefix.prefix, nlri->prefix, sizeof(prefix.prefix));
    return offset + bgp_encode_vpnv6_prefix(buffer + offset, &prefix);
}

static int bgp_ribout_encode_evpn4_nlri(uint8_t *buffer, const bgp_ribout_nlri_evpn4_t *nlri, int add_path) {
    evpn_type5_prefix_t prefix;
    int                 offset = 0;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    memset(&prefix, 0, sizeof(prefix));
    prefix.route_type = EVPN_RT_IP_PREFIX;
    prefix.af = AF_INET;
    prefix.rd = nlri->rd;
    prefix.esi = nlri->esi;
    prefix.ethernet_tag_id = nlri->ethernet_tag_id;
    prefix.ip_prefix_len = nlri->prefix_len;
    memcpy(prefix.ip_prefix, &nlri->prefix, sizeof(nlri->prefix));
    memcpy(prefix.gateway_ip, &nlri->gateway_ip, sizeof(nlri->gateway_ip));
    prefix.label.label = nlri->label;
    prefix.label.tc = 0;
    prefix.label.s = 1;
    prefix.label.ttl = 0;
    prefix.label_vni = nlri->label_vni;
    return offset + bgp_encode_evpn_type5_prefix(buffer + offset, &prefix);
}

static int bgp_ribout_encode_evpn6_nlri(uint8_t *buffer, const bgp_ribout_nlri_evpn6_t *nlri, int add_path) {
    evpn_type5_prefix_t prefix;
    int                 offset = 0;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    memset(&prefix, 0, sizeof(prefix));
    prefix.route_type = EVPN_RT_IP_PREFIX;
    prefix.af = AF_INET6;
    prefix.rd = nlri->rd;
    prefix.esi = nlri->esi;
    prefix.ethernet_tag_id = nlri->ethernet_tag_id;
    prefix.ip_prefix_len = nlri->prefix_len;
    memcpy(prefix.ip_prefix, nlri->prefix, sizeof(prefix.ip_prefix));
    memcpy(prefix.gateway_ip, nlri->gateway_ip, sizeof(prefix.gateway_ip));
    prefix.label.label = nlri->label;
    prefix.label.tc = 0;
    prefix.label.s = 1;
    prefix.label.ttl = 0;
    prefix.label_vni = nlri->label_vni;
    return offset + bgp_encode_evpn_type5_prefix(buffer + offset, &prefix);
}

static int bgp_ribout_encode_evpn2_nlri(uint8_t *buffer, const bgp_ribout_nlri_evpn2_t *nlri, int add_path) {
    evpn_type2_prefix_t prefix;
    int                 offset = 0;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    memset(&prefix, 0, sizeof(prefix));
    prefix.route_type = EVPN_RT_MAC_IP_ADVERTISEMENT;
    prefix.rd = nlri->rd;
    prefix.esi = nlri->esi;
    prefix.ethernet_tag_id = nlri->ethernet_tag_id;
    memcpy(prefix.mac_addr, nlri->mac, sizeof(prefix.mac_addr));
    prefix.ip_addr_len = nlri->ip_addr_len;
    memcpy(prefix.ip_addr, nlri->ip_addr, sizeof(prefix.ip_addr));
    prefix.label1.label = nlri->label1;
    prefix.label1.tc = 0;
    prefix.label1.s = 1;
    prefix.label1.ttl = 0;
    prefix.has_label2 = nlri->has_label2;
    if (nlri->has_label2) {
        prefix.label2.label = nlri->label2;
        prefix.label2.tc = 0;
        prefix.label2.s = 1;
        prefix.label2.ttl = 0;
    }
    prefix.label_vni = nlri->label_vni;

    return offset + bgp_encode_evpn_type2_prefix(buffer + offset, &prefix);
}

static int bgp_ribout_encode_srpolicy4_nlri(uint8_t *buffer, const bgp_ribout_nlri_sr4_t *nlri, int add_path) {
    srpolicy_prefix_t prefix;
    int               offset = 0;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    memset(&prefix, 0, sizeof(prefix));
    prefix.distinguisher = nlri->distinguisher;
    prefix.color = nlri->color;
    prefix.endpoint_af = AFI_IPV4;
    memcpy(prefix.endpoint, &nlri->endpoint, sizeof(nlri->endpoint));
    return offset + bgp_encode_srpolicy_prefix(buffer + offset, &prefix);
}

static int bgp_ribout_encode_srpolicy6_nlri(uint8_t *buffer, const bgp_ribout_nlri_sr6_t *nlri, int add_path) {
    srpolicy_prefix_t prefix;
    int               offset = 0;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    memset(&prefix, 0, sizeof(prefix));
    prefix.distinguisher = nlri->distinguisher;
    prefix.color = nlri->color;
    prefix.endpoint_af = AFI_IPV6;
    memcpy(prefix.endpoint, nlri->endpoint, sizeof(prefix.endpoint));
    return offset + bgp_encode_srpolicy_prefix(buffer + offset, &prefix);
}

static int bgp_ribout_evpn2_wire_size(const bgp_ribout_nlri_evpn2_t *nlri) {
    int size = 1 + 1 + 8 + 10 + 4 + 1 + 6 + 1 + 3;

    if (nlri->ip_addr_len == 32) {
        size += 4;
    } else if (nlri->ip_addr_len == 128) {
        size += 16;
    } else if (nlri->ip_addr_len != 0) {
        return -1;
    }

    if (nlri->has_label2) {
        size += 3;
    }

    return size;
}

/*
 * Chunk encoders: each one encodes records from the cursor, in map order, until the next record does not fit in
 * max_bytes, and moves the cursor past them. They return the bytes written, or -1 when not even one record fits. With
 * add_path, each NLRI starts with its 4-octet path ID (RFC 7911). This one: IPv4 prefixes.
 */
static int bgp_ribout_encode_ipv4_chunk(bgp_nlri_cursor_t *cursor, uint8_t *buffer, int max_bytes, int add_path) {
    int written = 0;

    while (cursor->chunk) {
        const bgp_ribout_nlri_v4_t *nlri = bgp_ribout_nlri_cursor_data(cursor);
        int                         needed = 1 + bgp_prefix_bytes_needed(nlri->prefix_len);

        if (add_path) {
            needed += 4;
        }
        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        written += bgp_ribout_encode_ipv4_nlri(buffer + written, nlri, add_path);
        bgp_ribout_nlri_cursor_advance(cursor);
    }

    return written;
}

/*
 * IPv6 prefixes.
 */
static int bgp_ribout_encode_ipv6_chunk(bgp_nlri_cursor_t *cursor, uint8_t *buffer, int max_bytes, int add_path) {
    int written = 0;

    while (cursor->chunk) {
        const bgp_ribout_nlri_v6_t *nlri = bgp_ribout_nlri_cursor_data(cursor);
        int                         needed = 1 + bgp_prefix_bytes_needed(nlri->prefix_len);

        if (add_path) {
            needed += 4;
        }
        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        written += bgp_ribout_encode_ipv6_nlri(buffer + written, nlri, add_path);
        bgp_ribout_nlri_cursor_advance(cursor);
    }

    return written;
}

/*
 * Labeled IPv4 prefixes, one label each (RFC 8277).
 */
static int bgp_ribout_encode_labeled_ipv4_chunk(bgp_nlri_cursor_t *cursor, uint8_t *buffer, int max_bytes,
                                                int add_path) {
    int written = 0;

    while (cursor->chunk) {
        const bgp_ribout_nlri_lu4_t *nlri = bgp_ribout_nlri_cursor_data(cursor);
        int                          needed = 1 + 3 + bgp_prefix_bytes_needed(nlri->prefix_len);

        if (add_path) {
            needed += 4;
        }
        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        written += bgp_ribout_encode_labeled_ipv4_nlri(buffer + written, nlri, add_path);
        bgp_ribout_nlri_cursor_advance(cursor);
    }

    return written;
}

/*
 * Labeled IPv6 prefixes, one label each (RFC 8277).
 */
static int bgp_ribout_encode_labeled_ipv6_chunk(bgp_nlri_cursor_t *cursor, uint8_t *buffer, int max_bytes,
                                                int add_path) {
    int written = 0;

    while (cursor->chunk) {
        const bgp_ribout_nlri_lu6_t *nlri = bgp_ribout_nlri_cursor_data(cursor);
        int                          needed = 1 + 3 + bgp_prefix_bytes_needed(nlri->prefix_len);

        if (add_path) {
            needed += 4;
        }
        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        written += bgp_ribout_encode_labeled_ipv6_nlri(buffer + written, nlri, add_path);
        bgp_ribout_nlri_cursor_advance(cursor);
    }

    return written;
}

/*
 * EVPN Type 2 MAC/IP routes (RFC 7432 section 7.2).
 */
static int bgp_ribout_encode_evpn2_chunk(bgp_nlri_cursor_t *cursor, uint8_t *buffer, int max_bytes, int add_path) {
    int written = 0;

    while (cursor->chunk) {
        const bgp_ribout_nlri_evpn2_t *nlri = bgp_ribout_nlri_cursor_data(cursor);
        int                            needed = bgp_ribout_evpn2_wire_size(nlri);

        if (add_path) {
            needed += 4;
        }
        if (needed < 0) {
            return -1;
        }
        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        written += bgp_ribout_encode_evpn2_nlri(buffer + written, nlri, add_path);
        bgp_ribout_nlri_cursor_advance(cursor);
    }

    return written;
}

/*
 * VPNv4 routes: label, RD and IPv4 prefix (RFC 4364).
 */
static int bgp_ribout_encode_vpnv4_chunk(bgp_nlri_cursor_t *cursor, uint8_t *buffer, int max_bytes, int add_path) {
    int written = 0;

    while (cursor->chunk) {
        const bgp_ribout_nlri_vpnv4_t *nlri = bgp_ribout_nlri_cursor_data(cursor);
        int                            needed = 1 + 3 + 8 + bgp_prefix_bytes_needed(nlri->prefix_len);

        if (add_path) {
            needed += 4;
        }
        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        written += bgp_ribout_encode_vpnv4_nlri(buffer + written, nlri, add_path);
        bgp_ribout_nlri_cursor_advance(cursor);
    }

    return written;
}

/*
 * VPNv6 routes: label, RD and IPv6 prefix (RFC 4659).
 */
static int bgp_ribout_encode_vpnv6_chunk(bgp_nlri_cursor_t *cursor, uint8_t *buffer, int max_bytes, int add_path) {
    int written = 0;

    while (cursor->chunk) {
        const bgp_ribout_nlri_vpnv6_t *nlri = bgp_ribout_nlri_cursor_data(cursor);
        int                            needed = 1 + 3 + 8 + bgp_prefix_bytes_needed(nlri->prefix_len);

        if (add_path) {
            needed += 4;
        }
        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        written += bgp_ribout_encode_vpnv6_nlri(buffer + written, nlri, add_path);
        bgp_ribout_nlri_cursor_advance(cursor);
    }

    return written;
}

/*
 * EVPN Type 5 routes with an IPv4 prefix (RFC 9136).
 */
static int bgp_ribout_encode_evpn4_chunk(bgp_nlri_cursor_t *cursor, uint8_t *buffer, int max_bytes, int add_path) {
    int written = 0;

    while (cursor->chunk) {
        const bgp_ribout_nlri_evpn4_t *nlri = bgp_ribout_nlri_cursor_data(cursor);
        /*
         * EVPN Type 5 IPv4 payload:
         * route-type(1) + route-len(1) + RD(8) + ESI(10) + Ethernet Tag(4) +
         * prefix-len(1) + IPv4 prefix(4) + GW-IP(4) + label(3).
         */
        int needed = 36;

        if (add_path) {
            needed += 4;
        }
        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        written += bgp_ribout_encode_evpn4_nlri(buffer + written, nlri, add_path);
        bgp_ribout_nlri_cursor_advance(cursor);
    }

    return written;
}

/*
 * EVPN Type 5 routes with an IPv6 prefix (RFC 9136).
 */
static int bgp_ribout_encode_evpn6_chunk(bgp_nlri_cursor_t *cursor, uint8_t *buffer, int max_bytes, int add_path) {
    int written = 0;

    while (cursor->chunk) {
        const bgp_ribout_nlri_evpn6_t *nlri = bgp_ribout_nlri_cursor_data(cursor);
        /*
         * EVPN Type 5 IPv6 payload:
         * route-type(1) + route-len(1) + RD(8) + ESI(10) + Ethernet Tag(4) +
         * prefix-len(1) + IPv6 prefix(16) + GW-IP(16) + label(3).
         */
        int needed = 60;

        if (add_path) {
            needed += 4;
        }
        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        written += bgp_ribout_encode_evpn6_nlri(buffer + written, nlri, add_path);
        bgp_ribout_nlri_cursor_advance(cursor);
    }

    return written;
}

/*
 * SR Policy NLRIs with an IPv4 endpoint (RFC 9830).
 */
static int bgp_ribout_encode_srpolicy4_chunk(bgp_nlri_cursor_t *cursor, uint8_t *buffer, int max_bytes, int add_path) {
    int written = 0;

    while (cursor->chunk) {
        const bgp_ribout_nlri_sr4_t *nlri = bgp_ribout_nlri_cursor_data(cursor);
        int                          needed = 1 + 4 + 4 + 4;

        if (add_path) {
            needed += 4;
        }
        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        written += bgp_ribout_encode_srpolicy4_nlri(buffer + written, nlri, add_path);
        bgp_ribout_nlri_cursor_advance(cursor);
    }

    return written;
}

/*
 * SR Policy NLRIs with an IPv6 endpoint (RFC 9830).
 */
static int bgp_ribout_encode_srpolicy6_chunk(bgp_nlri_cursor_t *cursor, uint8_t *buffer, int max_bytes, int add_path) {
    int written = 0;

    while (cursor->chunk) {
        const bgp_ribout_nlri_sr6_t *nlri = bgp_ribout_nlri_cursor_data(cursor);
        int                          needed = 1 + 4 + 4 + 16;

        if (add_path) {
            needed += 4;
        }
        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        written += bgp_ribout_encode_srpolicy6_nlri(buffer + written, nlri, add_path);
        bgp_ribout_nlri_cursor_advance(cursor);
    }

    return written;
}

/*
 * FlowSpec records hold an instance number. Each one is rebuilt from the block
 * as a flowspec_rule_t and encoded by the FlowSpec library, which owns the NLRI
 * wire format (length, RD, components).
 */
static int bgp_ribout_encode_flowspec_chunk(bgp_nlri_cursor_t *cursor, uint8_t *buffer, int max_bytes, int add_path) {
    int                             written = 0;
    const bgp_ribout_family_info_t *info = bgp_ribout_nlri_info(cursor->nlri_type);
    uint16_t                        afi = info->afi;
    int                             vpn = (info->safi == SAFI_FLOWSPEC_VPN);

    while (cursor->chunk) {
        const bgp_ribout_nlri_flowspec_t *nlri = bgp_ribout_nlri_cursor_data(cursor);
        bgp_ribout_flowspec_nlri_t        rule;
        uint8_t                           entry_buf[FLOWSPEC_MAX_NLRI_ENTRY_LEN];
        int                               needed;

        if (!cursor->block || bgp_ribout_flowspec_materialize(cursor->block, nlri->instance, &rule) < 0) {
            return -1;
        }

        needed = bgp_encode_flowspec_nlri_entry(entry_buf, &rule.rule, vpn ? &nlri->rd : NULL,
                                                afi, add_path, nlri->path_id);
        if (needed <= 0) {
            return -1;
        }
        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        memcpy(buffer + written, entry_buf, (size_t)needed);
        written += needed;
        bgp_ribout_nlri_cursor_advance(cursor);
    }

    return written;
}

/*
 * Materialize compact template indices through the canonical family codecs.
 */
static int bgp_ribout_encode_template_chunk(bgp_nlri_cursor_t *cursor, uint8_t *buffer, int max_bytes, int add_path) {
    int written = 0;
    if (!cursor->block) return -1;
    while (cursor->chunk) {
        const bgp_ribout_nlri_template_t *nlri = bgp_ribout_nlri_cursor_data(cursor);
        uint8_t                           encoded[1024];
        int                               len = bgp_ribout_template_encode(&cursor->block->nlri_template, nlri->instance, encoded);
        if (len < 0) return -1;
        int needed = len + (add_path ? 4 : 0);
        if (needed > max_bytes - written) return written ? written : -1;
        if (add_path) {
            uint32_t id = htonl(nlri->path_id);
            memcpy(buffer + written, &id, 4);
            written += 4;
        }
        memcpy(buffer + written, encoded, (size_t)len);
        written += len;
        bgp_ribout_nlri_cursor_advance(cursor);
    }
    return written;
}

/*
 * Encode an IPv4 unicast entry with NEXT_HOP and trailing NLRI, split to fit the PDU budget.
 */
static int bgp_ribout_generate_ipv4_unicast_entry(const bgp_ribout_config_t *block,
                                                  const path_attr_entry_t *entry,
                                                  int add_path,
                                                  bgp_chunk_encoder_t encode_chunk,
                                                  bgp_builder_t *builder) {
    bgp_nlri_cursor_t cursor;
    uint8_t           attr_buf[BGP_MAX_PDU_SIZE];
    uint8_t           chunk_buf[BGP_MAX_PDU_SIZE];
    int               attr_len;
    int               available_space;

    attr_len = bgp_ribout_write_entry_attrs(block, entry, 1, attr_buf, sizeof(attr_buf));
    if (attr_len < 0) {
        return -1;
    }

    /*
     * Space for NLRI in one UPDATE: the PDU less the header, Withdrawn Routes Length (2), Total Path Attribute
     * Length (2) and the attributes.
     */
    available_space = BGP_MAX_PDU_SIZE - (BGP_HEADER_SIZE + 2 + 2 + attr_len);
    if (available_space <= 0) {
        return -1;
    }

    bgp_ribout_nlri_cursor_init(&cursor, block, entry);
    while (cursor.chunk) {
        int chunk_len = encode_chunk(&cursor, chunk_buf, available_space, add_path);

        if (chunk_len <= 0 ||
            bgp_builder_append(builder, NULL, 0, attr_buf, (uint16_t)attr_len, chunk_buf, (uint16_t)chunk_len) < 0) {
            return -1;
        }
    }

    return 0;
}

/*
 * Encode one entry as MP_REACH_NLRI UPDATEs (RFC 4760) with afi/safi and an encoded next hop; next_hop is NULL when
 * nh_len is 0. Every UPDATE has the shared attributes and as many records as fit; they are appended to builder.
 */
static int bgp_ribout_generate_mp_entry(const bgp_ribout_config_t *block,
                                        const path_attr_entry_t *entry,
                                        uint16_t afi, uint8_t safi,
                                        const uint8_t *next_hop, uint8_t nh_len, int add_path,
                                        bgp_chunk_encoder_t encode_chunk,
                                        bgp_builder_t *builder) {
    bgp_nlri_cursor_t cursor;
    uint8_t           attr_buf[BGP_MAX_PDU_SIZE];
    uint8_t           chunk_buf[BGP_MAX_PDU_SIZE];
    bgp_mp_args_t     mp_args;
    int               attr_len;
    int               available_space;

    attr_len = bgp_ribout_write_entry_attrs(block, entry, 0, attr_buf, sizeof(attr_buf));
    if (attr_len < 0) {
        return -1;
    }

    /*
     * Space for NLRI in one UPDATE: the PDU less the header, the two 2-octet length fields, the attributes, and the
     * MP_REACH_NLRI attribute without its NLRI: an extended-length attribute header (4), AFI (2), SAFI (1), Next Hop
     * Length (1), the next hop and the reserved octet (1).
     */
    available_space = BGP_MAX_PDU_SIZE - (BGP_HEADER_SIZE + 2 + 2 + attr_len + 4 + 2 + 1 + 1 + nh_len + 1);
    if (available_space <= 0) {
        return -1;
    }

    /*
     * Reuse one MP argument template for every chunk emitted from this
     * attribute bucket. Only the MP NLRI length changes inside the loop.
     */
    mp_args = (bgp_mp_args_t){
        .attrs       = attr_buf,
        .attrs_len   = (uint16_t)attr_len,
        .is_reach    = 1,
        .afi         = afi,
        .safi        = safi,
        .next_hop    = next_hop,
        .nh_len      = nh_len,
        .mp_nlri     = chunk_buf,
    };

    /*
     * Serialize directly from the chunked ribout map so UPDATE bytes remain
     * fully owned by the message cache without any intermediate NLRI lists.
     */
    bgp_ribout_nlri_cursor_init(&cursor, block, entry);
    while (cursor.chunk) {
        int chunk_len = encode_chunk(&cursor, chunk_buf, available_space, add_path);

        if (chunk_len <= 0) {
            return -1;
        }

        mp_args.mp_nlri_len = (uint16_t)chunk_len;
        if (bgp_builder_append_mp(builder, &mp_args) < 0) {
            return -1;
        }
    }

    return 0;
}

/*
 * VPN next hops carry an RD of zero; the transport follows the address
 * (RFC 4364, RFC 4659).
 */
static bgp_vpn_transport_t bgp_ribout_vpn_transport(const bgp_next_hop_t *next_hop) {
    return next_hop->af == AF_INET ? BGP_VPN_TRANSPORT_IPV4 : BGP_VPN_TRANSPORT_IPV6;
}

/*
 * VPNv4 next hop for bgp_ribout_families[]: RD 0 plus an IPv4 address, or an IPv6 one (RFC 8950).
 */
static int bgp_ribout_encode_vpnv4_next_hop(const bgp_next_hop_t *next_hop, uint8_t *buffer, uint8_t *nh_len_out) {
    return bgp_encode_vpn_next_hop(AFI_IPV4, bgp_ribout_vpn_transport(next_hop), next_hop, buffer, nh_len_out);
}

/*
 * VPNv6 next hop: RD 0 plus the address, with IPv4 or IPv6 transport (RFC 4659).
 */
static int bgp_ribout_encode_vpnv6_next_hop(const bgp_next_hop_t *next_hop, uint8_t *buffer, uint8_t *nh_len_out) {
    return bgp_encode_vpn_next_hop(AFI_IPV6, bgp_ribout_vpn_transport(next_hop), next_hop, buffer, nh_len_out);
}

#define BGP_RIBOUT_NH_ANY (BGP_RIBOUT_NH_IPV4 | BGP_RIBOUT_NH_IPV6)

/*
 * Family table: see bgp_ribout_family_info_t. Rows are in enum order.
 */
const bgp_ribout_family_info_t bgp_ribout_families[BGP_RIBOUT_FAMILY_COUNT] = {
    [BGP_RIBOUT_FAMILY_NONE] = {
        .name = "none",
    },
    [BGP_RIBOUT_FAMILY_IPV4_UNICAST] = {
        .name = "ipv4-unicast", .afi = AFI_IPV4, .safi = SAFI_UNICAST,
        .kind = BGP_RIBOUT_KIND_PREFIX, .prefix_af = AF_INET, .next_hop_afs = BGP_RIBOUT_NH_ANY,
        .nlri_stride = sizeof(bgp_ribout_nlri_v4_t),
        .encode_next_hop = bgp_encode_ipv6_family_next_hop, .encode_chunk = bgp_ribout_encode_ipv4_chunk,
    },
    [BGP_RIBOUT_FAMILY_IPV6_UNICAST] = {
        .name = "ipv6-unicast", .afi = AFI_IPV6, .safi = SAFI_UNICAST,
        .kind = BGP_RIBOUT_KIND_PREFIX, .prefix_af = AF_INET6, .next_hop_afs = BGP_RIBOUT_NH_IPV6,
        .nlri_stride = sizeof(bgp_ribout_nlri_v6_t),
        .encode_next_hop = bgp_encode_ipv6_family_next_hop, .encode_chunk = bgp_ribout_encode_ipv6_chunk,
    },
    [BGP_RIBOUT_FAMILY_LABELED_IPV4] = {
        .name = "ipv4-labeled-unicast", .afi = AFI_IPV4, .safi = SAFI_LABELED_UNICAST,
        .kind = BGP_RIBOUT_KIND_PREFIX, .prefix_af = AF_INET, .has_label = 1, .next_hop_afs = BGP_RIBOUT_NH_ANY,
        .nlri_stride = sizeof(bgp_ribout_nlri_lu4_t),
        .encode_next_hop = bgp_encode_labeled_ipv4_next_hop, .encode_chunk = bgp_ribout_encode_labeled_ipv4_chunk,
    },
    [BGP_RIBOUT_FAMILY_LABELED_IPV6] = {
        .name = "ipv6-labeled-unicast", .afi = AFI_IPV6, .safi = SAFI_LABELED_UNICAST,
        .kind = BGP_RIBOUT_KIND_PREFIX, .prefix_af = AF_INET6, .has_label = 1, .next_hop_afs = BGP_RIBOUT_NH_IPV6,
        .nlri_stride = sizeof(bgp_ribout_nlri_lu6_t),
        .encode_next_hop = bgp_encode_ipv6_family_next_hop, .encode_chunk = bgp_ribout_encode_labeled_ipv6_chunk,
    },
    [BGP_RIBOUT_FAMILY_VPNV4] = {
        .name = "vpnv4", .afi = AFI_IPV4, .safi = SAFI_MPLS_VPN,
        .kind = BGP_RIBOUT_KIND_PREFIX, .prefix_af = AF_INET, .next_hop_afs = BGP_RIBOUT_NH_ANY,
        .nlri_stride = sizeof(bgp_ribout_nlri_vpnv4_t),
        .encode_next_hop = bgp_ribout_encode_vpnv4_next_hop, .encode_chunk = bgp_ribout_encode_vpnv4_chunk,
    },
    [BGP_RIBOUT_FAMILY_VPNV6] = {
        .name = "vpnv6", .afi = AFI_IPV6, .safi = SAFI_MPLS_VPN,
        .kind = BGP_RIBOUT_KIND_PREFIX, .prefix_af = AF_INET6, .next_hop_afs = BGP_RIBOUT_NH_ANY,
        .nlri_stride = sizeof(bgp_ribout_nlri_vpnv6_t),
        .encode_next_hop = bgp_ribout_encode_vpnv6_next_hop, .encode_chunk = bgp_ribout_encode_vpnv6_chunk,
    },
    [BGP_RIBOUT_FAMILY_EVPN_TYPE5_IPV4] = {
        .name = "evpn-type5-ipv4", .afi = AFI_L2VPN, .safi = SAFI_EVPN,
        .kind = BGP_RIBOUT_KIND_PREFIX, .prefix_af = AF_INET, .next_hop_afs = BGP_RIBOUT_NH_ANY,
        .nlri_stride = sizeof(bgp_ribout_nlri_evpn4_t),
        .encode_next_hop = bgp_encode_evpn_next_hop, .encode_chunk = bgp_ribout_encode_evpn4_chunk,
    },
    [BGP_RIBOUT_FAMILY_EVPN_TYPE5_IPV6] = {
        .name = "evpn-type5-ipv6", .afi = AFI_L2VPN, .safi = SAFI_EVPN,
        .kind = BGP_RIBOUT_KIND_PREFIX, .prefix_af = AF_INET6, .next_hop_afs = BGP_RIBOUT_NH_ANY,
        .nlri_stride = sizeof(bgp_ribout_nlri_evpn6_t),
        .encode_next_hop = bgp_encode_evpn_next_hop, .encode_chunk = bgp_ribout_encode_evpn6_chunk,
    },
    [BGP_RIBOUT_FAMILY_SR_POLICY_IPV4] = {
        .name = "ipv4-sr-policy", .afi = AFI_IPV4, .safi = SAFI_SR_POLICY,
        .kind = BGP_RIBOUT_KIND_SR_POLICY, .prefix_af = AF_INET, .next_hop_afs = BGP_RIBOUT_NH_ANY,
        .nlri_stride = sizeof(bgp_ribout_nlri_sr4_t),
        .encode_next_hop = bgp_encode_srpolicy_next_hop, .encode_chunk = bgp_ribout_encode_srpolicy4_chunk,
    },
    [BGP_RIBOUT_FAMILY_SR_POLICY_IPV6] = {
        .name = "ipv6-sr-policy", .afi = AFI_IPV6, .safi = SAFI_SR_POLICY,
        .kind = BGP_RIBOUT_KIND_SR_POLICY, .prefix_af = AF_INET6, .next_hop_afs = BGP_RIBOUT_NH_ANY,
        .nlri_stride = sizeof(bgp_ribout_nlri_sr6_t),
        .encode_next_hop = bgp_encode_srpolicy_next_hop, .encode_chunk = bgp_ribout_encode_srpolicy6_chunk,
    },
    [BGP_RIBOUT_FAMILY_EVPN_TYPE2] = {
        .name = "evpn-type2", .afi = AFI_L2VPN, .safi = SAFI_EVPN,
        .kind = BGP_RIBOUT_KIND_EVPN_TYPE2, .next_hop_afs = BGP_RIBOUT_NH_ANY,
        .nlri_stride = sizeof(bgp_ribout_nlri_evpn2_t),
        .encode_next_hop = bgp_encode_evpn_next_hop, .encode_chunk = bgp_ribout_encode_evpn2_chunk,
    },
    [BGP_RIBOUT_FAMILY_FLOWSPEC_IPV4] = {
        .name = "ipv4-flowspec", .afi = AFI_IPV4, .safi = SAFI_FLOWSPEC,
        .kind = BGP_RIBOUT_KIND_FLOWSPEC, .prefix_af = AF_INET, .next_hop_afs = BGP_RIBOUT_NH_ANY,
        .next_hop_optional = 1, .nlri_stride = sizeof(bgp_ribout_nlri_flowspec_t),
        .encode_next_hop = bgp_encode_standard_next_hop, .encode_chunk = bgp_ribout_encode_flowspec_chunk,
    },
    [BGP_RIBOUT_FAMILY_FLOWSPEC_IPV6] = {
        .name = "ipv6-flowspec", .afi = AFI_IPV6, .safi = SAFI_FLOWSPEC,
        .kind = BGP_RIBOUT_KIND_FLOWSPEC, .prefix_af = AF_INET6, .next_hop_afs = BGP_RIBOUT_NH_ANY,
        .next_hop_optional = 1, .nlri_stride = sizeof(bgp_ribout_nlri_flowspec_t),
        .encode_next_hop = bgp_encode_standard_next_hop, .encode_chunk = bgp_ribout_encode_flowspec_chunk,
    },
    [BGP_RIBOUT_FAMILY_FLOWSPEC_VPN_IPV4] = {
        .name = "ipv4-flowspec-vpn", .afi = AFI_IPV4, .safi = SAFI_FLOWSPEC_VPN,
        .kind = BGP_RIBOUT_KIND_FLOWSPEC, .prefix_af = AF_INET, .next_hop_afs = BGP_RIBOUT_NH_ANY,
        .next_hop_optional = 1, .nlri_stride = sizeof(bgp_ribout_nlri_flowspec_t),
        .encode_next_hop = bgp_encode_standard_next_hop, .encode_chunk = bgp_ribout_encode_flowspec_chunk,
    },
    [BGP_RIBOUT_FAMILY_FLOWSPEC_VPN_IPV6] = {
        .name = "ipv6-flowspec-vpn", .afi = AFI_IPV6, .safi = SAFI_FLOWSPEC_VPN,
        .kind = BGP_RIBOUT_KIND_FLOWSPEC, .prefix_af = AF_INET6, .next_hop_afs = BGP_RIBOUT_NH_ANY,
        .next_hop_optional = 1, .nlri_stride = sizeof(bgp_ribout_nlri_flowspec_t),
        .encode_next_hop = bgp_encode_standard_next_hop, .encode_chunk = bgp_ribout_encode_flowspec_chunk,
    },
#define TEMPLATE_FAMILY(family, label, af, saf)                                                            \
    [BGP_RIBOUT_FAMILY_##family] = {                                                                       \
        .name = label, .afi = af, .safi = saf, .kind = BGP_RIBOUT_KIND_TEMPLATE,                           \
        .next_hop_afs = BGP_RIBOUT_NH_ANY, .nlri_stride = sizeof(bgp_ribout_nlri_template_t),              \
        .encode_next_hop = bgp_encode_standard_next_hop, .encode_chunk = bgp_ribout_encode_template_chunk, \
    }
    TEMPLATE_FAMILY(RTC, "ipv4-rtc", AFI_IPV4, SAFI_RTC),
    TEMPLATE_FAMILY(VPLS, "l2vpn-vpls", AFI_L2VPN, SAFI_VPLS),
    TEMPLATE_FAMILY(EVPN_TYPE1, "evpn-type1", AFI_L2VPN, SAFI_EVPN),
    TEMPLATE_FAMILY(EVPN_TYPE3, "evpn-type3", AFI_L2VPN, SAFI_EVPN),
    TEMPLATE_FAMILY(EVPN_TYPE4, "evpn-type4", AFI_L2VPN, SAFI_EVPN),
    TEMPLATE_FAMILY(MVPN_IPV4, "ipv4-mvpn", AFI_IPV4, SAFI_MVPN),
    TEMPLATE_FAMILY(MVPN_IPV6, "ipv6-mvpn", AFI_IPV6, SAFI_MVPN),
    TEMPLATE_FAMILY(BGP_LS, "bgp-ls", AFI_BGP_LS, SAFI_BGP_LS),
#undef TEMPLATE_FAMILY
};

#undef BGP_RIBOUT_NH_ANY

#define BGP_RIBOUT_SAME_NUMBER(name)                                                 \
    STATIC_ASSERT((int)BGP_RIBOUT_NLRI_TYPE_##name == (int)BGP_RIBOUT_FAMILY_##name, \
                  "NLRI type and family " #name " must share a number")
BGP_RIBOUT_SAME_NUMBER(VPNV4);
BGP_RIBOUT_SAME_NUMBER(VPNV6);
BGP_RIBOUT_SAME_NUMBER(EVPN_TYPE5_IPV4);
BGP_RIBOUT_SAME_NUMBER(EVPN_TYPE5_IPV6);
BGP_RIBOUT_SAME_NUMBER(SR_POLICY_IPV4);
BGP_RIBOUT_SAME_NUMBER(SR_POLICY_IPV6);
BGP_RIBOUT_SAME_NUMBER(EVPN_TYPE2);
BGP_RIBOUT_SAME_NUMBER(FLOWSPEC_IPV4);
BGP_RIBOUT_SAME_NUMBER(FLOWSPEC_IPV6);
BGP_RIBOUT_SAME_NUMBER(FLOWSPEC_VPN_IPV4);
BGP_RIBOUT_SAME_NUMBER(FLOWSPEC_VPN_IPV6);
BGP_RIBOUT_SAME_NUMBER(RTC);
BGP_RIBOUT_SAME_NUMBER(VPLS);
BGP_RIBOUT_SAME_NUMBER(EVPN_TYPE1);
BGP_RIBOUT_SAME_NUMBER(EVPN_TYPE3);
BGP_RIBOUT_SAME_NUMBER(EVPN_TYPE4);
BGP_RIBOUT_SAME_NUMBER(MVPN_IPV4);
BGP_RIBOUT_SAME_NUMBER(MVPN_IPV6);
BGP_RIBOUT_SAME_NUMBER(BGP_LS);
#undef BGP_RIBOUT_SAME_NUMBER
STATIC_ASSERT((int)BGP_RIBOUT_NLRI_TYPE_IPV4 == (int)BGP_RIBOUT_FAMILY_IPV4_UNICAST, "IPv4 numbers differ");
STATIC_ASSERT((int)BGP_RIBOUT_NLRI_TYPE_IPV6 == (int)BGP_RIBOUT_FAMILY_IPV6_UNICAST, "IPv6 numbers differ");
STATIC_ASSERT((int)BGP_RIBOUT_NLRI_TYPE_LABELED_IPV4 == (int)BGP_RIBOUT_FAMILY_LABELED_IPV4, "LU4 numbers differ");
STATIC_ASSERT((int)BGP_RIBOUT_NLRI_TYPE_LABELED_IPV6 == (int)BGP_RIBOUT_FAMILY_LABELED_IPV6, "LU6 numbers differ");
STATIC_ASSERT(BGP_RIBOUT_FAMILY_BGP_LS + 1 == BGP_RIBOUT_FAMILY_COUNT, "family table size");

/*
 * Encode one grouped-map entry with the next-hop and NLRI encoders of its family row and append its UPDATEs to
 * builder.
 */
static int bgp_ribout_generate_entry_messages(const bgp_ribout_config_t *block,
                                              const path_attr_entry_t *entry,
                                              bgp_builder_t *builder) {
    const bgp_ribout_family_info_t *info = bgp_ribout_nlri_info(entry->nlri_type);
    bgp_next_hop_t                  next_hop;
    uint8_t                         nh_buf[48];
    uint8_t                         nh_len = 0;
    int                             add_path = (block->path_id_count > 0);

    if (!info->encode_chunk) {
        return -1;
    }

    /*
     * IPv4 unicast with an IPv4 next hop uses the classic NEXT_HOP and NLRI
     * fields; every other case is MP_REACH_NLRI.
     */
    if (entry->nlri_type == BGP_RIBOUT_NLRI_TYPE_IPV4 && entry->next_hop_af == AF_INET) {
        return bgp_ribout_generate_ipv4_unicast_entry(block, entry, add_path, bgp_ribout_encode_ipv4_chunk, builder);
    }

    /*
     * FlowSpec sends a zero-length next hop (RFC 8955 section 4) unless a
     * redirect-to-next-hop action gave the entry one.
     */
    if (!info->next_hop_optional || entry->next_hop_af != 0) {
        bgp_ribout_fill_next_hop(entry, &next_hop);
        if (info->encode_next_hop(&next_hop, nh_buf, &nh_len) < 0) {
            return -1;
        }
    }

    return bgp_ribout_generate_mp_entry(block, entry, info->afi, info->safi, nh_len ? nh_buf : NULL, nh_len,
                                        add_path, info->encode_chunk, builder);
}

static int append_update_result_messages(bgp_msg_t **list_head, bgp_msg_t **list_tail,
                                         size_t *total_messages, uint64_t *total_bytes,
                                         bgp_update_result_t *result) {
    int i;

    for (i = 0; i < result->num_messages; i++) {
        bgp_msg_t *msg = malloc(sizeof(*msg));
        if (!msg) {
            return -1;
        }

        msg->length = result->message_lens[i];
        msg->data = result->messages[i];
        msg->next = NULL;

        /*
         * Transfer ownership of the encoded UPDATE buffer directly into the
         * ribout message list instead of allocating and copying it again.
         */
        result->messages[i] = NULL;

        if (*list_head == NULL) {
            *list_head = msg;
            *list_tail = msg;
        } else {
            (*list_tail)->next = msg;
            *list_tail = msg;
        }

        (*total_messages)++;
        *total_bytes += msg->length;
    }

    return 0;
}

/*
 * Generate BGP UPDATE messages from ribout map
 */
int bgp_ribout_generate_messages(bgp_ribout_config_t *block) {
    int generation_failed = 0;

    if (!block || !block->ribout) {
        fprintf(stderr, "Error: No ribout map to generate messages from\n");
        return -1;
    }

    // Start timing
    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    bgp_ribout_map_t *map = block->ribout;
    bgp_msg_t        *msg_list_head = NULL;
    bgp_msg_t        *msg_list_tail = NULL;
    size_t            total_messages = 0;
    uint64_t          total_bytes = 0;
    bgp_builder_t     builder;

    /*
     * One builder for the whole walk, so its result and arrays are allocated once, not once per entry. For each
     * entry: the builder collects the UPDATEs; append_update_result_messages() moves each UPDATE buffer to the message
     * list and sets its builder slot to NULL; bgp_builder_clear() sets the count to 0. After an error,
     * bgp_builder_release() frees the UPDATEs that did not move.
     */
    if (bgp_builder_init(&builder) < 0) {
        generation_failed = 1;
    }

    /*
     * Walk the groups in insertion order: the UPDATEs follow the generator order (not the hash), and the walk reads
     * the arena forward.
     */
    for (path_attr_entry_t *entry = map->order_head; !generation_failed && entry; entry = entry->order_next) {
        if (bgp_ribout_generate_entry_messages(block, entry, &builder) < 0 ||
            append_update_result_messages(&msg_list_head, &msg_list_tail,
                                          &total_messages, &total_bytes, builder.result) < 0) {
            generation_failed = 1;
            break;
        }
        bgp_builder_clear(&builder);
    }
    bgp_builder_release(&builder);

    if (generation_failed) {
        bgp_msg_list_free(msg_list_head);
        block->message_time_ms = 0.0;
        return -1;
    }

    // Publish the messages as a new snapshot. The old snapshot stays alive while peers hold it.
    bgp_tx_profile_t       profile;
    bgp_ribout_snapshot_t *snapshot;

    bgp_ribout_snapshot_profile(block, map, &profile);
    snapshot = bgp_ribout_snapshot_create(block, &profile, msg_list_head, total_messages, total_bytes);
    if (!snapshot) {
        bgp_msg_list_free(msg_list_head);
        block->message_time_ms = 0.0;
        return -1;
    }
    bgp_ribout_snapshot_unref(block->snapshot);
    block->snapshot = snapshot;
    block->messages = snapshot->adv->msgs;
    block->message_count = total_messages;

    // Free the map - no longer needed
    bgp_ribout_map_destroy(block->ribout);
    block->ribout = NULL;

    // Stop timing and calculate elapsed time in milliseconds
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    double elapsed_sec = (end_time.tv_sec - start_time.tv_sec);
    double elapsed_nsec = (end_time.tv_nsec - start_time.tv_nsec);
    block->message_time_ms = (elapsed_sec * 1000.0) + (elapsed_nsec / 1000000.0);

    return 0;
}

bgp_ribout_generation_result_t bgp_ribout_generate(bgp_ribout_config_t *block) {
    struct timespec start, end, cpu_start, cpu_end;
    if (!block) return BGP_RIBOUT_MAP_FAILED;
    block->dirty = 1;
    block->generation_time_ms = block->generation_cpu_ms = block->map_time_ms = block->message_time_ms = 0;
    if (bgp_ribout_resolve_family(block) == BGP_RIBOUT_FAMILY_NONE) return BGP_RIBOUT_INCOMPLETE;
    clock_gettime(CLOCK_MONOTONIC, &start);
    // The CPU time of this thread does not grow while it waits for a CPU, unlike the elapsed time on a busy host.
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpu_start);
    if (bgp_ribout_generate_map(block) < 0) return BGP_RIBOUT_MAP_FAILED;
    if (bgp_ribout_generate_messages(block) < 0) return BGP_RIBOUT_MESSAGES_FAILED;
    clock_gettime(CLOCK_MONOTONIC, &end);
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpu_end);
    block->generation_time_ms = (end.tv_sec - start.tv_sec) * 1000.0 +
                                (end.tv_nsec - start.tv_nsec) / 1000000.0;
    block->generation_cpu_ms = (cpu_end.tv_sec - cpu_start.tv_sec) * 1000.0 +
                               (cpu_end.tv_nsec - cpu_start.tv_nsec) / 1000000.0;
    block->dirty = 0;
    return BGP_RIBOUT_GENERATED;
}

// Helper Functions

/*
 * Host-step sequences (next-hop, endpoint, IP, MAC, SID x N) advance by one
 * address; bytes_be_add() owns the arithmetic for every sequence kind.
 */
static void increment_ipv4(struct in_addr *addr, uint32_t increment) {
    (void)bytes_be_add((uint8_t *)&addr->s_addr, sizeof(addr->s_addr), increment, 0);
}

/*
 * Add increment to an IPv6 address.
 */
static void increment_ipv6(struct in6_addr *addr, uint32_t increment) {
    (void)bytes_be_add(addr->s6_addr, sizeof(addr->s6_addr), increment, 0);
}

/*
 * Add increment to a 48-bit MAC address.
 */
static void increment_mac(uint8_t mac[6], uint32_t increment) {
    (void)bytes_be_add(mac, 6, increment, 0);
}

// Generation Helper Functions

/*
 * Generate prefix string at given index
 */
void bgp_prefix_to_string(bgp_prefix_spec_t *spec, uint32_t index, char *output, size_t output_len) {
    char ip_str[INET6_ADDRSTRLEN];

    // Same block stepping as the generator: the index-th prefix block.
    if (spec->af == AF_INET) {
        struct in_addr addr = spec->base_addr.ipv4;

        (void)bgp_ribout_prefix_advance(AF_INET, &addr, spec->prefix_len, index);
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
        snprintf(output, output_len, "%s/%u", ip_str, spec->prefix_len);
    } else {
        struct in6_addr addr = spec->base_addr.ipv6;

        (void)bgp_ribout_prefix_advance(AF_INET6, &addr, spec->prefix_len, index);
        inet_ntop(AF_INET6, &addr, ip_str, sizeof(ip_str));
        snprintf(output, output_len, "%s/%u", ip_str, spec->prefix_len);
    }
}

/*
 * Generate next_hop string at given index (with wrapping)
 */
void bgp_next_hop_to_string(bgp_next_hop_spec_t *spec, uint32_t index, char *output, size_t output_len) {
    // Wrap index if necessary
    uint32_t wrapped_index = index % spec->count;

    if (spec->af == AF_INET) {
        struct in_addr addr = spec->base_addr.ipv4;
        increment_ipv4(&addr, wrapped_index);
        inet_ntop(AF_INET, &addr, output, (socklen_t)output_len);
    } else {
        struct in6_addr addr = spec->base_addr.ipv6;
        increment_ipv6(&addr, wrapped_index);
        inet_ntop(AF_INET6, &addr, output, (socklen_t)output_len);
    }
}

/*
 * Generate AS-path string
 */
void bgp_aspath_to_string(const bgp_aspath_segment_t *segments, uint32_t segment_count,
                          char *output, size_t output_len) {
    char  *ptr = output;
    size_t remaining = output_len;
    int    written;

    for (uint32_t i = 0; i < segment_count; i++) {
        if (i > 0 && remaining > 1) {
            *ptr++ = ' ';
            remaining--;
        }

        const bgp_aspath_segment_t *seg = &segments[i];

        switch (seg->type) {
            case ASPATH_SEQUENCE:
                for (uint32_t j = 0; j < seg->value_count; j++) {
                    if (j > 0 && remaining > 1) {
                        *ptr++ = ' ';
                        remaining--;
                    }
                    written = snprintf(ptr, remaining, "%u", seg->as_values[j]);
                    if (written > 0 && (size_t)written < remaining) {
                        ptr += written;
                        remaining -= (size_t)written;
                    }
                }
                break;

            case ASPATH_SET:
                if (remaining > 2) {
                    *ptr++ = '{';
                    remaining--;

                    for (uint32_t j = 0; j < seg->value_count; j++) {
                        if (j > 0 && remaining > 1) {
                            *ptr++ = ' ';
                            remaining--;
                        }
                        written = snprintf(ptr, remaining, "%u", seg->as_values[j]);
                        if (written > 0 && (size_t)written < remaining) {
                            ptr += written;
                            remaining -= (size_t)written;
                        }
                    }

                    if (remaining > 1) {
                        *ptr++ = '}';
                        remaining--;
                    }
                }
                break;

            case ASPATH_RANDOM:
                if (seg->rand_count == 1) {
                    written = snprintf(ptr, remaining, "rand(%u)", seg->rand_max);
                    if (written > 0 && (size_t)written < remaining) {
                        ptr += written;
                        remaining -= (size_t)written;
                    }
                } else {
                    written = snprintf(ptr, remaining, "[rand(%u) x %u]", seg->rand_max, seg->rand_count);
                    if (written > 0 && (size_t)written < remaining) {
                        ptr += written;
                        remaining -= (size_t)written;
                    }
                }
                break;
        }
    }

    if (remaining > 0) {
        *ptr = '\0';
    }
}

/*
 * Convert origin to string
 */
const char* bgp_origin_to_string(bgp_origin_t origin) {
    switch (origin) {
        case ORIGIN_IGP: return "igp";
        case ORIGIN_EGP: return "egp";
        case ORIGIN_INCOMPLETE: return "incomplete";
        default: return "incomplete";
    }
}

// Generator Functions (Iterator Pattern)

/*
 * FlowSpec checks: the block has a match, its longest NLRI encodes for the family (the FlowSpec library owns the
 * RFC 8955 / RFC 8956 rules), and the MP_REACH next hop follows RFC 8955 section 4: zero length, unless a
 * redirect-to-next-hop action (type 0x08) needs one.
 */
static int bgp_ribout_flowspec_validate(const bgp_ribout_config_t *block, bgp_ribout_family_t family) {
    int vpn = (family == BGP_RIBOUT_FAMILY_FLOWSPEC_VPN_IPV4 || family == BGP_RIBOUT_FAMILY_FLOWSPEC_VPN_IPV6);
    int af = (family == BGP_RIBOUT_FAMILY_FLOWSPEC_IPV4 || family == BGP_RIBOUT_FAMILY_FLOWSPEC_VPN_IPV4) ?
             AF_INET : AF_INET6;
    uint16_t                   afi = (af == AF_INET) ? AFI_IPV4 : AFI_IPV6;
    int                        prefixes_af = bgp_ribout_flowspec_af(block);
    uint64_t                   instances = bgp_ribout_flowspec_instances(block);
    int                        redirect_next_hop = 0;
    bgp_ribout_flowspec_nlri_t nlri;
    uint8_t                    buffer[FLOWSPEC_MAX_NLRI_ENTRY_LEN];

    for (uint32_t i = 0; block->flowspec && i < block->flowspec->actions.line_count; i++) {
        redirect_next_hop |= block->flowspec->actions.lines[i].redirect_next_hop;
    }

    if (vpn && block->rd_count == 0) {
        fprintf(stderr, "Error: rd is required for VPN FlowSpec ribouts\n");
        return -1;
    }
    if (prefixes_af != 0 && prefixes_af != af) {
        fprintf(stderr, "Error: FlowSpec prefix and src-prefix must match the ribout address-family\n");
        return -1;
    }
    if (instances == 0 || instances > UINT32_MAX) {
        fprintf(stderr, "Error: FlowSpec ribout makes too many NLRIs (max %u)\n", UINT32_MAX);
        return -1;
    }
    if (bgp_ribout_flowspec_materialize_longest(block, &nlri) < 0) {
        fprintf(stderr, "Error: a FlowSpec ribout needs prefix, src-prefix or a component\n");
        return -1;
    }
    if (bgp_encode_flowspec_nlri_entry(buffer, &nlri.rule, NULL, afi, 1, 0) < 0) {
        fprintf(stderr, "Error: the FlowSpec match is not valid for %s FlowSpec\n", (af == AF_INET) ? "IPv4" : "IPv6");
        return -1;
    }
    if (redirect_next_hop && block->next_hop_spec.count == 0) {
        fprintf(stderr, "Error: redirect-next-hop needs next-hop\n");
        return -1;
    }
    if (block->next_hop_spec.count > 0 && !redirect_next_hop) {
        fprintf(stderr, "Error: next-hop needs a redirect-next-hop action; "
                        "RFC 8955 section 4 sends FlowSpec with a zero-length next hop\n");
        return -1;
    }

    return 0;
}

/*
 * rotate-period: every rotating list has the period's length, or one value, so that all of them advance in step and
 * rotation step r picks entry r mod period of each (route target, RD, labels, next hop, ... of one VRF).
 */
static int bgp_ribout_check_rotate_period(const bgp_ribout_config_t *block, bgp_ribout_family_t family) {
    int type2 = bgp_ribout_family_is_evpn_type2(family);
    const struct {
        const char *name;
        uint32_t    count;
    } lists[] = {
        {"rt-set", block->rt_set_count},
        {"next-hop", block->next_hop_spec.count},
        {"soo", block->soo_count},
        {"encap", block->encap_count},
        {"router-mac", block->router_mac_count},
        {"color", (bgp_ribout_family_is_srpolicy(family) || block->color_set) ? 0 : block->color_count},
        {"label", (type2 || block->label_rotate) ? block->label_count : 0},
        {"label2", type2 ? block->label2_count : 0},
        {"esi", type2 ? block->esi_count : 0},
        {"rd rotate", block->rd_rotate ? block->rd_count : 0},
        {"ethernet-tag rotate", block->ethernet_tag_rotate ? block->ethernet_tag_count : 0},
        {"path-id rotate", block->path_id_rotate ? block->path_id_count : 0},
        {"distinguisher rotate", block->distinguisher_rotate ? block->distinguisher_count : 0},
        {"color rotate", (block->color_rotate && bgp_ribout_family_is_srpolicy(family)) ? block->color_count : 0},
        {"endpoint rotate", block->endpoint_rotate ? block->endpoint_spec.count : 0},
        {"community", (uint32_t)bgp_ribout_community_sets(block)},
        {"large-community", (uint32_t)bgp_ribout_large_community_sets(block)},
    };

    for (size_t i = 0; i < sizeof(lists) / sizeof(lists[0]); i++) {
        if (lists[i].count > 1 && lists[i].count != block->rotate_period) {
            fprintf(stderr, "Error: rotate-period %u: %s rotates %u values\n", block->rotate_period, lists[i].name,
                    lists[i].count);
            return -1;
        }
    }
    // A rotating FlowSpec component is a rotating list too: its values (a step's count, or each() alternatives).
    for (uint8_t type = FLOWSPEC_IP_PROTOCOL; block->flowspec && type <= FLOWSPEC_FLOW_LABEL; type++) {
        const bgp_ribout_flowspec_component_t *comp = &block->flowspec->components[type];
        uint32_t                               count = (comp->step_count > 1) ? comp->step_count : comp->alternative_count;

        if (comp->rotate && count > 1 && count != block->rotate_period) {
            fprintf(stderr, "Error: rotate-period %u: %s rotate rotates %u values\n", block->rotate_period,
                    bgp_ribout_flowspec_component_keyword(type), count);
            return -1;
        }
    }
    return 0;
}

/*
 * Check that a block can generate before any path is made: the family resolves, each family has its required tokens,
 * and no token is set that the family cannot encode. Prints the first problem and returns -1.
 */
static int bgp_ribout_generator_validate(const bgp_ribout_config_t *block) {
    bgp_ribout_family_t family = bgp_ribout_resolve_family(block);

    if (family == BGP_RIBOUT_FAMILY_NONE) {
        fprintf(stderr, "Error: Unable to resolve ribout address-family from configured tokens\n");
        return -1;
    }

    // Family inference can change after the color line was accepted, so validate the mode here too.
    if (block->color_set && (bgp_ribout_family_is_srpolicy(family) || block->color_rotate ||
                             block->color_count > MAX_EXT_COMMS_PER_ROUTE)) {
        fprintf(stderr, "Error: color set requires a non-SR-Policy family, no rotation, and at most %u communities\n",
                MAX_EXT_COMMS_PER_ROUTE);
        return -1;
    }

    if (block->next_hop_spec.has_link_local &&
        block->next_hop_spec.af != AF_INET6) {
        fprintf(stderr, "Error: link-local next-hop requires an IPv6 next-hop\n");
        return -1;
    }

    if ((block->encap_count > 0 || block->router_mac_count > 0) &&
        family != BGP_RIBOUT_FAMILY_EVPN_TYPE2 &&
        family != BGP_RIBOUT_FAMILY_EVPN_TYPE5_IPV4 &&
        family != BGP_RIBOUT_FAMILY_EVPN_TYPE5_IPV6) {
        fprintf(stderr, "Error: encap and router-mac are only valid on EVPN type 2 and type 5 ribouts\n");
        return -1;
    }

    if (block->rotate_period > 0 && bgp_ribout_check_rotate_period(block, family) < 0) {
        return -1;
    }

    // MPLS labels have 20 bits (RFC 3032); a 24-bit value fits only as a VNI.
    if (bgp_ribout_max_label(block) > 0xFFFFFU && !bgp_ribout_labels_are_vnis(block, family)) {
        fprintf(stderr, "Error: a label above 1048575 is valid only as a VNI: on an EVPN ribout whose every encap is "
                        "vxlan, nvgre, VXLAN-GPE (12) or Geneve (19)\n");
        return -1;
    }

    if (block->prefix_offset > 0 &&
        family != BGP_RIBOUT_FAMILY_FLOWSPEC_IPV6 && family != BGP_RIBOUT_FAMILY_FLOWSPEC_VPN_IPV6) {
        fprintf(stderr, "Error: a prefix offset is valid only for an IPv6 FlowSpec destination\n");
        return -1;
    }

    if (bgp_ribout_family_is_template(family)) return bgp_ribout_template_validate(block);
    if (block->family_attr_type || *block->l2_info_text) {
        fprintf(stderr, "Error: family attributes require a compatible NLRI template\n");
        return -1;
    }
    if (bgp_ribout_family_is_flowspec(family)) {
        return bgp_ribout_flowspec_validate(block, family);
    }

    if (bgp_ribout_family_is_srpolicy(family)) {
        if (block->distinguisher_count == 0) {
            fprintf(stderr, "Error: distinguisher is required for SR Policy ribouts\n");
            return -1;
        }
        if (block->color_count == 0) {
            fprintf(stderr, "Error: color is required for SR Policy ribouts\n");
            return -1;
        }
        for (uint32_t i = 0; i < (block->colors_step ? 1 : block->color_count); i++) {
            if (bgp_ribout_color_co_at(block, i) != BGP_COLOR_CO_SPECIFIC) {
                fprintf(stderr, "Error: co is valid only for a Color community, not for an SR Policy color\n");
                return -1;
            }
        }
        if (block->endpoint_spec.count == 0) {
            fprintf(stderr, "Error: endpoint is required for SR Policy ribouts\n");
            return -1;
        }
        if (block->segment_list_count == 0) {
            fprintf(stderr, "Error: segment-list is required for SR Policy ribouts\n");
            return -1;
        }
        if (block->rt_count == 0 && block->rt_set_count == 0) {
            fprintf(stderr, "Error: SR Policy ribouts require at least one route-target\n");
            return -1;
        }
        /*
         * RFC 9830 allows an alternate NO_ADVERTISE-only distribution path,
         * but the initial ribout implementation deliberately starts with the
         * IPv4-address-specific RT path because it scales naturally through
         * the existing RT / RT-set knobs.
         */
        if (!bgp_ribout_rt_surface_is_ipv4_only(block)) {
            fprintf(stderr, "Error: SR Policy ribouts currently require IPv4-address route-targets\n");
            return -1;
        }
        return 0;
    }

    if (bgp_ribout_family_is_evpn_type2(family)) {
        if (block->rd_count == 0) {
            fprintf(stderr, "Error: rd is required for EVPN type 2 ribouts\n");
            return -1;
        }
        if (block->label_count == 0) {
            fprintf(stderr, "Error: label is required for EVPN type 2 ribouts\n");
            return -1;
        }
        if (block->mac_spec.count == 0) {
            fprintf(stderr, "Error: mac is required for EVPN type 2 ribouts\n");
            return -1;
        }
        if (block->prefix_spec.count > 0 || block->gateway_ip_spec.count > 0) {
            fprintf(stderr, "Error: EVPN type 2 ribouts must not configure prefix or gateway-ip\n");
            return -1;
        }
        if (block->next_hop_spec.has_link_local) {
            fprintf(stderr, "Error: EVPN ribouts do not support link-local next-hop companions in strict mode\n");
            return -1;
        }
        return 0;
    }

    if (block->prefix_spec.count == 0) {
        fprintf(stderr, "Error: No prefixes defined in ribout\n");
        return -1;
    }

    if (block->rd_count == 0 &&
        (block->rt_count > 0 || block->rt_set_count > 0 ||
         block->soo_count > 0 || block->ethernet_tag_count > 0 ||
         block->gateway_ip_spec.count > 0 || block->esi_count > 0)) {
        fprintf(stderr, "Error: rd is required when VPN/EVPN-specific tokens are configured\n");
        return -1;
    }

    if ((family == BGP_RIBOUT_FAMILY_VPNV4 ||
         family == BGP_RIBOUT_FAMILY_VPNV6 ||
         family == BGP_RIBOUT_FAMILY_EVPN_TYPE5_IPV4 ||
         family == BGP_RIBOUT_FAMILY_EVPN_TYPE5_IPV6) &&
        block->label_count == 0) {
        fprintf(stderr, "Error: label is required for VPN and EVPN ribout families\n");
        return -1;
    }

    if (family == BGP_RIBOUT_FAMILY_EVPN_TYPE5_IPV4 ||
        family == BGP_RIBOUT_FAMILY_EVPN_TYPE5_IPV6) {
        if (block->next_hop_spec.has_link_local) {
            fprintf(stderr, "Error: EVPN ribouts do not support link-local next-hop companions in strict mode\n");
            return -1;
        }
        if (block->gateway_ip_spec.count > 0 &&
            block->gateway_ip_spec.af != block->prefix_spec.af) {
            fprintf(stderr, "Error: gateway-ip address family must match prefix address family\n");
            return -1;
        }
        if (block->gateway_ip_spec.count > 0 && block->esi_count > 0) {
            fprintf(stderr, "Error: EVPN type 5 ribouts must not configure both gateway-ip and esi\n");
            return -1;
        }
        if (block->gateway_ip_spec.count == 0 && block->esi_count == 0 && block->router_mac_count == 0) {
            for (uint32_t i = 0; i < block->label_count; i++) {
                if (bgp_ribout_labels_at(block, i) == 0) {
                    fprintf(stderr, "Error: EVPN type 5 label 0 requires an Overlay Index\n");
                    return -1;
                }
            }
        }
    }

    return 0;
}

static int bgp_ribout_append_ext_comm(bgp_gen_path_t *path, uint16_t *offset, const bgp_ext_comm_t *ext_comm) {
    if (!path || !offset || !ext_comm) {
        return -1;
    }

    if (((size_t)*offset + 8U) > sizeof(path->ext_comm_data)) {
        return -1;
    }

    memcpy(path->ext_comm_data + *offset, ext_comm->bytes, 8);
    *offset += 8;
    return 0;
}

/*
 * Fill the extended communities of one generated path: the RTs or the RT set in rotation, SoO, encap, router-MAC and
 * Color (except in SR Policy, where color is the NLRI), then the FlowSpec block lines and rule lines (8-octet
 * communities to ext_comm_data, IPv6-address ones to ipv6_ext_comm_data). Returns -1 when they do not fit.
 */
static int bgp_ribout_fill_ext_comms(const bgp_ribout_config_t *block,
                                     const bgp_ribout_gen_t *gen,
                                     bgp_gen_path_t *path) {
    uint16_t offset = 0;

    path->ext_comm_len = 0;

    if (block->rt_set_count > 0) {
        bgp_rt_set_spec_t set = bgp_ribout_rt_set_at(block, gen->current_rt_set_idx % block->rt_set_count);

        for (uint32_t i = 0; i < set.count; i++) {
            if (bgp_ribout_append_ext_comm(path, &offset, &set.values[i]) < 0) {
                return -1;
            }
        }
    } else {
        for (uint32_t i = 0; i < block->rt_count; i++) {
            if (bgp_ribout_append_ext_comm(path, &offset, &block->rt_values[i]) < 0) {
                return -1;
            }
        }
    }

    if (*block->l2_info_text && bgp_ribout_append_ext_comm(path, &offset, &block->l2_info) < 0) return -1;

    if (block->soo_count > 0) {
        const bgp_ext_comm_t *soo =
            &block->soo_values[gen->current_soo_idx % block->soo_count];

        if (bgp_ribout_append_ext_comm(path, &offset, soo) < 0) {
            return -1;
        }
    }

    /*
     * EVPN attr-side extended communities are appended after the generic
     * RT/RT-set/SoO surface so the generated path stream, grouped-map key,
     * and final attribute rebuild all see one stable ext-community tuple.
     */
    if (block->encap_count > 0) {
        const bgp_ext_comm_t *encap =
            &block->encap_values[
                gen->current_encap_idx % block->encap_count];

        if (bgp_ribout_append_ext_comm(path, &offset, encap) < 0) {
            return -1;
        }
    }

    if (block->router_mac_count > 0) {
        const bgp_ext_comm_t *router_mac =
            &block->router_mac_values[
                gen->current_router_mac_idx % block->router_mac_count];

        if (bgp_ribout_append_ext_comm(path, &offset, router_mac) < 0) {
            return -1;
        }
    }

    if (block->color_count > 0 && !bgp_ribout_family_is_srpolicy(gen->family)) {
        uint32_t count = block->color_set ? block->color_count : 1;
        for (uint32_t n = 0; n < count; n++) {
            uint32_t       i = block->color_set ? n : gen->current_color_idx % block->color_count;
            bgp_ext_comm_t color;

            bgp_ext_comm_color_write(color.bytes, bgp_ribout_colors_at(block, i), BGP_COLOR_CO_FLAGS(bgp_ribout_color_co_at(block, i)));
            if (bgp_ribout_append_ext_comm(path, &offset, &color) < 0) return -1;
        }
    }

    if (path->has_flowspec && block->flowspec) {
        uint16_t ipv6_offset = 0;

        // Each action line adds the value of this path: a line with several values rotates them.
        for (uint32_t i = 0; i < block->flowspec->actions.line_count; i++) {
            const bgp_ribout_flowspec_line_t *line = &block->flowspec->actions.lines[i];
            const uint8_t *value = bgp_ribout_flowspec_action_value(line,
                                                                    bgp_ribout_rotation(block, gen->paths_generated));

            if (line->value_len == 8) {
                bgp_ext_comm_t ext_comm;

                memcpy(ext_comm.bytes, value, 8);
                if (bgp_ribout_append_ext_comm(path, &offset, &ext_comm) < 0) {
                    return -1;
                }
            } else {
                if ((size_t)ipv6_offset + 20U > sizeof(path->ipv6_ext_comm_data)) {
                    return -1;
                }
                memcpy(path->ipv6_ext_comm_data + ipv6_offset, value, 20);
                ipv6_offset += 20;
            }
        }
        path->ipv6_ext_comm_len = ipv6_offset;
    }

    path->ext_comm_len = offset;
    return 0;
}

/*
 * Zero bytes in pieces of at most 64 octets. GCC expands a larger constant memset to "rep stos", which has a slow
 * start and delays the loads of those bytes that follow; pieces of 64 octets or less become plain vector stores.
 * This runs once per generated path.
 */
static inline void bgp_ribout_zero_pieces(void *dst, size_t bytes) {
    uint8_t *p = dst;

    for (; bytes >= 64; p += 64, bytes -= 64) {
        memset(p, 0, 64);
    }
    memset(p, 0, bytes);
}

/*
 * Clear the per-path fields before the generator fills them. The large AS-path and community arrays keep their bytes;
 * only their lengths go to 0.
 */
static void bgp_ribout_generated_path_reset(
    bgp_gen_path_t *path,
    bgp_ribout_family_t family,
    uint8_t prefix_af,
    uint8_t prefix_len) {
    /*
     * Keep the large embedded AS-path / ext-community backing storage intact.
     * The generator rewrites those arrays under explicit count/length fields,
     * so clearing the full struct on every path just burns cycles on data that
     * will never be read past the active counts.
     */
    bgp_ribout_zero_pieces(path, offsetof(bgp_gen_path_t, aspath_segments));
    path->aspath_segments = NULL;  /* First field after the zeroed range; bgp_ribout_generator_next() sets it */
    path->aspath_segment_count = 0;
    path->ext_comm_len = 0;
    path->ipv6_ext_comm_len = 0;
    path->community_len = 0;
    path->large_community_len = 0;
    path->med = 0;
    path->has_med = 0;
    path->family = family;
    path->local_pref = 100;
    path->origin = BGP_ORIGIN_IGP;

    if (bgp_ribout_family_is_flowspec(family)) {
        path->prefix_af = bgp_ribout_family_info(family)->prefix_af;
    } else if (!bgp_ribout_family_is_srpolicy(family) && !bgp_ribout_family_is_evpn_type2(family)) {
        path->prefix_len = prefix_len;
        path->prefix_af = prefix_af;
    }
}

/*
 * Number of paths the generator emits for family (docs/bgp-ribout.md, "Total Path Count").
 */
static int bgp_ribout_generator_total_paths(const bgp_ribout_config_t *block, bgp_ribout_family_t family,
                                           uint64_t *total) {
    uint64_t dimensions[7] = {1, 1, 1, 1, 1, 1, 1};

    if (bgp_ribout_family_is_template(family)) {
        dimensions[0] = block->nlri_template.count;
        dimensions[1] = bgp_ribout_path_id_dimension(block);
    } else if (bgp_ribout_family_is_flowspec(family)) {
        dimensions[0] = bgp_ribout_flowspec_rules(block);
        dimensions[1] = bgp_ribout_rd_dimension(block);
        dimensions[2] = bgp_ribout_path_id_dimension(block);
    } else if (bgp_ribout_family_is_srpolicy(family)) {
        dimensions[0] = (block->distinguisher_count && block->color_count && block->endpoint_spec.count) ?
                            bgp_ribout_distinguisher_dimension(block) : 0;
        dimensions[1] = bgp_ribout_color_dimension(block);
        dimensions[2] = bgp_ribout_endpoint_dimension(block);
        dimensions[3] = bgp_ribout_path_id_dimension(block);
    } else if (bgp_ribout_family_is_evpn_type2(family)) {
        dimensions[0] = (block->rd_count && block->label_count && block->mac_spec.count) ?
                            bgp_ribout_rd_dimension(block) : 0;
        dimensions[1] = bgp_ribout_tag_dimension(block);
        dimensions[2] = block->mac_spec.count;
        dimensions[3] = bgp_ribout_type2_ip_dimension(block);
        dimensions[4] = bgp_ribout_path_id_dimension(block);
    } else {
        dimensions[0] = block->prefix_spec.count;
        dimensions[1] = bgp_ribout_rd_dimension(block);
        dimensions[2] = bgp_ribout_tag_dimension(block);
        dimensions[3] = bgp_ribout_effective_count(block->gateway_ip_spec.count);
        dimensions[4] = bgp_ribout_effective_count(block->esi_count);
        dimensions[5] = bgp_ribout_effective_count(block->label_rotate ? 0 : block->label_count);
        dimensions[6] = bgp_ribout_path_id_dimension(block);
    }

    *total = 1;
    for (size_t i = 0; i < sizeof(dimensions) / sizeof(*dimensions); i++) {
        if (dimensions[i] && *total > UINT64_MAX / dimensions[i]) {
            *total = 0;
            return -1;
        }
        *total *= dimensions[i];
    }
    return 0;
}

/*
 * Number of paths a block generates. The CLI and the benchmarks use this one formula.
 */
uint64_t bgp_ribout_total_paths(const bgp_ribout_config_t *block) {
    uint64_t total;
    if (!block) {
        return 0;
    }

    return bgp_ribout_generator_total_paths(block, bgp_ribout_resolve_family(block), &total) == 0 ? total : 0;
}

/*
 * Initialize generator
 */
int bgp_ribout_generator_init(bgp_ribout_gen_t *gen, bgp_ribout_config_t *block) {
    bgp_ribout_family_t family;

    if (!gen || !block) {
        return -1;
    }

    if (bgp_ribout_generator_validate(block) < 0) {
        return -1;
    }

    memset(gen, 0, sizeof(bgp_ribout_gen_t));
    gen->ribout_config = block;
    family = bgp_ribout_resolve_family(block);
    gen->family = family;
    gen->paths_generated = 0;
    if (bgp_ribout_generator_total_paths(block, family, &gen->total_paths) < 0) {
        fprintf(stderr, "Error: Ribout path count exceeds the 64-bit range\n");
        return -1;
    }
    gen->random_state = ribout_seed_state(ribout_initial_seed(block->name));
    gen->aspath_has_random = bgp_ribout_aspath_has_random(block->aspath_segments, block->aspath_segment_count);
    gen->community_sets = bgp_ribout_community_sets(block);
    gen->large_community_sets = bgp_ribout_large_community_sets(block);

    gen->initialized = 1;

    return 0;
}

/*
 * Check if generator has more paths
 */
int bgp_ribout_generator_has_next(bgp_ribout_gen_t *gen) {
    if (!gen || !gen->initialized) {
        return 0;
    }

    return gen->paths_generated < gen->total_paths;
}

/*
 * The configured token alone is not an Overlay Index: zero ESI, gateway and
 * Router's MAC values mean "absent". Check materialized values so rotations
 * cannot emit a label-zero route without an index (RFC 9136 section 3.1).
 */
static int bgp_ribout_evpn5_has_overlay_index(const bgp_gen_path_t *path) {
    static const uint8_t zero[16] = {0};

    if (path->has_esi && memcmp(&path->esi, zero, sizeof(path->esi)) != 0) {
        return 1;
    }
    if (path->has_gateway_ip) {
        size_t len = path->gateway_ip_af == AF_INET ? 4 : 16;

        if (memcmp(&path->gateway_ip_addr, zero, len) != 0) {
            return 1;
        }
    }
    for (size_t i = 0; i + 8 <= path->ext_comm_len; i += 8) {
        if (path->ext_comm_data[i] == 0x06 && path->ext_comm_data[i + 1] == 0x03 &&
            memcmp(path->ext_comm_data + i + 2, zero, 6) != 0) {
            return 1;
        }
    }
    return 0;
}

/*
 * rotate-every, before each path: at the first path of a block of rotate_every paths, save the attribute rotation
 * state (and the random state); for the other paths of the block, start from the saved state again. So every path
 * of the block gets the same attributes, and the block's last path leaves the state one step on for the next block.
 * NLRI counters are not touched: the color list is an NLRI key of SR Policy, and labels and ESIs are keys outside
 * EVPN Type 2.
 */
static void bgp_ribout_rotation_block(bgp_ribout_gen_t *gen, const bgp_ribout_config_t *block,
                                      bgp_ribout_family_t family) {
    int                          keyed_color = bgp_ribout_family_is_srpolicy(family);
    int                          type2 = bgp_ribout_family_is_evpn_type2(family);
    bgp_ribout_rotation_state_t *saved = &gen->rotation_saved;

    if (gen->paths_generated % block->rotate_every == 0) {
        saved->next_hop = gen->current_next_hop_idx;
        saved->rt_set = gen->current_rt_set_idx;
        saved->soo = gen->current_soo_idx;
        saved->encap = gen->current_encap_idx;
        saved->router_mac = gen->current_router_mac_idx;
        saved->color = gen->current_color_idx;
        saved->localpref = gen->current_localpref_idx;
        saved->med = gen->current_med_idx;
        saved->enlp = gen->current_enlp_idx;
        saved->priority = gen->current_priority_idx;
        saved->preference = gen->current_preference_idx;
        saved->binding_sid = gen->current_binding_sid_idx;
        saved->label = gen->current_label_idx;
        saved->label2 = gen->current_label2_idx;
        saved->esi = gen->current_esi_idx;
        saved->random_state = gen->random_state;
        return;
    }
    gen->current_next_hop_idx = saved->next_hop;
    gen->current_rt_set_idx = saved->rt_set;
    gen->current_soo_idx = saved->soo;
    gen->current_encap_idx = saved->encap;
    gen->current_router_mac_idx = saved->router_mac;
    if (!keyed_color) {
        gen->current_color_idx = saved->color;
    }
    gen->current_localpref_idx = saved->localpref;
    gen->current_med_idx = saved->med;
    gen->current_enlp_idx = saved->enlp;
    gen->current_priority_idx = saved->priority;
    gen->current_preference_idx = saved->preference;
    gen->current_binding_sid_idx = saved->binding_sid;
    if (type2) {
        gen->current_label_idx = saved->label;
        gen->current_label2_idx = saved->label2;
        gen->current_esi_idx = saved->esi;
    }
    gen->random_state = saved->random_state;
}

/*
 * Generate the next path of the ribout into *path and step the generator.
 *
 * Returns 0, or -1 when:
 *   - the generator is not initialized, or no path is left
 *   - the extended communities do not fit
 *   - an EVPN Type 5 path with label 0 has no overlay index (an error is printed)
 *
 * The path is built in this order:
 *   - rotate-every: save or restore the attribute rotation state (bgp_ribout_rotation_block())
 *   - rotation step: bgp_ribout_rotation() gives the step of this path. Every rotating list indexes it, so
 *     endpoint, distinguisher, color, path-id, rd, label, ethernet-tag, rt-set (bgp_ribout_fill_ext_comms())
 *     and the community sets move together
 *   - NLRI keys, from the per-dimension counters (current_*_idx) or from the rotation step for a rotating list:
 *     the template instance, the FlowSpec instance, the SR Policy endpoint, color and distinguisher, the EVPN
 *     Type 2 MAC and IP, or the prefix for the other families
 *   - attributes: path-id, RD, labels and the VNI flag, Ethernet tag, gateway IP, ESI, next hop (a per-family
 *     default when none is configured, zero-length for FlowSpec), extended communities, community sets, AS path
 *     (a random segment gets a per-path copy), local-pref, MED, origin
 *   - SR Policy only: enlp, priority, preference and the binding SID
 *
 * Then the counters advance:
 *   - attribute counters, on every path: next-hop, rt-set, soo, encap, router-mac, color (unless a color-set or
 *     SR Policy keys it), enlp, priority, preference and binding SID (unless a range or randrange spec supplies
 *     them), and the EVPN Type 2 label, label2 and ESI
 *   - NLRI dimensions, like an odometer with path-id innermost, then per family:
 *       FlowSpec:     rd, instance
 *       SR Policy:    endpoint, color, distinguisher
 *       EVPN Type 2:  IP, MAC, Ethernet tag, RD
 *       others:       label, ESI, gateway IP, Ethernet tag, RD, prefix
 *     A rotating list is a dimension of 1, so its counter stays 0
 *   - paths_generated, which counts the path
 */
int bgp_ribout_generator_next(bgp_ribout_gen_t *gen, bgp_gen_path_t *path) {
    if (!gen || !gen->initialized || !path) {
        return -1;
    }

    if (!bgp_ribout_generator_has_next(gen)) {
        return -1; /* No more paths */
    }

    bgp_ribout_config_t *block = gen->ribout_config;
    bgp_ribout_family_t  family = gen->family;

    if (block->rotate_every > 1) {
        bgp_ribout_rotation_block(gen, block, family);
    }
    bgp_ribout_generated_path_reset(path, family, block->prefix_spec.af, block->prefix_spec.prefix_len);

    // Rotating key lists take the value of this rotation step, in step with rt-set, rd rotate and the others.
    uint64_t rotation = bgp_ribout_rotation(block, gen->paths_generated);

    if (bgp_ribout_family_is_template(family)) {
        path->template_instance = gen->paths_generated / bgp_ribout_path_id_dimension(block);
    } else if (bgp_ribout_family_is_flowspec(family)) {
        path->has_flowspec = 1;
        path->flowspec_instance = bgp_ribout_flowspec_rule_instance(block, gen->current_flowspec_instance, rotation);
    } else if (bgp_ribout_family_is_srpolicy(family)) {
        uint32_t endpoint_idx = (uint32_t)((block->endpoint_rotate ? rotation : gen->current_endpoint_idx) %
                                           block->endpoint_spec.count);

        path->distinguisher = bgp_ribout_distinguishers_at(block, block->distinguisher_rotate ?
                                                    rotation % block->distinguisher_count :
                                                    gen->current_distinguisher_idx);
        path->color = bgp_ribout_colors_at(block, block->color_rotate ? rotation % block->color_count : gen->current_color_idx);
        path->endpoint_af = (uint8_t)block->endpoint_spec.af;
        path->has_endpoint = 1;

        if (block->endpoint_spec.af == AF_INET) {
            path->endpoint_addr.ipv4 = block->endpoint_spec.base_addr.ipv4;
            increment_ipv4(&path->endpoint_addr.ipv4, endpoint_idx);
        } else {
            path->endpoint_addr.ipv6 = block->endpoint_spec.base_addr.ipv6;
            increment_ipv6(&path->endpoint_addr.ipv6, endpoint_idx);
        }
    } else if (bgp_ribout_family_is_evpn_type2(family)) {
        uint32_t mac_idx = gen->current_mac_idx;

        memcpy(path->mac_addr, block->mac_spec.base_addr, sizeof(path->mac_addr));
        increment_mac(path->mac_addr, mac_idx);
        path->has_mac = 1;

        if (block->ip_spec.count > 0) {
            /*
             * The IPs of the first family, then of the second (dual-stack). With ip rotate MAC number i (counted
             * over the RD, Ethernet tag and MAC tuples; a rotating RD or tag list counts once) goes with IP i of the
             * family (mod its IP count).
             */
            uint32_t                   first = bgp_ribout_type2_ip_width(block, 0);
            int                        slot = gen->current_ip_idx >= first;
            const bgp_next_hop_spec_t *spec = slot ? &block->ip2_spec : &block->ip_spec;
            uint64_t mac_number = ((uint64_t)gen->current_rd_idx * bgp_ribout_tag_dimension(block) +
                                   gen->current_ethernet_tag_idx) * block->mac_spec.count + mac_idx;
            uint32_t ip_idx = (uint32_t)(((slot ? block->ip2_rotate : block->ip_rotate) ?
                                          mac_number : gen->current_ip_idx - (slot ? first : 0)) % spec->count);

            path->ip_af = (uint8_t)spec->af;
            path->has_ip = 1;
            if (spec->af == AF_INET) {
                path->ip_addr.ipv4 = spec->base_addr.ipv4;
                increment_ipv4(&path->ip_addr.ipv4, ip_idx);
            } else {
                path->ip_addr.ipv6 = spec->base_addr.ipv6;
                increment_ipv6(&path->ip_addr.ipv6, ip_idx);
            }
        }
    } else {
        /*
         * Generate binary prefix: one whole prefix block per index, so every
         * generated prefix is a distinct route on the wire. The parser
         * checked that the last block fits in the address space.
         */
        if (block->prefix_spec.af == AF_INET) {
            path->prefix_addr.ipv4 = block->prefix_spec.base_addr.ipv4;
        } else {
            path->prefix_addr.ipv6 = block->prefix_spec.base_addr.ipv6;
        }
        (void)bgp_ribout_prefix_advance(block->prefix_spec.af, &path->prefix_addr,
                                        block->prefix_spec.prefix_len, gen->current_prefix_idx);
    }

    // Get current path-id (default to 0 if not configured)
    if (block->path_id_count > 0) {
        path->path_id = bgp_ribout_path_ids_at(block, block->path_id_rotate ? rotation % block->path_id_count :
                                        gen->current_path_id_idx);
    } else {
        path->path_id = 0;
    }

    if (!bgp_ribout_family_is_srpolicy(family) && block->rd_count > 0) {
        // rd rotate: one RD per rotation step, in step with rt-set and label rotate.
        path->rd = bgp_ribout_rds_at(block, block->rd_rotate ? rotation % block->rd_count : gen->current_rd_idx);
        path->has_rd = 1;
    }

    // Get current label (default to unlabeled if not configured)
    if (!bgp_ribout_family_is_srpolicy(family) && block->label_count > 0) {
        if (bgp_ribout_family_is_evpn_type2(family)) {
            path->label = bgp_ribout_labels_at(block, gen->current_label_idx % block->label_count);
        } else if (block->label_rotate) {
            // One label per rotation step, in step with rt-set and the other rotations.
            path->label = bgp_ribout_labels_at(block, bgp_ribout_rotation(block, gen->paths_generated) % block->label_count);
        } else {
            path->label = bgp_ribout_labels_at(block, gen->current_label_idx);
        }
        path->has_label = 1;
    } else {
        path->label = 0;
        path->has_label = 0;
    }

    if (bgp_ribout_family_is_evpn_type2(family) &&
        block->label2_count > 0) {
        path->label2 = bgp_ribout_label2s_at(block, gen->current_label2_idx % block->label2_count);
        path->has_label2 = 1;
    }

    // With a VXLAN-like encapsulation the EVPN labels carry the VNI (RFC 8365). The encap rotates with the path.
    if (bgp_ribout_family_is_evpn(family) && block->encap_count > 0) {
        path->label_vni = (uint8_t)bgp_ribout_encap_carries_vni(
            &block->encap_values[gen->current_encap_idx % block->encap_count]);
    }

    if (!bgp_ribout_family_is_srpolicy(family) &&
        block->ethernet_tag_count > 0) {
        path->ethernet_tag_id = bgp_ribout_ethernet_tags_at(block, block->ethernet_tag_rotate ?
                                                     rotation % block->ethernet_tag_count :
                                                     gen->current_ethernet_tag_idx);
        path->has_ethernet_tag = 1;
    } else if (family == BGP_RIBOUT_FAMILY_EVPN_TYPE5_IPV4 ||
               family == BGP_RIBOUT_FAMILY_EVPN_TYPE5_IPV6 ||
               family == BGP_RIBOUT_FAMILY_EVPN_TYPE2) {
        path->ethernet_tag_id = 0;
    }

    if (!bgp_ribout_family_is_srpolicy(family) &&
        block->gateway_ip_spec.count > 0) {
        uint32_t gw_idx =
            gen->current_gateway_ip_idx % block->gateway_ip_spec.count;

        path->gateway_ip_af = (uint8_t)block->gateway_ip_spec.af;
        path->has_gateway_ip = 1;
        if (block->gateway_ip_spec.af == AF_INET) {
            path->gateway_ip_addr.ipv4 = block->gateway_ip_spec.base_addr.ipv4;
            increment_ipv4(&path->gateway_ip_addr.ipv4, gw_idx);
        } else {
            path->gateway_ip_addr.ipv6 = block->gateway_ip_spec.base_addr.ipv6;
            increment_ipv6(&path->gateway_ip_addr.ipv6, gw_idx);
        }
    }

    if (!bgp_ribout_family_is_srpolicy(family) && block->esi_count > 0) {
        if (bgp_ribout_family_is_evpn_type2(family)) {
            path->esi = block->esis[gen->current_esi_idx %
                                    block->esi_count];
        } else {
            path->esi = block->esis[gen->current_esi_idx];
        }
        path->has_esi = 1;
    }

    // Generate binary next_hop (default to 0.0.0.0 if not configured)
    if (block->next_hop_spec.count > 0) {
        path->next_hop_af = block->next_hop_spec.af;
        uint32_t nh_idx = gen->current_next_hop_idx % block->next_hop_spec.count;
        if (block->next_hop_spec.af == AF_INET) {
            path->next_hop_addr.ipv4 = block->next_hop_spec.base_addr.ipv4;
            increment_ipv4(&path->next_hop_addr.ipv4, nh_idx);
        } else {
            path->next_hop_addr.ipv6 = block->next_hop_spec.base_addr.ipv6;
            increment_ipv6(&path->next_hop_addr.ipv6, nh_idx);
            path->next_hop_has_link_local = block->next_hop_spec.has_link_local;
            if (block->next_hop_spec.has_link_local) {
                path->next_hop_link_local = block->next_hop_spec.link_local;
            }
        }
    } else {
        /*
         * Match the generated path family when no explicit next-hop is
         * configured so preview, grouping, and UPDATE generation stay
         * consistent for both IPv4 and IPv6 ribouts.
         */
        if (bgp_ribout_family_is_template(family) || bgp_ribout_family_is_srpolicy(family) ||
            bgp_ribout_family_is_evpn_type2(family)) {
            /*
             * SR Policy treats next-hop AF independently from NLRI AFI.
             * EVPN Type 2 also has an AF-independent next-hop. Default both
             * families to the strict encoder's 4-octet all-zero next hop when
             * the ribout does not configure one explicitly.
             */
            path->next_hop_af = AF_INET;
            path->next_hop_addr.ipv4.s_addr = 0;
        } else {
            path->next_hop_af = path->prefix_af;
            if (path->prefix_af == AF_INET) {
                path->next_hop_addr.ipv4.s_addr = 0;
            } else {
                memset(&path->next_hop_addr.ipv6, 0, sizeof(path->next_hop_addr.ipv6));
            }
        }
        path->next_hop_has_link_local = 0;
    }

    if (bgp_ribout_family_is_flowspec(family)) {
        if (block->next_hop_spec.count == 0) {
            // RFC 8955 section 4: zero-length next hop.
            path->next_hop_af = 0;
            memset(&path->next_hop_addr, 0, sizeof(path->next_hop_addr));
        }
    }

    if (bgp_ribout_fill_ext_comms(block, gen, path) < 0) {
        return -1;
    }
    // The community and large-community sets: one each per rotation step, in step with rt-set and rd rotate.
    if (gen->community_sets > 0) {
        path->community_len = bgp_ribout_community_set_encode(
            block, bgp_ribout_rotation(block, gen->paths_generated) % gen->community_sets, path->community_data);
    }
    if (gen->large_community_sets > 0) {
        path->large_community_len = bgp_ribout_large_community_set_encode(
            block, bgp_ribout_rotation(block, gen->paths_generated) % gen->large_community_sets,
            path->large_community_data);
    }
    if ((family == BGP_RIBOUT_FAMILY_EVPN_TYPE5_IPV4 || family == BGP_RIBOUT_FAMILY_EVPN_TYPE5_IPV6) &&
        path->label == 0 && !bgp_ribout_evpn5_has_overlay_index(path)) {
        fprintf(stderr, "Error: EVPN type 5 label 0 requires a nonzero Overlay Index\n");
        return -1;
    }

    /*
     * AS-path: the block's segments. Only a random segment needs a per-path copy (each segment is 416 octets, so
     * copying them for every path costs more than all other per-path fields). The map stores the AS path in its own
     * compact form when it adds the path, so the pointer only has to stay valid until the next path.
     */
    path->aspath_segments = block->aspath_segments;
    path->aspath_segment_count = block->aspath_segment_count;
    if (gen->aspath_has_random) {
        memcpy(gen->aspath_scratch, block->aspath_segments, block->aspath_segment_count * sizeof(bgp_aspath_segment_t));
        for (uint32_t i = 0; i < block->aspath_segment_count; i++) {
            bgp_aspath_segment_t *seg = &gen->aspath_scratch[i];

            if (seg->type == ASPATH_RANDOM) {
                seg->type = ASPATH_SEQUENCE;
                seg->value_count = seg->rand_count;
                for (uint32_t j = 0; j < seg->value_count; j++) {
                    seg->as_values[j] =
                        ribout_random_bounded(gen, seg->rand_max);
                }
            }
        }
        path->aspath_segments = gen->aspath_scratch;
    }

    // Generate local preference (default to 100 if not configured).
    path->local_pref = ribout_u32_val(&block->localpref_spec, gen, &gen->current_localpref_idx);

    if (block->med_spec.enabled) {
        path->has_med = 1;
        path->med = ribout_u32_opt_val(&block->med_spec, gen, &gen->current_med_idx);
    }

    // Set origin
    path->origin = block->origin;

    if (bgp_ribout_family_is_srpolicy(family)) {
        if (block->enlp_spec.enabled) {
            path->enlp = (uint8_t)ribout_u32_opt_val(&block->enlp_spec, gen, &gen->current_enlp_idx);
            path->has_enlp = 1;
        } else if (block->enlp_count > 0) {
            path->enlp = (uint8_t)bgp_ribout_enlps_at(block, gen->current_enlp_idx % block->enlp_count);
            path->has_enlp = 1;
        }

        if (block->priority_spec.enabled) {
            path->priority = (uint8_t)ribout_u32_opt_val(&block->priority_spec, gen, &gen->current_priority_idx);
            path->has_priority = 1;
        } else if (block->priority_count > 0) {
            path->priority =
                (uint8_t)bgp_ribout_priorities_at(block, gen->current_priority_idx % block->priority_count);
            path->has_priority = 1;
        }

        if (block->preference_spec.enabled) {
            path->preference = ribout_u32_opt_val(&block->preference_spec, gen, &gen->current_preference_idx);
            path->has_preference = 1;
        } else if (block->preference_count > 0) {
            path->preference =
                bgp_ribout_preferences_at(block, gen->current_preference_idx % block->preference_count);
            path->has_preference = 1;
        } else {
            path->preference = 100;
            path->has_preference = 0;
        }

        path->binding_sid.type = SRPOLICY_BINDING_SID_NONE;
        path->binding_sid.flags = 0;
        if (block->binding_sid_kind == BGP_RIBOUT_SR_BINDING_SID_SRV6 &&
            block->binding_sid_srv6_spec.count > 0) {
            uint32_t bsid_idx =
                gen->current_binding_sid_idx % block->binding_sid_srv6_spec.count;
            struct in6_addr sid_addr;

            path->binding_sid.type = SRPOLICY_BINDING_SID_SRV6;
            path->binding_sid.mpls_label = 0;
            path->binding_sid.flags = 0;
            path->has_binding_sid = 1;
            sid_addr = block->binding_sid_srv6_spec.base_addr.ipv6;
            increment_ipv6(&sid_addr, bsid_idx);
            memcpy(path->binding_sid.srv6_sid, &sid_addr, sizeof(path->binding_sid.srv6_sid));
        } else if (block->binding_sid_spec.enabled) {
            path->binding_sid.type = SRPOLICY_BINDING_SID_MPLS;
            path->binding_sid.mpls_label =
                ribout_u32_opt_val(&block->binding_sid_spec, gen, &gen->current_binding_sid_idx);
            path->has_binding_sid = 1;
        } else if (block->binding_sid_count > 0) {
            path->binding_sid.type = SRPOLICY_BINDING_SID_MPLS;
            path->binding_sid.mpls_label =
                bgp_ribout_binding_sids_at(block, gen->current_binding_sid_idx % block->binding_sid_count);
            path->has_binding_sid = 1;
        }
    }

    // Advance to next position
    gen->current_path_id_idx++;
    if (block->next_hop_spec.count > 0) {
        gen->current_next_hop_idx++;  /* Increment next_hop on every path */
    }
    if (block->rt_set_count > 0) {
        gen->current_rt_set_idx++;
    }
    if (block->soo_count > 0) {
        gen->current_soo_idx++;
    }
    if (block->encap_count > 0) {
        gen->current_encap_idx++;
    }
    if (block->router_mac_count > 0) {
        gen->current_router_mac_idx++;
    }
    if (block->color_count > 0 && !block->color_set && !bgp_ribout_family_is_srpolicy(family)) {
        gen->current_color_idx++;  /* Color community rotation; SR Policy steps it as an NLRI key */
    }
    if (block->enlp_count > 0 &&
        !block->enlp_spec.enabled) {
        gen->current_enlp_idx++;
    }
    if (block->priority_count > 0 &&
        !block->priority_spec.enabled) {
        gen->current_priority_idx++;
    }
    if (block->preference_count > 0 &&
        !block->preference_spec.enabled) {
        gen->current_preference_idx++;
    }
    if (((block->binding_sid_kind == BGP_RIBOUT_SR_BINDING_SID_MPLS &&
          block->binding_sid_count > 0 &&
          !block->binding_sid_spec.enabled) ||
         (block->binding_sid_kind == BGP_RIBOUT_SR_BINDING_SID_SRV6 &&
          block->binding_sid_srv6_spec.count > 0))) {
        gen->current_binding_sid_idx++;
    }
    if (bgp_ribout_family_is_evpn_type2(family)) {
        if (block->label_count > 0) {
            gen->current_label_idx++;
        }
        if (block->esi_count > 0) {
            gen->current_esi_idx++;
        }
        if (block->label2_count > 0) {
            gen->current_label2_idx++;
        }
    }

    /*
     * If we've cycled through all path-ids (or no path-ids), move through the
     * remaining NLRI-side dimensions from the innermost (label) outward. A
     * rotating list is a dimension of 1, so its counter stays 0 and its value
     * comes from the rotation step instead.
     */
    uint32_t path_id_max = bgp_ribout_path_id_dimension(block);
    if (gen->current_path_id_idx >= path_id_max) {
        gen->current_path_id_idx = 0;

        if (bgp_ribout_family_is_template(family)) {
            // The template instance comes directly from paths_generated; only path-id has a counter.
        } else if (bgp_ribout_family_is_flowspec(family)) {
            // path-id, then rd, then the NLRI instance (its fields decode in bgp_ribout_flowspec_materialize()).
            gen->current_rd_idx++;
            if (gen->current_rd_idx >= bgp_ribout_rd_dimension(block)) {
                gen->current_rd_idx = 0;
                gen->current_flowspec_instance++;
            }
        } else if (bgp_ribout_family_is_srpolicy(family)) {
            gen->current_endpoint_idx++;
            if (gen->current_endpoint_idx >= bgp_ribout_endpoint_dimension(block)) {
                gen->current_endpoint_idx = 0;
                gen->current_color_idx++;
                if (gen->current_color_idx >= bgp_ribout_color_dimension(block)) {
                    gen->current_color_idx = 0;
                    gen->current_distinguisher_idx++;
                }
            }
        } else if (bgp_ribout_family_is_evpn_type2(family)) {
            uint64_t ip_max = bgp_ribout_type2_ip_dimension(block);
            uint32_t ethernet_tag_max = bgp_ribout_tag_dimension(block);

            gen->current_ip_idx++;
            if (gen->current_ip_idx >= ip_max) {
                gen->current_ip_idx = 0;
                gen->current_mac_idx++;
                if (gen->current_mac_idx >= block->mac_spec.count) {
                    gen->current_mac_idx = 0;
                    gen->current_ethernet_tag_idx++;
                    if (gen->current_ethernet_tag_idx >= ethernet_tag_max) {
                        gen->current_ethernet_tag_idx = 0;
                        gen->current_rd_idx++;
                    }
                }
            }
        } else {
            uint32_t label_max = bgp_ribout_effective_count(block->label_rotate ? 0 : block->label_count);
            uint32_t esi_max = bgp_ribout_effective_count(block->esi_count);
            uint32_t gateway_ip_max =
                bgp_ribout_effective_count(block->gateway_ip_spec.count);
            uint32_t ethernet_tag_max = bgp_ribout_tag_dimension(block);
            uint32_t rd_max = bgp_ribout_rd_dimension(block);

            gen->current_label_idx++;
            if (gen->current_label_idx >= label_max) {
                gen->current_label_idx = 0;
                gen->current_esi_idx++;
                if (gen->current_esi_idx >= esi_max) {
                    gen->current_esi_idx = 0;
                    gen->current_gateway_ip_idx++;
                    if (gen->current_gateway_ip_idx >= gateway_ip_max) {
                        gen->current_gateway_ip_idx = 0;
                        gen->current_ethernet_tag_idx++;
                        if (gen->current_ethernet_tag_idx >= ethernet_tag_max) {
                            gen->current_ethernet_tag_idx = 0;
                            gen->current_rd_idx++;
                            if (gen->current_rd_idx >= rd_max) {
                                gen->current_rd_idx = 0;
                                gen->current_prefix_idx++;
                            }
                        }
                    }
                }
            }
        }
    }

    gen->paths_generated++;

    return 0;
}

/*
 * Reset generator to beginning
 */
void bgp_ribout_generator_reset(bgp_ribout_gen_t *gen) {
    if (gen && gen->initialized) {
        gen->current_prefix_idx = 0;
        gen->current_rd_idx = 0;
        gen->current_ethernet_tag_idx = 0;
        gen->current_mac_idx = 0;
        gen->current_ip_idx = 0;
        gen->current_gateway_ip_idx = 0;
        gen->current_esi_idx = 0;
        gen->current_label_idx = 0;
        gen->current_label2_idx = 0;
        gen->current_distinguisher_idx = 0;
        gen->current_color_idx = 0;
        gen->current_endpoint_idx = 0;
        gen->current_path_id_idx = 0;
        gen->current_next_hop_idx = 0;
        gen->current_rt_set_idx = 0;
        gen->current_soo_idx = 0;
        gen->current_encap_idx = 0;
        gen->current_router_mac_idx = 0;
        gen->current_localpref_idx = 0;
        gen->current_med_idx = 0;
        gen->current_enlp_idx = 0;
        gen->current_priority_idx = 0;
        gen->current_preference_idx = 0;
        gen->current_binding_sid_idx = 0;
        gen->current_flowspec_instance = 0;
        gen->random_state = ribout_seed_state(ribout_initial_seed(gen->ribout_config->name));
        gen->paths_generated = 0;
    }
}

/*
 * Get total number of paths this generator will produce
 */
uint64_t bgp_ribout_gen_total_paths(bgp_ribout_gen_t *gen) {
    if (gen && gen->initialized) {
        return gen->total_paths;
    }
    return 0;
}
