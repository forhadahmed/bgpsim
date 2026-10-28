#ifndef BGP_RIBOUT_H
#define BGP_RIBOUT_H

#include <stdint.h>
#include <netinet/in.h>
#include "bgp_ribout_config.h"

// Default hashmap size
#define RIBOUT_HASHMAP_DEFAULT_SIZE 256

typedef enum {
    BGP_RIBOUT_NLRI_TYPE_IPV4              = 1,
    BGP_RIBOUT_NLRI_TYPE_IPV6              = 2,
    BGP_RIBOUT_NLRI_TYPE_LABELED_IPV4      = 3,
    BGP_RIBOUT_NLRI_TYPE_LABELED_IPV6      = 4,
    BGP_RIBOUT_NLRI_TYPE_VPNV4             = 5,
    BGP_RIBOUT_NLRI_TYPE_VPNV6             = 6,
    BGP_RIBOUT_NLRI_TYPE_EVPN_TYPE5_IPV4   = 7,
    BGP_RIBOUT_NLRI_TYPE_EVPN_TYPE5_IPV6   = 8,
    BGP_RIBOUT_NLRI_TYPE_SR_POLICY_IPV4    = 9,
    BGP_RIBOUT_NLRI_TYPE_SR_POLICY_IPV6    = 10,
    BGP_RIBOUT_NLRI_TYPE_EVPN_TYPE2        = 11,
    BGP_RIBOUT_NLRI_TYPE_FLOWSPEC_IPV4     = 12,
    BGP_RIBOUT_NLRI_TYPE_FLOWSPEC_IPV6     = 13,
    BGP_RIBOUT_NLRI_TYPE_FLOWSPEC_VPN_IPV4 = 14,
    BGP_RIBOUT_NLRI_TYPE_FLOWSPEC_VPN_IPV6 = 15,
    BGP_RIBOUT_NLRI_TYPE_RTC               = 16,
    BGP_RIBOUT_NLRI_TYPE_VPLS              = 17,
    BGP_RIBOUT_NLRI_TYPE_EVPN_TYPE1        = 18,
    BGP_RIBOUT_NLRI_TYPE_EVPN_TYPE3        = 19,
    BGP_RIBOUT_NLRI_TYPE_EVPN_TYPE4        = 20,
    BGP_RIBOUT_NLRI_TYPE_MVPN_IPV4         = 21,
    BGP_RIBOUT_NLRI_TYPE_MVPN_IPV6         = 22,
    BGP_RIBOUT_NLRI_TYPE_BGP_LS            = 23
} bgp_ribout_nlri_type_t;

/*
 * Compact runtime record for one IPv4 unicast NLRI.
 */
typedef struct {
    uint32_t prefix;      /* IPv4 prefix (network byte order) */
    uint32_t path_id;     /* Path ID for ADD-PATH             */
    uint8_t  prefix_len;  /* Prefix length (CIDR)             */
    uint8_t  reserved[3];
} bgp_ribout_nlri_v4_t;

/*
 * Compact runtime record for one IPv6 unicast NLRI.
 */
typedef struct {
    uint8_t  prefix[16];  /* IPv6 prefix (network byte order) */
    uint32_t path_id;     /* Path ID for ADD-PATH             */
    uint8_t  prefix_len;  /* Prefix length (CIDR)             */
    uint8_t  reserved[3];
} bgp_ribout_nlri_v6_t;

/*
 * Compact runtime record for one IPv4 labeled-unicast NLRI.
 */
typedef struct {
    uint32_t prefix;      /* IPv4 prefix (network byte order) */
    uint32_t label;       /* MPLS label                       */
    uint32_t path_id;     /* Path ID for ADD-PATH             */
    uint8_t  prefix_len;  /* Prefix length (CIDR)             */
    uint8_t  reserved[3];
} bgp_ribout_nlri_lu4_t;

/*
 * Compact runtime record for one IPv6 labeled-unicast NLRI.
 */
typedef struct {
    uint8_t  prefix[16];  /* IPv6 prefix (network byte order) */
    uint32_t label;       /* MPLS label                       */
    uint32_t path_id;     /* Path ID for ADD-PATH             */
    uint8_t  prefix_len;  /* Prefix length (CIDR)             */
    uint8_t  reserved[3];
} bgp_ribout_nlri_lu6_t;

/*
 * Compact runtime record for one VPNv4 NLRI.
 */
typedef struct {
    route_distinguisher_t rd;          /* Route distinguisher              */
    uint32_t              prefix;      /* IPv4 prefix (network byte order) */
    uint32_t              label;       /* MPLS label                       */
    uint32_t              path_id;     /* Path ID for ADD-PATH             */
    uint8_t               prefix_len;  /* Prefix length (CIDR)             */
    uint8_t               reserved[3];
} bgp_ribout_nlri_vpnv4_t;

/*
 * Compact runtime record for one VPNv6 NLRI.
 */
typedef struct {
    route_distinguisher_t rd;          /* Route distinguisher              */
    uint8_t               prefix[16];  /* IPv6 prefix (network byte order) */
    uint32_t              label;       /* MPLS label                       */
    uint32_t              path_id;     /* Path ID for ADD-PATH             */
    uint8_t               prefix_len;  /* Prefix length (CIDR)             */
    uint8_t               reserved[3];
} bgp_ribout_nlri_vpnv6_t;

/*
 * Compact runtime record for one EVPN type 5 IPv4 NLRI.
 */
typedef struct {
    route_distinguisher_t rd;               /* Route distinguisher              */
    evpn_esi_t            esi;              /* Ethernet segment identifier      */
    uint32_t              ethernet_tag_id;  /* Ethernet Tag ID                  */
    uint32_t              label;            /* MPLS label                       */
    uint32_t              path_id;          /* Path ID for ADD-PATH             */
    uint32_t              prefix;           /* IPv4 prefix (network byte order) */
    uint32_t              gateway_ip;       /* IPv4 gateway IP (network order)  */
    uint8_t               prefix_len;       /* Prefix length (CIDR)             */
    uint8_t               label_vni;        /* label is a VNI (RFC 8365)        */
    uint8_t               reserved[2];
} bgp_ribout_nlri_evpn4_t;

/*
 * Compact runtime record for one EVPN type 5 IPv6 NLRI.
 */
typedef struct {
    route_distinguisher_t rd;               /* Route distinguisher              */
    evpn_esi_t            esi;              /* Ethernet segment identifier      */
    uint32_t              ethernet_tag_id;  /* Ethernet Tag ID                  */
    uint32_t              label;            /* MPLS label                       */
    uint32_t              path_id;          /* Path ID for ADD-PATH             */
    uint8_t               prefix[16];       /* IPv6 prefix (network byte order) */
    uint8_t               gateway_ip[16];   /* IPv6 gateway IP (network order)  */
    uint8_t               prefix_len;       /* Prefix length (CIDR)             */
    uint8_t               label_vni;        /* label is a VNI (RFC 8365)        */
    uint8_t               reserved[2];
} bgp_ribout_nlri_evpn6_t;

/*
 * Compact runtime record for one IPv4 SR Policy NLRI.
 */
typedef struct {
    uint32_t distinguisher;  /* SR Policy distinguisher */
    uint32_t color;          /* SR Policy color         */
    uint32_t path_id;        /* Path ID                 */
    uint32_t endpoint;       /* IPv4 endpoint           */
} bgp_ribout_nlri_sr4_t;

/*
 * Compact runtime record for one IPv6 SR Policy NLRI.
 */
typedef struct {
    uint32_t distinguisher;  /* SR Policy distinguisher */
    uint32_t color;          /* SR Policy color         */
    uint32_t path_id;        /* Path ID                 */
    uint8_t  endpoint[16];   /* IPv6 endpoint           */
} bgp_ribout_nlri_sr6_t;

/*
 * Compact runtime record for one EVPN Type 2 NLRI.
 */
typedef struct {
    route_distinguisher_t rd;               /* Route distinguisher         */
    evpn_esi_t            esi;              /* Ethernet segment identifier */
    uint32_t              ethernet_tag_id;  /* Ethernet Tag ID             */
    uint32_t              label1;           /* MPLS Label1                 */
    uint32_t              label2;           /* Optional MPLS Label2        */
    uint32_t              path_id;          /* Path ID for ADD-PATH        */
    uint8_t               mac[6];           /* MAC address                 */
    uint8_t               ip_addr_len;      /* 0, 32, or 128               */
    uint8_t               has_label2;       /* Optional Label2 is present  */
    uint8_t               label_vni;        /* Labels are VNIs (RFC 8365)  */
    uint8_t               ip_addr[16];      /* Optional IPv4/IPv6 address  */
} bgp_ribout_nlri_evpn2_t;

/*
 * Compact runtime record for one FlowSpec NLRI. A rule is variable-length on
 * the wire, so the record keeps only its instance number; the encoder rebuilds
 * the rule from the block (bgp_ribout_flowspec_materialize()).
 */
typedef struct {
    route_distinguisher_t rd;        /* Route distinguisher (SAFI 134) */
    uint64_t              instance;  /* FlowSpec NLRI instance         */
    uint32_t              path_id;   /* Path ID for ADD-PATH           */
    uint32_t              reserved;
} bgp_ribout_nlri_flowspec_t;

typedef struct {
    uint64_t instance;
    uint32_t path_id;
    uint32_t reserved;
} bgp_ribout_nlri_template_t;

/*
 * Fixed-capacity chunk of compact NLRI runtime records.
 */
typedef struct bgp_ribout_nlri_chunk {
    struct bgp_ribout_nlri_chunk *next;      /* Next chunk in this attribute bucket */
    uint16_t                      count;     /* Number of records used              */
    uint16_t                      capacity;  /* Number of records allocated         */
    uint16_t                      stride;    /* Bytes per record                    */
    uint16_t                      reserved;
    uint8_t                       data[];    /* Packed runtime NLRI records         */
} bgp_ribout_nlri_chunk_t;

/*
 * One unique UPDATE packing key inside the ribout map.
 */
typedef struct path_attr_entry {
    // BGP Path Attributes
    union {
        struct in_addr  ipv4;  /* IPv4 next_hop (binary) */
        struct in6_addr ipv6;  /* IPv6 next_hop (binary) */
    } next_hop;
    struct in6_addr          next_hop_link_local;      /* IPv6 link-local next-hop              */
    const uint8_t           *aspath_data;              /* Compact runtime AS path bytes         */
    const uint8_t           *ext_comm_data;            /* Encoded extended communities          */
    const uint8_t           *ipv6_ext_comm_data;       /* Encoded attribute 25 entries          */
    const uint8_t           *community_data;           /* COMMUNITIES value (attribute 8)       */
    const uint8_t           *large_community_data;     /* LARGE_COMMUNITY value (attribute 32)  */
    bgp_ribout_nlri_chunk_t *nlri_chunks;              /* Head of NLRI chunk list               */
    bgp_ribout_nlri_chunk_t *nlri_chunks_tail;         /* Tail of NLRI chunk list               */
    size_t                   nlri_count;               /* Number of NLRIs in all chunks         */
    struct path_attr_entry  *next;                     /* Next entry in hash bucket             */
    struct path_attr_entry  *order_next;               /* Next entry in insertion order         */
    uint32_t                 attr_hash;                /* Cached path attribute hash            */
    uint32_t                 local_pref;               /* Local preference                      */
    uint32_t                 med;                      /* MED value                             */
    uint32_t                 preference;               /* SR Policy preference                  */
    srpolicy_binding_sid_t   binding_sid;              /* SR Policy Binding SID                 */
    uint16_t                 aspath_data_len;          /* Size of compact AS path bytes         */
    uint16_t                 ext_comm_len;             /* Size of encoded ext-community bytes   */
    uint16_t                 ipv6_ext_comm_len;        /* Size of attribute 25 bytes            */
    uint16_t                 community_len;            /* Size of community_data                */
    uint16_t                 large_community_len;      /* Size of large_community_data          */
    uint16_t                 aspath_segment_count;     /* Number of AS path segments            */
    uint8_t                  next_hop_af;              /* Next-hop address family               */
    uint8_t                  next_hop_has_link_local;  /* IPv6 link-local if set                */
    uint8_t                  origin;                   /* Origin: IGP(0), EGP(1), INCOMPLETE(2) */
    uint8_t                  nlri_type;                /* bgp_ribout_nlri_type_t                */
    uint8_t                  enlp;                     /* SR Policy ENLP                        */
    uint8_t                  priority;                 /* SR Policy priority                    */
    uint8_t                  has_med;                  /* MED attribute is present              */
    uint8_t                  has_enlp;                 /* SR Policy ENLP is present             */
    uint8_t                  has_priority;             /* SR Policy priority is present         */
    uint8_t                  has_tunnel_encap;         /* SR Policy tunnel attr is present      */
} path_attr_entry_t;

/*
 * Hash map that groups generated paths by attribute tuple. The entries are also on a list in insertion order
 * (order_head, then order_next). Bucket compaction and message generation walk that list: it reads the arena forward
 * (the bucket order jumps across memory and misses the cache), and the UPDATEs come out in generator order.
 */
typedef struct bgp_ribout_map {
    path_attr_entry_t            **buckets;           /* Array of bucket pointers           */
    path_attr_entry_t             *order_head;        /* First entry in insertion order     */
    path_attr_entry_t             *order_tail;        /* Last entry in insertion order      */
    struct bgp_ribout_arena_chunk *arena_chunks;      /* Pooled chunk allocator list        */
    size_t                         bucket_count;      /* Number of buckets                  */
    size_t                         bucket_mask;       /* bucket_count - 1 for mask indexing */
    size_t                         entry_count;       /* Number of path_attr entries        */
    size_t                         total_nlri_count;  /* Total NLRIs across all entries     */
    size_t                         memory_usage;      /* Total memory usage in bytes        */
    size_t                         arena_chunk_size;  /* Default chunk size for pool alloc  */
} bgp_ribout_map_t;

/*
 * Path attributes tuple for ribout map lookups and insertions.
 */
typedef struct {
    const void                 *next_hop_addr;            /* struct in_addr* or struct in6_addr* */
    const struct in6_addr      *next_hop_link_local;      /* Optional IPv6 link-local next-hop   */
    const bgp_aspath_segment_t *aspath_segments;          /* AS path segments (array)            */
    const uint8_t              *ext_comm_data;            /* Encoded extended communities        */
    const uint8_t              *ipv6_ext_comm_data;       /* Encoded attribute 25 entries        */
    const uint8_t              *community_data;           /* COMMUNITIES value                   */
    const uint8_t              *large_community_data;     /* LARGE_COMMUNITY value               */
    uint32_t                    aspath_segment_count;     /* Number of AS path segments          */
    uint32_t                    local_pref;               /* Local preference                    */
    uint32_t                    med;                      /* MED value                           */
    uint32_t                    preference;               /* SR Policy preference                */
    srpolicy_binding_sid_t      binding_sid;              /* SR Policy Binding SID               */
    uint16_t                    ext_comm_len;             /* Size of ext_comm_data               */
    uint16_t                    ipv6_ext_comm_len;        /* Size of ipv6_ext_comm_data          */
    uint16_t                    community_len;            /* Size of community_data              */
    uint16_t                    large_community_len;      /* Size of large_community_data        */
    uint8_t                     next_hop_af;              /* AF_INET or AF_INET6                 */
    uint8_t                     next_hop_has_link_local;  /* IPv6 link-local next-hop if set     */
    uint8_t                     origin;                   /* IGP(0), EGP(1), INCOMPLETE(2)       */
    uint8_t                     enlp;                     /* SR Policy ENLP                      */
    uint8_t                     priority;                 /* SR Policy priority                  */
    uint8_t                     has_med;                  /* MED attribute is present            */
    uint8_t                     has_enlp;                 /* SR Policy ENLP is present           */
    uint8_t                     has_priority;             /* SR Policy priority is present       */
    uint8_t                     has_tunnel_encap;         /* SR Policy tunnel attr is present    */
} bgp_path_attrs_t;

// RibOut Map Functions

/*
 * Create a new ribout map with specified bucket count
 */
bgp_ribout_map_t* bgp_ribout_map_create(size_t bucket_count);

/*
 * Destroy a ribout map and free all memory
 */
void bgp_ribout_map_destroy(bgp_ribout_map_t *map);

/*
 * Clear all entries from the map (without destroying the map itself)
 */
void bgp_ribout_map_clear(bgp_ribout_map_t *map);

/*
 * Insert or update an NLRI with given path attributes
 * If attributes already exist, adds NLRI to that entry's list
 * If attributes don't exist, creates new entry and adds NLRI
 * Returns 0 on success, -1 on error
 *
 * prefix_addr: pointer to struct in_addr (AF_INET) or struct in6_addr (AF_INET6)
 * attrs: path attributes tuple (next_hop, AS path, local_pref, origin)
 */
int bgp_ribout_map_insert(bgp_ribout_map_t *map,
                          const void *prefix_addr,
                          uint8_t prefix_len,
                          uint8_t prefix_af,
                          uint32_t path_id,
                          const bgp_path_attrs_t *attrs);

/*
 * Find a path_attr_entry matching the given attributes
 * Returns the entry if found, NULL otherwise
 * attrs: path attributes tuple to search for
 */
path_attr_entry_t* bgp_ribout_map_find(bgp_ribout_map_t *map, const bgp_path_attrs_t *attrs);

/*
 * Get statistics about the map
 */
void bgp_ribout_map_get_stats(bgp_ribout_map_t *map,
                              size_t *out_entries,
                              size_t *out_total_nlris,
                              size_t *out_bucket_count);

/*
 * Get memory usage of the map in bytes
 */
size_t bgp_ribout_map_get_memory_usage(bgp_ribout_map_t *map);

/*
 * Print the ribout map (for debugging/display)
 */
void bgp_ribout_map_print(bgp_ribout_map_t *map);

// Hash Function

/*
 * Compute hash for a set of path attributes
 * attrs: path attributes tuple to hash
 */
uint32_t bgp_ribout_map_hash_attributes(const bgp_path_attrs_t *attrs);

// BGP UPDATE Message Structure

/*
 * One encoded BGP UPDATE message stored on a ribout block.
 */
typedef struct bgp_msg {
    uint8_t        *data;    /* Binary BGP UPDATE message */
    uint16_t        length;  /* Message length in bytes   */
    struct bgp_msg *next;    /* Next message in list      */
} bgp_msg_t;

// RibOut Generation Functions

/*
 * Generate ribout map from configuration
 */
typedef enum {
    BGP_RIBOUT_GENERATED       = 0,
    BGP_RIBOUT_INCOMPLETE      = 1,
    BGP_RIBOUT_MAP_FAILED      = -1,
    BGP_RIBOUT_MESSAGES_FAILED = -2
} bgp_ribout_generation_result_t;

/*
 * Complete generation owns aggregate timing and dirty-state transitions.
 */
bgp_ribout_generation_result_t bgp_ribout_generate(bgp_ribout_config_t *block);

int bgp_ribout_generate_map(bgp_ribout_config_t *block);

/*
 * Clear the ribout map
 */
void bgp_ribout_clear_map(bgp_ribout_config_t *block);

/*
 * Generate BGP UPDATE messages from ribout map
 */
int bgp_ribout_generate_messages(bgp_ribout_config_t *block);

/*
 * Free a list of BGP UPDATE messages
 */
void bgp_msg_list_free(bgp_msg_t *list);

/*
 * Generator Functions (Iterator Pattern)
 * Note: Generator types are defined in bgp_ribout_config.h
 */

/*
 * Initialize generator
 */
int bgp_ribout_generator_init(bgp_ribout_gen_t *gen, bgp_ribout_config_t *block);

/*
 * Check if generator has more paths
 */
int bgp_ribout_generator_has_next(bgp_ribout_gen_t *gen);

/*
 * Get next generated path
 */
int bgp_ribout_generator_next(bgp_ribout_gen_t *gen, bgp_gen_path_t *path);

/*
 * Reset generator to beginning
 */
void bgp_ribout_generator_reset(bgp_ribout_gen_t *gen);

/*
 * Get total number of paths generator will produce
 */
uint64_t bgp_ribout_gen_total_paths(bgp_ribout_gen_t *gen);

/*
 * Paths a block generates (the NLRI-side product times path-ids); 0 on count overflow.
 */
uint64_t bgp_ribout_total_paths(const bgp_ribout_config_t *block);

// Helper Functions

/*
 * Convert prefix spec and index to string representation
 */
void bgp_prefix_to_string(bgp_prefix_spec_t *spec, uint32_t index, char *output, size_t output_len);

/*
 * Convert next_hop spec and index to string representation
 */
void bgp_next_hop_to_string(bgp_next_hop_spec_t *spec, uint32_t index, char *output, size_t output_len);

/*
 * Convert AS-path segments to string representation
 */
void bgp_aspath_to_string(const bgp_aspath_segment_t *segments, uint32_t segment_count,
                          char *output, size_t output_len);

/*
 * Convert origin type to string
 */
const char* bgp_origin_to_string(bgp_origin_t origin);

#endif /* BGP_RIBOUT_H */
