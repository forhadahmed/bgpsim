#ifndef BGP_RIBOUT_CONFIG_H
#define BGP_RIBOUT_CONFIG_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>
#include "util.h"
#include "bgp_update.h"

/*
 * Forward declarations from bgp_ribout.h
 */
typedef struct bgp_ribout_map bgp_ribout_map_t;
typedef struct bgp_msg bgp_msg_t;
struct bgp_ribout_snapshot;  /* bgp_ribout_snapshot.h */

// Remaining per-route/parser bounds. Router, peer, ribout and attribute inventories grow independently.
#define BGP_RIBOUT_NAME_SIZE          32
#define MAX_RTS                       64
#define MAX_RT_VALUES_PER_SET         16
#define MAX_SOOS                      32
#define MAX_ENCAPS                    16
#define MAX_ROUTER_MACS               32
#define MAX_ESIS                      32
#define MAX_COMMUNITIES_PER_SET       16   /* Values in one community set           */
#define MAX_LARGE_COMMUNITIES_PER_SET 16   /* Values in one large-community set     */
#define MAX_FLOWSPEC_OPS              8    /* {operator, value} pairs per component */
#define MAX_FLOWSPEC_ALTERNATIVES     16   /* each(...) items of one component      */
#define MAX_FLOWSPEC_LINES            8    /* action lines per block                */
#define MAX_FLOWSPEC_ACTION_VALUES    64   /* Rotating values of one action line    */
#define MAX_FLOWSPEC_LINE_TEXT        512  /* Canonical text of one action line     */
// Shared per-path capacity for RT/RT-set, SoO, encap, router-MAC, Colors and FlowSpec actions.
#define MAX_EXT_COMMS_PER_ROUTE (MAX_RTS + 4 + MAX_FLOWSPEC_LINES)
#define MAX_IPV6_EXT_COMMS_PER_ROUTE MAX_FLOWSPEC_LINES
#define MAX_ASPATH_SEGMENTS          50
#define MAX_AS_VALUES_PER_SEGMENT    100
#define MAX_ASPATH_STRING_LEN        1024
#define MAX_PREFIX_STRING_LEN        64
#define MAX_SR_SEGMENTS_PER_LIST     32

/*
 * AS-Path segment types
 */
typedef enum {
    ASPATH_SEQUENCE,  /* AS sequence: 10 20 30    */
    ASPATH_SET,       /* AS set: { 10 20 30 }     */
    ASPATH_RANDOM     /* Random: [rand(100) x 10] */
} aspath_segment_type_t;

/*
 * Generic scalar value generation modes for ribout attributes.
 */
typedef enum {
    BGP_U32_MODE_FIXED,        /* Fixed value               */
    BGP_U32_MODE_RANDOM,       /* Random: rand(N)           */
    BGP_U32_MODE_RANGE,        /* Deterministic: range(A,B) */
    BGP_U32_MODE_RANDOM_RANGE  /* Random: randrange(A,B)    */
} bgp_u32_mode_t;

/*
 * BGP origin types
 */
typedef enum {
    ORIGIN_IGP        = 0,  /* 'i' - Interior Gateway Protocol */
    ORIGIN_EGP        = 1,  /* 'e' - Exterior Gateway Protocol */
    ORIGIN_INCOMPLETE = 2   /* '?' - Incomplete                */
} bgp_origin_t;

/*
 * Resolved address-family for one ribout block.
 */
typedef enum {
    BGP_RIBOUT_FAMILY_NONE              = 0,
    BGP_RIBOUT_FAMILY_IPV4_UNICAST      = 1,
    BGP_RIBOUT_FAMILY_IPV6_UNICAST      = 2,
    BGP_RIBOUT_FAMILY_LABELED_IPV4      = 3,
    BGP_RIBOUT_FAMILY_LABELED_IPV6      = 4,
    BGP_RIBOUT_FAMILY_VPNV4             = 5,
    BGP_RIBOUT_FAMILY_VPNV6             = 6,
    BGP_RIBOUT_FAMILY_EVPN_TYPE5_IPV4   = 7,
    BGP_RIBOUT_FAMILY_EVPN_TYPE5_IPV6   = 8,
    BGP_RIBOUT_FAMILY_SR_POLICY_IPV4    = 9,
    BGP_RIBOUT_FAMILY_SR_POLICY_IPV6    = 10,
    BGP_RIBOUT_FAMILY_EVPN_TYPE2        = 11,
    BGP_RIBOUT_FAMILY_FLOWSPEC_IPV4     = 12,
    BGP_RIBOUT_FAMILY_FLOWSPEC_IPV6     = 13,
    BGP_RIBOUT_FAMILY_FLOWSPEC_VPN_IPV4 = 14,
    BGP_RIBOUT_FAMILY_FLOWSPEC_VPN_IPV6 = 15,
    BGP_RIBOUT_FAMILY_RTC               = 16,
    BGP_RIBOUT_FAMILY_VPLS              = 17,
    BGP_RIBOUT_FAMILY_EVPN_TYPE1        = 18,
    BGP_RIBOUT_FAMILY_EVPN_TYPE3        = 19,
    BGP_RIBOUT_FAMILY_EVPN_TYPE4        = 20,
    BGP_RIBOUT_FAMILY_MVPN_IPV4         = 21,
    BGP_RIBOUT_FAMILY_MVPN_IPV6         = 22,
    BGP_RIBOUT_FAMILY_BGP_LS            = 23
} bgp_ribout_family_t;

// Families in bgp_ribout_family_t, BGP_RIBOUT_FAMILY_NONE included.
#define BGP_RIBOUT_FAMILY_COUNT 24

/*
 * What a ribout family generates.
 */
typedef enum {
    BGP_RIBOUT_KIND_NONE = 0,
    BGP_RIBOUT_KIND_PREFIX,      /* Unicast, labeled-unicast, VPN, EVPN Type 5 */
    BGP_RIBOUT_KIND_EVPN_TYPE2,  /* EVPN MAC/IP advertisement                  */
    BGP_RIBOUT_KIND_SR_POLICY,   /* SR Policy, SAFI 73                         */
    BGP_RIBOUT_KIND_FLOWSPEC,    /* FlowSpec rules, SAFI 133 and 134           */
    BGP_RIBOUT_KIND_TEMPLATE     /* Typed non-prefix NLRI templates            */
} bgp_ribout_kind_t;

// Next-hop address families, for bgp_ribout_family_info_t.next_hop_afs.
#define BGP_RIBOUT_NH_IPV4 0x01
#define BGP_RIBOUT_NH_IPV6 0x02

struct bgp_nlri_cursor;  /* Encoder state, private to bgp_ribout.c */

/*
 * One row per ribout family, indexed by bgp_ribout_family_t. The grouped-map
 * NLRI types (bgp_ribout_nlri_type_t) use the same numbers, so a row also
 * describes the NLRI record of the family. Family-dependent code reads this
 * table; to add a family, add a row to bgp_ribout_families[] in bgp_ribout.c.
 */
typedef struct {
    const char *name;               /* Name in show ribout, "ipv4-unicast"  */
    uint16_t    afi;                /* MP_REACH AFI                         */
    uint8_t     safi;               /* MP_REACH SAFI                        */
    uint8_t     kind;               /* bgp_ribout_kind_t                    */
    uint8_t     prefix_af;          /* NLRI address AF, 0 if none           */
    uint8_t     has_label;          /* Labeled-unicast NLRI                 */
    uint8_t     next_hop_afs;       /* BGP_RIBOUT_NH_* the next hop accepts */
    uint8_t     next_hop_optional;  /* Zero-length next hop unless one set  */
    size_t      nlri_stride;        /* Grouped-map record size              */
    int (*encode_next_hop)(const bgp_next_hop_t *next_hop, uint8_t *buffer, uint8_t *nh_len_out);
    int (*encode_chunk)(struct bgp_nlri_cursor *cursor, uint8_t *buffer, int max_bytes, int add_path);
} bgp_ribout_family_info_t;

extern const bgp_ribout_family_info_t bgp_ribout_families[BGP_RIBOUT_FAMILY_COUNT];

/*
 * The table row of a family; the NONE row for a value out of range.
 */
static inline const bgp_ribout_family_info_t *bgp_ribout_family_info(bgp_ribout_family_t family) {
    return &bgp_ribout_families[(unsigned)family < BGP_RIBOUT_FAMILY_COUNT ? (unsigned)family : 0];
}

/*
 * The family carries FlowSpec rules, not prefixes.
 */
static inline int bgp_ribout_family_is_flowspec(bgp_ribout_family_t family) {
    return bgp_ribout_family_info(family)->kind == BGP_RIBOUT_KIND_FLOWSPEC;
}

static inline int bgp_ribout_family_is_template(bgp_ribout_family_t family) {
    return bgp_ribout_family_info(family)->kind == BGP_RIBOUT_KIND_TEMPLATE;
}

/*
 * Templates contain no pointers: config edits and snapshots own complete independent copies.
 */
typedef struct {
    bgp_ribout_family_t   family;
    uint32_t              count;
    uint8_t               route_type;
    uint8_t               step;
    uint8_t               af;
    uint8_t               is_default;
    route_distinguisher_t rd;
    evpn_esi_t            esi;
    uint32_t              origin_as, source_as, tag, label;
    uint16_t              ve_id, offset, size;
    uint8_t               target[8], router[16], source[16], group[16];
    uint8_t               route_key[239];
    uint8_t               route_key_len;
    uint8_t               protocol;
    uint64_t              identifier;
    uint8_t               local_desc[64], remote_desc[64], descriptor[32];
    uint16_t              local_len, remote_len, descriptor_len, descriptor_type;
    char                  text[1024];
} bgp_ribout_template_t;

static inline uint32_t bgp_ribout_effective_count(uint32_t count) {
    return (count == 0) ? 1U : count;
}

/*
 * Prefix generator specification for a ribout block.
 */
typedef struct {
    union {
        struct in_addr  ipv4;
        struct in6_addr ipv6;
    } base_addr;
    uint8_t  prefix_len;  /* Prefix length (e.g., 16 for /16)     */
    uint32_t count;       /* Number of prefixes to generate (x N) */
    int      af;          /* AF_INET or AF_INET6                  */
} bgp_prefix_spec_t;

/*
 * Next-hop generator specification for a ribout block.
 */
typedef struct {
    union {
        struct in_addr  ipv4;
        struct in6_addr ipv6;
    } base_addr;
    uint32_t        count;           /* Number of next_hops (x N), 1 for single IP */
    int             af;              /* AF_INET or AF_INET6                        */
    uint8_t         has_link_local;  /* Optional IPv6 link-local companion         */
    struct in6_addr link_local;      /* Optional IPv6 link-local companion         */
} bgp_next_hop_spec_t;

/*
 * MAC generator specification for EVPN Type 2 host identity scale.
 */
typedef struct {
    uint8_t  base_addr[6];  /* Starting MAC address */
    uint32_t count;         /* Number of MACs (x N) */
} bgp_mac_spec_t;

/*
 * Parsed ribout AS-path segment specification.
 */
typedef struct {
    aspath_segment_type_t type;
    uint32_t              as_values[MAX_AS_VALUES_PER_SEGMENT];  /* For SEQUENCE/SET     */
    uint32_t              value_count;                           /* Number of AS values  */
    uint32_t              rand_max;                              /* Max value for RANDOM */
    uint32_t              rand_count;                            /* Count for RANDOM     */
} bgp_aspath_segment_t;

/*
 * Parsed ribout scalar specification.
 */
typedef struct {
    bgp_u32_mode_t mode;
    uint32_t       value;        /* Fixed value or rand(N) max      */
    uint32_t       range_start;  /* range()/randrange() start value */
    uint32_t       range_end;    /* range()/randrange() end value   */
} bgp_u32_spec_t;

/*
 * Optional parsed ribout scalar specification.
 */
typedef struct {
    bgp_u32_mode_t mode;
    uint32_t       value;        /* Fixed value or rand(N) max      */
    uint32_t       range_start;  /* range()/randrange() start value */
    uint32_t       range_end;    /* range()/randrange() end value   */
    uint8_t        enabled;      /* 1 when MED should be emitted    */
} bgp_u32_optional_spec_t;

/*
 * One encoded extended community value in canonical 8-byte wire form.
 */
typedef struct {
    uint8_t bytes[8];
} bgp_ext_comm_t;

/*
 * FlowSpec operator components (RFC 8955 section 4.2.2, RFC 8956 section 3):
 * X(id, keyword, component type, bitmask operator, help). This one list owns
 * the keywords of the rule parser, the renderer, and the CLI command table.
 */
#define BGP_RIBOUT_FLOWSPEC_OP_COMPONENTS(X)                                                             \
    X(protocol,      "protocol",      FLOWSPEC_IP_PROTOCOL, 0, "IP protocol; IPv6 upper-layer protocol") \
    X(port,          "port",          FLOWSPEC_PORT,        0, "source or destination port")             \
    X(dst_port,      "dst-port",      FLOWSPEC_DEST_PORT,   0, "destination port")                       \
    X(src_port,      "src-port",      FLOWSPEC_SRC_PORT,    0, "source port")                            \
    X(icmp_type,     "icmp-type",     FLOWSPEC_ICMP_TYPE,   0, "ICMP type")                              \
    X(icmp_code,     "icmp-code",     FLOWSPEC_ICMP_CODE,   0, "ICMP code")                              \
    X(tcp_flags,     "tcp-flags",     FLOWSPEC_TCP_FLAGS,   1, "TCP flags")                              \
    X(packet_length, "packet-length", FLOWSPEC_PACKET_LEN,  0, "packet length")                          \
    X(dscp,          "dscp",          FLOWSPEC_DSCP,        0, "DSCP")                                   \
    X(fragment,      "fragment",      FLOWSPEC_FRAGMENT,    1, "fragment bits")                          \
    X(flow_label,    "flow-label",    FLOWSPEC_FLOW_LABEL,  0, "IPv6 flow label")

/*
 * {operator, value} list of one FlowSpec component; num_values 0 = unset.
 */
typedef struct {
    flowspec_op_value_t values[MAX_FLOWSPEC_OPS];
    uint8_t             num_values;
} bgp_ribout_flowspec_ops_t;

/*
 * One "community" set as written: its values (RFC 1997, 4 octets each) and how many sets it makes ("[set] x <repeat>":
 * set i has every value's low 16 bits larger by i, except the well-known ones, 65535:x, which stay).
 */
typedef struct {
    uint32_t values[MAX_COMMUNITIES_PER_SET];
    uint32_t count;
    uint32_t repeat;
} bgp_community_group_t;

/*
 * One "large-community" set as written (RFC 8092: global administrator, local data 1, local data 2), and how many
 * sets it makes: set i has every value's local data 2 larger by i.
 */
typedef struct {
    uint32_t values[MAX_LARGE_COMMUNITIES_PER_SET][3];
    uint32_t count;
    uint32_t repeat;
} bgp_large_community_group_t;

/*
 * One written RT set. Repetitions step each member's local administrator, without expanding storage.
 */
typedef struct {
    bgp_ext_comm_t values[MAX_RT_VALUES_PER_SET];
    uint32_t       count;
    uint32_t       repeat;
    uint32_t       first;  /* Logical index of this group's first set; supports binary search. */
} bgp_rt_set_spec_t;

/*
 * One configured SR Policy segment-list definition.
 */
typedef struct {
    uint32_t           id;
    uint32_t           weight;
    uint32_t           segment_count;
    srpolicy_segment_t segments[MAX_SR_SEGMENTS_PER_LIST];
} bgp_ribout_sr_segment_list_t;

/*
 * One FlowSpec operator component. Each "each(...)" alternative makes its own NLRI. One expression with "x <count>"
 * makes count NLRIs: the value of its one comparison steps by 1.
 */
typedef struct {
    bgp_ribout_flowspec_ops_t alternatives[MAX_FLOWSPEC_ALTERNATIVES];
    uint32_t                  alternative_count;  /* 0 = component unset                                  */
    uint32_t                  step_count;         /* "x <count>", else 1                                  */
    uint8_t                   rotate;             /* "rotate": one value per path, not one NLRI per value */
} bgp_ribout_flowspec_component_t;

/*
 * The action kinds that have a value list: they rotate, one value per path.
 */
typedef enum {
    BGP_RIBOUT_FLOWSPEC_ACTION_FIXED = 0,  /* One value: traffic-rate, traffic-action, ... */
    BGP_RIBOUT_FLOWSPEC_ACTION_REDIRECT_IP,
    BGP_RIBOUT_FLOWSPEC_ACTION_REDIRECT_VRF,
    BGP_RIBOUT_FLOWSPEC_ACTION_MARK,
} bgp_ribout_flowspec_action_kind_t;

/*
 * One FlowSpec "action" line: its canonical text (also the running-config form) and the community values it rotates
 * through, one per path. A value is an 8-octet community (attribute 16) or, with an IPv6 address, a 20-octet one
 * (attribute 25).
 */
typedef struct {
    char    text[MAX_FLOWSPEC_LINE_TEXT];
    uint8_t values[MAX_FLOWSPEC_ACTION_VALUES][20];
    uint8_t value_count;
    uint8_t value_len;          /* 8 or 20                            */
    uint8_t kind;               /* bgp_ribout_flowspec_action_kind_t  */
    uint8_t redirect_next_hop;  /* 0x0800: the next hop is the target */
} bgp_ribout_flowspec_line_t;

/*
 * The action lines of a block.
 */
typedef struct {
    bgp_ribout_flowspec_line_t lines[MAX_FLOWSPEC_LINES];
    uint32_t                   line_count;
} bgp_ribout_flowspec_actions_t;

/*
 * The FlowSpec part of a block: the source prefix, the operator components and the action lines. The block "prefix"
 * is the destination prefix.
 */
typedef struct {
    bgp_prefix_spec_t               src_prefix;                           /* count 0 when unset                 */
    uint8_t                         src_offset;                           /* IPv6 offset (RFC 8956 section 3.1) */
    bgp_ribout_flowspec_component_t components[FLOWSPEC_FLOW_LABEL + 1];  /* By type, 3-13                      */
    uint8_t                         set_types[FLOWSPEC_FLOW_LABEL];       /* Set component types, ascending     */
    uint8_t                         set_count;                            /* Entries in set_types               */
    uint8_t                         rotating;                             /* Some set component rotates         */
    bgp_ribout_flowspec_actions_t   actions;
} bgp_ribout_flowspec_t;

typedef enum {
    BGP_RIBOUT_SR_BINDING_SID_NONE = 0,
    BGP_RIBOUT_SR_BINDING_SID_MPLS = 1,
    BGP_RIBOUT_SR_BINDING_SID_SRV6 = 2
} bgp_ribout_sr_binding_sid_kind_t;

// User-facing ribout block plus its cached map/message products.
// One inventory schema drives clone, cleanup, edit transfer and memory accounting.
#define BGP_RIBOUT_U32_ARRAYS(X)                     \
    X(uint32_t, labels, label_count)                 \
    X(uint32_t, label2s, label2_count)               \
    X(uint32_t, ethernet_tags, ethernet_tag_count)   \
    X(uint32_t, path_ids, path_id_count)             \
    X(uint32_t, distinguishers, distinguisher_count) \
    X(uint32_t, colors, color_count)                 \
    X(uint32_t, enlps, enlp_count)                   \
    X(uint32_t, priorities, priority_count)          \
    X(uint32_t, preferences, preference_count)       \
    X(uint32_t, binding_sids, binding_sid_count)

#define BGP_RIBOUT_OWNED_ARRAYS(X)                                                      \
    BGP_RIBOUT_U32_ARRAYS(X)                                                            \
    X(route_distinguisher_t, rds, rd_count)                                             \
    X(uint8_t, color_co, color_count)                                                   \
    X(bgp_aspath_segment_t, aspath_segments, aspath_segment_count)                      \
    X(bgp_rt_set_spec_t, rt_sets, rt_set_group_count)                                   \
    X(bgp_community_group_t, community_groups, community_group_count)                   \
    X(bgp_large_community_group_t, large_community_groups, large_community_group_count) \
    X(bgp_ribout_sr_segment_list_t, segment_lists, segment_list_count)

typedef struct bgp_ribout_config {
    char                             name[BGP_RIBOUT_NAME_SIZE];          /* Network block name                     */
    bgp_prefix_spec_t                prefix_spec;                         /* Prefix (FlowSpec: destination prefix)  */
    uint8_t                          prefix_offset;                       /* FlowSpec IPv6 destination offset       */
    uint32_t                         rd_count;                            /* Number of route distinguishers         */
    uint8_t                          rd_rotate;                           /* RDs rotate per path, not multiply      */
    uint32_t                         label_count;                         /* Number of labels                       */
    uint8_t                          label_rotate;                        /* Labels rotate per path, not multiply   */
    uint32_t                         ethernet_tag_count;                  /* Number of Ethernet Tag IDs             */
    uint8_t                          ethernet_tag_rotate;                 /* Tags rotate per path, not multiply     */
    bgp_mac_spec_t                   mac_spec;                            /* EVPN Type 2 MAC generation spec        */
    bgp_next_hop_spec_t              ip_spec;                             /* EVPN Type 2 optional IP spec           */
    uint8_t                          ip_rotate;                           /* Type 2 IPs pair with MACs, 1 per MAC   */
    bgp_next_hop_spec_t              ip2_spec;                            /* Type 2 IPs of the other family         */
    uint8_t                          ip2_rotate;                          /* ip rotate for ip2_spec                 */
    uint32_t                         rotate_every;                        /* Rotations advance every n paths (0: 1) */
    uint32_t                         rotate_period;                       /* Rotating lists must have this length   */
    uint32_t                         path_id_count;                       /* Number of path IDs                     */
    uint8_t                          path_id_rotate;                      /* Path IDs rotate per path, not multiply */
    bgp_next_hop_spec_t              next_hop_spec;                       /* Next-hop generation spec               */
    bgp_next_hop_spec_t              gateway_ip_spec;                     /* EVPN gateway IP generation spec        */
    bgp_next_hop_spec_t              endpoint_spec;                       /* SR Policy endpoint generation spec     */
    uint8_t                          endpoint_rotate;                     /* Endpoints rotate per path              */
    evpn_esi_t                       esis[MAX_ESIS];                      /* EVPN ESI list                          */
    uint32_t                         esi_count;                           /* Number of EVPN ESI values              */
    uint32_t                         label2_count;                        /* Number of EVPN Type 2 Label2 values    */
    uint32_t                         aspath_segment_count;                /* Number of AS-Path segments             */
    bgp_u32_spec_t                   localpref_spec;                      /* Local preference spec                  */
    bgp_u32_optional_spec_t          med_spec;                            /* MED specification                      */
    bgp_u32_optional_spec_t          enlp_spec;                           /* SR Policy ENLP generation mode         */
    bgp_u32_optional_spec_t          priority_spec;                       /* SR Policy priority generation mode     */
    bgp_u32_optional_spec_t          preference_spec;                     /* SR Policy preference generation mode   */
    bgp_u32_optional_spec_t          binding_sid_spec;                    /* SR Policy binding-SID generation mode  */
    bgp_ext_comm_t                   rt_values[MAX_RTS];                  /* Fixed route-target set                 */
    uint32_t                         rt_count;                            /* Number of fixed route-target values    */
    uint32_t                         rt_set_count;                        /* Number of route-target sets            */
    uint32_t                         rt_set_group_count;                  /* Stored RT-set sequence groups          */
    uint32_t                         community_group_count;               /* Number of community groups             */
    uint32_t                         large_community_group_count;         /* Number of large-community groups       */
    bgp_ext_comm_t                   soo_values[MAX_SOOS];                /* Site-of-origin rotation values         */
    uint32_t                         soo_count;                           /* Number of site-of-origin values        */
    bgp_ext_comm_t                   encap_values[MAX_ENCAPS];            /* Encapsulation EC rotation values       */
    uint32_t                         encap_count;                         /* Number of Encapsulation EC values      */
    bgp_ext_comm_t                   router_mac_values[MAX_ROUTER_MACS];  /* EVPN Router's MAC EC rotation values   */
    uint32_t                         router_mac_count;                    /* Number of EVPN Router's MAC EC values  */
    uint32_t                         distinguisher_count;                 /* Number of SR Policy distinguishers     */
    uint8_t                          distinguisher_rotate;                /* Distinguishers rotate per path         */
    uint32_t                         color_count;                         /* Number of colors                       */
    uint8_t                          color_rotate;                        /* SR Policy colors rotate per path       */
    uint8_t                          color_set;                           /* All configured Colors on each path     */
    uint32_t                         enlp_count;                          /* Number of SR Policy ENLP values        */
    uint32_t                         priority_count;                      /* Number of SR Policy priority values    */
    uint32_t                         preference_count;                    /* Number of SR Policy preferences        */
    uint32_t                         binding_sid_count;                   /* Number of SR-MPLS binding SID labels   */
    bgp_next_hop_spec_t              binding_sid_srv6_spec;               /* SRv6 Binding SID generation spec       */
    bgp_ribout_sr_binding_sid_kind_t binding_sid_kind;                    /* SR Binding SID encoding flavor         */
    uint32_t                         segment_list_count;                  /* Number of SR Policy segment-lists      */
#define RIBOUT_DECLARE_ARRAY(type, field, count) type *field; int field##_capacity;
    BGP_RIBOUT_OWNED_ARRAYS(RIBOUT_DECLARE_ARRAY)
#undef RIBOUT_DECLARE_ARRAY
#define RIBOUT_DECLARE_STEP(type, field, count) uint32_t field##_step;
    BGP_RIBOUT_U32_ARRAYS(RIBOUT_DECLARE_STEP)
#undef RIBOUT_DECLARE_STEP
    uint32_t                    rds_step;
    uint16_t                    address_family_afi;   /* address-family AFI, 0 = infer        */
    uint8_t                     address_family_safi;  /* address-family SAFI                  */
    bgp_ribout_flowspec_t      *flowspec;             /* FlowSpec lines, set by the first one */
    bgp_origin_t                origin;               /* Origin attribute                     */
    bgp_ribout_template_t       nlri_template;
    uint8_t                     family_attr[512];     /* PMSI or BGP-LS attribute value       */
    uint16_t                    family_attr_len;
    uint8_t                     family_attr_type;
    char                        family_attr_text[1024];
    bgp_ext_comm_t              l2_info;
    char                        l2_info_text[128];
    bgp_ribout_map_t           *ribout;               /* Generated RibOut map (temporary)     */
    bgp_msg_t                  *messages;             /* UPDATEs of snapshot (snapshot owns)  */
    size_t                      message_count;        /* Number of messages in snapshot       */
    int                         dirty;                /* Config changed, needs regeneration   */
    struct bgp_ribout_snapshot *snapshot;             /* Current published snapshot (one ref) */
    double                      generation_time_ms;   /* update generate time (ms)            */
    double                      generation_cpu_ms;    /* CPU time of that thread for it (ms)  */
    double                      map_time_ms;          /* Grouped ribout map build time (ms)   */
    double                      message_time_ms;      /* UPDATE serialize time (ms)           */
} bgp_ribout_config_t;

// The configuration part precedes the generated products. Owned pointers require deep copy or transfer.
#define BGP_RIBOUT_CONFIG_SIZE offsetof(bgp_ribout_config_t, ribout)

/*
 * A sequence stores one base value; step zero denotes an explicit inventory.
 * Callers use accessors so generation, display and key comparison never expand it.
 */
static inline uint32_t bgp_u32_value(const uint32_t *values, uint32_t step, uint32_t index) {
    return step ? values[0] + step * index : values[index];
}
#define RIBOUT_U32_ACCESSOR(type, field, count)                                                        \
    static inline uint32_t bgp_ribout_##field##_at(const bgp_ribout_config_t *block, uint32_t index) { \
        return bgp_u32_value(block->field, block->field##_step, index);                                \
    }
BGP_RIBOUT_U32_ARRAYS(RIBOUT_U32_ACCESSOR)
#undef RIBOUT_U32_ACCESSOR

static inline uint8_t bgp_ribout_color_co_at(const bgp_ribout_config_t *block, uint32_t index) {
    return block->color_co[block->colors_step ? 0 : index];
}

static inline route_distinguisher_t bgp_ribout_rds_at(const bgp_ribout_config_t *block, uint32_t index) {
    route_distinguisher_t rd = block->rds[block->rds_step ? 0 : index];
    /*
     * RD sequences advance only the assigned-number field, never the administrator.
     * Parsing validates its last value before publishing the compact sequence.
     */
    if (block->rds_step) {
        unsigned admin_bytes = rd.type == 0 ? 2 : 4;
        (void)bytes_be_add(rd.value + admin_bytes, 6 - admin_bytes, index, 0);
    }
    return rd;
}

/*
 * One emitted path from the ribout generator before grouping.
 */
typedef struct {
    bgp_ribout_family_t   family;            /* Resolved ribout family       */

    // Prefix (binary)
    union {
        struct in_addr  ipv4;
        struct in6_addr ipv6;
    } prefix_addr;
    route_distinguisher_t rd;                /* VPN/EVPN route distinguisher */
    evpn_esi_t            esi;               /* EVPN ESI                     */
    uint32_t              label;             /* MPLS label                   */
    uint32_t              label2;            /* EVPN Type 2 optional Label2  */
    uint32_t              ethernet_tag_id;   /* EVPN Ethernet Tag ID         */
    uint32_t              path_id;           /* Path ID                      */
    uint8_t               prefix_len;        /* Prefix length                */
    uint8_t               prefix_af;         /* Address family               */
    uint8_t               has_rd;            /* VPN/EVPN route if set        */
    uint8_t               has_label;         /* Labeled-unicast NLRI if set  */
    uint8_t               has_label2;        /* EVPN Type 2 Label2 if set    */
    uint8_t               label_vni;         /* EVPN labels are VNIs if set  */
    uint8_t               has_ethernet_tag;  /* EVPN Ethernet Tag if set     */
    uint8_t               has_esi;           /* EVPN ESI if set              */
    uint8_t               mac_addr[6];       /* EVPN Type 2 MAC address      */
    uint8_t               has_mac;           /* EVPN Type 2 MAC is set       */

    // EVPN Type 2 optional IP (binary)
    union {
        struct in_addr  ipv4;
        struct in6_addr ipv6;
    } ip_addr;
    uint8_t ip_af;   /* EVPN Type 2 IP address family */
    uint8_t has_ip;  /* EVPN Type 2 IP is set         */

    // Gateway IP (binary)
    union {
        struct in_addr  ipv4;
        struct in6_addr ipv6;
    } gateway_ip_addr;
    uint8_t gateway_ip_af;   /* Gateway IP address family */
    uint8_t has_gateway_ip;  /* EVPN gateway IP if set    */

    // Next-hop (binary)
    union {
        struct in_addr  ipv4;
        struct in6_addr ipv6;
    } next_hop_addr;
    struct in6_addr next_hop_link_local;      /* IPv6 link-local companion */
    uint8_t         next_hop_af;              /* Next-hop address family   */
    uint8_t         next_hop_has_link_local;  /* IPv6 link-local if set    */

    // FlowSpec NLRI: the instance number decodes to the prefix and component positions
    uint64_t flowspec_instance;  /* bgp_ribout_flowspec_materialize() instance  */
    uint8_t  has_flowspec;       /* FlowSpec NLRI is set                        */
    uint64_t template_instance;  /* Instance of the block's typed NLRI template */

    // SR Policy NLRI
    uint32_t distinguisher;  /* SR Policy distinguisher */
    uint32_t color;          /* SR Policy color         */
    union {
        struct in_addr  ipv4;
        struct in6_addr ipv6;
    } endpoint_addr;
    uint8_t endpoint_af;   /* SR Policy endpoint AF */
    uint8_t has_endpoint;  /* SR Policy endpoint    */

    // SR Policy attributes
    uint32_t               preference;       /* Candidate-path preference       */
    srpolicy_binding_sid_t binding_sid;      /* Binding SID payload choice      */
    uint8_t                has_enlp;         /* ENLP value is configured        */
    uint8_t                enlp;             /* ENLP value                      */
    uint8_t                has_priority;     /* Priority value is configured    */
    uint8_t                priority;         /* Priority value                  */
    uint8_t                has_preference;   /* Preference value is configured  */
    uint8_t                has_binding_sid;  /* Binding SID value is configured */

    /*
     * Path attributes. aspath_segments points at the block's segments, or, when a segment is random, at the
     * generator's copy for this path: it stays valid until the next path from the same generator.
     */
    const bgp_aspath_segment_t *aspath_segments;
    uint8_t                     ext_comm_data[MAX_EXT_COMMS_PER_ROUTE * 8];
    uint8_t                     ipv6_ext_comm_data[MAX_IPV6_EXT_COMMS_PER_ROUTE * 20];
    uint8_t                     community_data[MAX_COMMUNITIES_PER_SET * 4];               /* COMMUNITIES value       */
    uint8_t                     large_community_data[MAX_LARGE_COMMUNITIES_PER_SET * 12];  /* LARGE_COMMUNITY value   */
    uint32_t                    aspath_segment_count;                                      /* Number of AS path segments */
    uint16_t                    ext_comm_len;                                              /* Encoded extended-community byte count */
    uint16_t                    ipv6_ext_comm_len;                                         /* Encoded attribute 25 byte count */
    uint16_t                    community_len;                                             /* Octets in community_data (0: none) */
    uint16_t                    large_community_len;                                       /* Octets in large_community_data */
    uint32_t                    local_pref;                                                /* Local preference        */
    uint32_t                    med;                                                       /* MED value               */
    uint8_t                     has_med;                                                   /* MED attribute if set    */
    bgp_origin_t                origin;                                                    /* Origin attribute        */
} bgp_gen_path_t;

/*
 * rotate-every: the attribute rotation state at the start of the current block of paths, which every path of the
 * block starts from (bgp_ribout_generator_next()).
 */
typedef struct {
    uint32_t next_hop, rt_set, soo, encap, router_mac, color, localpref, med, enlp, priority, preference;
    uint32_t binding_sid, label, label2, esi, random_state;
} bgp_ribout_rotation_state_t;

/*
 * Iterator state for walking a ribout block's generated path stream.
 */
typedef struct {
    bgp_ribout_config_t        *ribout_config;              /* Configuration                                  */
    bgp_ribout_family_t         family;                     /* Resolved address-family                        */
    uint64_t                    total_paths;                /* Total paths to generate                        */
    uint64_t                    paths_generated;            /* Number of paths generated                      */
    uint32_t                    current_prefix_idx;         /* Current prefix index                           */
    uint32_t                    current_rd_idx;             /* Current RD index                               */
    uint32_t                    current_ethernet_tag_idx;   /* Current Ethernet Tag index                     */
    uint32_t                    current_mac_idx;            /* Current EVPN Type 2 MAC idx                    */
    uint64_t                    current_ip_idx;             /* Index across both Type 2 IP families           */
    uint32_t                    current_gateway_ip_idx;     /* Current gateway IP index                       */
    uint32_t                    current_esi_idx;            /* Current ESI index                              */
    uint32_t                    current_label_idx;          /* Current label index                            */
    uint32_t                    current_label2_idx;         /* Current EVPN Type 2 Label2 idx                 */
    uint32_t                    current_distinguisher_idx;  /* Current SR distinguisher                       */
    uint32_t                    current_color_idx;          /* Current SR color index                         */
    uint32_t                    current_endpoint_idx;       /* Current SR endpoint index                      */
    uint32_t                    current_path_id_idx;        /* Current path-id index                          */
    uint32_t                    current_next_hop_idx;       /* Current next-hop index                         */
    uint32_t                    current_rt_set_idx;         /* Current RT-set index                           */
    uint32_t                    current_soo_idx;            /* Current SoO index                              */
    uint32_t                    current_encap_idx;          /* Current Encapsulation EC idx                   */
    uint32_t                    current_router_mac_idx;     /* Current Router's MAC EC idx                    */
    uint32_t                    current_localpref_idx;      /* Current localpref index                        */
    uint32_t                    current_med_idx;            /* Current MED index                              */
    uint32_t                    current_enlp_idx;           /* Current SR ENLP idx                            */
    uint32_t                    current_priority_idx;       /* Current SR priority idx                        */
    uint32_t                    current_preference_idx;     /* Current SR preference idx                      */
    uint32_t                    current_binding_sid_idx;    /* Current SR binding SID idx                     */
    uint64_t                    current_flowspec_instance;  /* Current FlowSpec NLRI instance                 */
    uint32_t                    random_state;               /* Deterministic PRNG state                       */
    bgp_ribout_rotation_state_t rotation_saved;             /* rotate-every: state at the block start         */
    uint64_t                    community_sets;             /* bgp_ribout_community_sets() of the block       */
    uint64_t                    large_community_sets;       /* bgp_ribout_large_community_sets() of the block */
    int                         initialized;                /* Generator initialized flag                     */
    int                         aspath_has_random;          /* A segment is rand(): copy it                   */
    // Per-path AS-path copy, used only when a segment is random (the random values change per path).
    bgp_aspath_segment_t        aspath_scratch[MAX_ASPATH_SEGMENTS];
} bgp_ribout_gen_t;

/*
 * bgp_ribout.h includes bgp_ribout_config.h for the config types, and this
 * header needs bgp_ribout.h for the map/message API.  The late include here
 * breaks the cycle: bgp_ribout_config_t is fully defined above, so
 * bgp_ribout.h can use it when it gets included.
 */
#include "bgp_ribout.h"

// Function Declarations

/*
 * Initialize ribout block with default values
 */
int bgp_ribout_parse_rd_value(const char *text, route_distinguisher_t *rd);
int bgp_ribout_has_srpolicy_tokens(const bgp_ribout_config_t *block);
int bgp_ribout_parse_esi_value(const char *text, evpn_esi_t *esi);
int bgp_ribout_parse_ext_comm_value(const char *text, uint8_t subtype, bgp_ext_comm_t *value);
int bgp_ribout_parse_nlri(bgp_ribout_config_t *block, const char *line);
int bgp_ribout_parse_family_attr(bgp_ribout_config_t *block, const char *line);
int bgp_ribout_template_validate(const bgp_ribout_config_t *block);
int bgp_ribout_template_encode(const bgp_ribout_template_t *spec, uint64_t instance, uint8_t *buffer);
void bgp_ribout_template_describe(const bgp_ribout_template_t *spec, uint64_t instance, char *buffer, size_t len);
int bgp_ribout_template_compare_keys(const bgp_ribout_template_t *a, const bgp_ribout_template_t *b, int equal);

static inline int bgp_ribout_name_valid(const char *name) {
    return config_name_valid(name, BGP_RIBOUT_NAME_SIZE);
}
int bgp_ribout_init(bgp_ribout_config_t *block, const char *name);
/*
 * User/config edits are atomic and mark derived products dirty on success.
 * The parse helpers below are leaf parsers for candidates, not live edits.
 */
int bgp_ribout_edit(bgp_ribout_config_t *block, const char *keyword, const char *value, int clear);
void bgp_ribout_destroy(bgp_ribout_config_t *block);
void bgp_ribout_move(bgp_ribout_config_t *dst, bgp_ribout_config_t *src);
/*
 * A heap copy of the configuration part of block, with its own FlowSpec part and no generated products. NULL when
 * there is no memory. Free it with bgp_ribout_config_clone_free().
 */
bgp_ribout_config_t *bgp_ribout_config_clone(const bgp_ribout_config_t *block);
void bgp_ribout_config_clone_free(bgp_ribout_config_t *clone);
/*
 * Transfer configuration ownership, preserving dst's generated products.
 */
void bgp_ribout_config_take(bgp_ribout_config_t *dst, bgp_ribout_config_t *src);
uint64_t bgp_ribout_config_bytes(const bgp_ribout_config_t *block);

/*
 * Add <blocks> prefix-sized blocks to a network-order address, that is
 * blocks * 2^(address bits - prefix_len). Returns -1 when the result runs
 * past the top of the address space. Inline: the generator calls it per path.
 */
static inline int bgp_ribout_prefix_advance(int af, void *addr, uint8_t prefix_len, uint32_t blocks) {
    unsigned addr_bits = (af == AF_INET) ? 32 : 128;

    if (prefix_len > addr_bits) {
        return -1;
    }

    return bytes_be_add(addr, addr_bits / 8, blocks, addr_bits - prefix_len);
}

/*
 * Parse configuration attributes
 */
int bgp_ribout_parse_prefix(bgp_ribout_config_t *block, const char *line);
int bgp_ribout_parse_rd(bgp_ribout_config_t *block, const char *line);
int bgp_ribout_parse_label(bgp_ribout_config_t *block, const char *line);
int bgp_ribout_parse_label2(bgp_ribout_config_t *block, const char *line);
int bgp_ribout_parse_ethernet_tag(bgp_ribout_config_t *block, const char *line);
int bgp_ribout_parse_mac(bgp_ribout_config_t *block, const char *line);
int bgp_ribout_parse_ip(bgp_ribout_config_t *block, const char *line);
int bgp_ribout_parse_path_ids(bgp_ribout_config_t *block, const char *line);
int bgp_ribout_parse_next_hop(bgp_ribout_config_t *block, const char *line);
int bgp_ribout_parse_gateway_ip(bgp_ribout_config_t *block, const char *line);
int bgp_ribout_parse_esi(bgp_ribout_config_t *block, const char *line);
int bgp_ribout_parse_aspath(bgp_ribout_config_t *block, const char *line);
int bgp_ribout_parse_localpref(bgp_ribout_config_t *block, const char *line);
int bgp_ribout_parse_med(bgp_ribout_config_t *block, const char *line);
int bgp_ribout_parse_rt(bgp_ribout_config_t *block, const char *line);
int bgp_ribout_parse_rt_set(bgp_ribout_config_t *block, const char *line);
/*
 * Requires index < rt_set_count; returns the generated set by value, not a borrowed inventory pointer.
 */
bgp_rt_set_spec_t bgp_ribout_rt_set_at(const bgp_ribout_config_t *block, uint32_t index);
/*
 * "community <set> [<set> ...]" and "large-community <set> ...": a set is [v,v,...] or one value, optionally followed
 * by "x <count>". Lines append. Community values are <0-65535>:<0-65535> or a well-known name; large-community values
 * are <u32>:<u32>:<u32>.
 */
int bgp_ribout_parse_community(bgp_ribout_config_t *block, const char *line);
int bgp_ribout_parse_large_community(bgp_ribout_config_t *block, const char *line);
/*
 * Sets the groups make (the sum of their repeats); 0 without groups.
 */
uint64_t bgp_ribout_community_sets(const bgp_ribout_config_t *block);
uint64_t bgp_ribout_large_community_sets(const bgp_ribout_config_t *block);
/*
 * Write the values of community set number index (of bgp_ribout_community_sets()) to out, 4 octets each in network
 * order; returns the octet count.
 */
uint16_t bgp_ribout_community_set_encode(const bgp_ribout_config_t *block, uint64_t index, uint8_t *out);
uint16_t bgp_ribout_large_community_set_encode(const bgp_ribout_config_t *block, uint64_t index, uint8_t *out);
/*
 * The name of a well-known community (RFC 1997, RFC 7999, RFC 8326, RFC 9494 ...), or NULL.
 */
const char *bgp_community_well_known_name(uint32_t value);
int bgp_ribout_parse_rotate_every(bgp_ribout_config_t *block, const char *line);
int bgp_ribout_parse_rotate_period(bgp_ribout_config_t *block, const char *line);
int bgp_ext_comm_local_admin_add(bgp_ext_comm_t *ext_comm, uint32_t delta);
int bgp_ribout_parse_soo(bgp_ribout_config_t *block, const char *line);
int bgp_ribout_parse_encap(bgp_ribout_config_t *block, const char *line);
int bgp_ribout_parse_router_mac(bgp_ribout_config_t *block, const char *line);
int bgp_ribout_parse_origin(bgp_ribout_config_t *block, const char *line);
int bgp_ribout_parse_distinguisher(bgp_ribout_config_t *block, const char *line);
/*
 * The family decides the meaning of "color": SR Policy NLRI color, or Color communities.
 * "color set ..." carries every value on each non-SR-Policy path; ordinary lists rotate one value per path.
 */
int bgp_ribout_parse_color(bgp_ribout_config_t *block, const char *line);
/*
 * The CO bits text, "00" to "11", of a Color-Only type.
 */
const char *bgp_ribout_co_bits_text(uint8_t co_type);
int bgp_ribout_parse_endpoint(bgp_ribout_config_t *block, const char *line);
int bgp_ribout_parse_enlp(bgp_ribout_config_t *block, const char *line);
int bgp_ribout_parse_priority(bgp_ribout_config_t *block, const char *line);
int bgp_ribout_parse_preference(bgp_ribout_config_t *block, const char *line);
int bgp_ribout_parse_binding_sid(bgp_ribout_config_t *block, const char *line);
int bgp_ribout_parse_segment_list(bgp_ribout_config_t *block, const char *line);
int bgp_ribout_parse_address_family(bgp_ribout_config_t *block, const char *line);
bgp_ribout_family_t bgp_ribout_resolve_family(const bgp_ribout_config_t *block);
// AFI/SAFI that a ribout family sends; -1 for BGP_RIBOUT_FAMILY_NONE.

/*
 * Shared value parsers for the ribout grammar (also used by the FlowSpec
 * rule and action parser).
 */

/*
 * "<keyword> <IP/len>[-<len>] [x <count>]": offset_out NULL rejects the IPv6
 * "/offset-length" form (RFC 8956 section 3.1).
 */
int bgp_ribout_parse_prefix_spec(const char *keyword, const char *line,
                                 bgp_prefix_spec_t *spec_out, uint8_t *offset_out);

/*
 * One "<admin>:<assigned>" value (RD, RT, SoO, FlowSpec redirect-to-VRF).
 */
typedef enum {
    BGP_RIBOUT_ADMIN_AS2  = 0,  /* 2-octet AS : 4-octet number   */
    BGP_RIBOUT_ADMIN_IPV4 = 1,  /* IPv4 address : 2-octet number */
    BGP_RIBOUT_ADMIN_AS4  = 2   /* 4-octet AS : 2-octet number   */
} bgp_ribout_admin_form_t;

typedef struct {
    bgp_ribout_admin_form_t form;
    uint32_t                admin;     /* AS number, or IPv4 address in host order */
    uint32_t                assigned;  /* Assigned number                          */
} bgp_ribout_admin_pair_t;

/*
 * Parse "<admin>:<assigned>" (an RD, RT, SoO or redirect-vrf target). The admin
 * form picks the layout: dotted IPv4, a number above 65535 (4-octet AS), or a
 * 2-octet AS. Returns -1 when assigned does not fit its form.
 */
int bgp_ribout_parse_admin_pair(const char *text, bgp_ribout_admin_pair_t *pair_out);
/*
 * One-community attribute for an admin pair: Type type_base + form, sub_type
 * as given (RFC 4360, RFC 5668). The caller owns the attribute.
 */
bgp_path_attr_t *bgp_ribout_admin_pair_ext_comm(const bgp_ribout_admin_pair_t *pair,
                                                uint8_t type_base, uint8_t sub_type);
/*
 * Take one 8-octet community out of a library attribute (frees attr).
 */
int bgp_ribout_copy_single_ext_comm_attr(const char *value_name, bgp_path_attr_t *attr, bgp_ext_comm_t *ext_comm_out);

/*
 * FlowSpec lines: "src-prefix", the operator components and the "action" lines
 * of a block ("prefix" is the destination prefix). Parsing and canonical text
 * live here; the wire format stays with bgp_update_flowspec.c.
 */

// Components in one materialized NLRI: types 1-13, at most once each.
#define BGP_RIBOUT_FLOWSPEC_MAX_COMPONENTS FLOWSPEC_FLOW_LABEL

/*
 * One generated FlowSpec NLRI as a library rule. A stepped value changes from NLRI to NLRI, so it is a copy in
 * values; the other operator lists point into the block, so the block must outlive the NLRI.
 */
typedef struct {
    flowspec_component_t comps[BGP_RIBOUT_FLOWSPEC_MAX_COMPONENTS];
    flowspec_op_value_t  values[BGP_RIBOUT_FLOWSPEC_MAX_COMPONENTS][MAX_FLOWSPEC_OPS];
    flowspec_rule_t      rule;
} bgp_ribout_flowspec_nlri_t;

/*
 * The FlowSpec part of a block, allocated by the first call; NULL with an error when there is no memory.
 */
bgp_ribout_flowspec_t *bgp_ribout_flowspec_get(bgp_ribout_config_t *block);
/*
 * 1 when the block has a FlowSpec-only line: src-prefix, an operator component or an action.
 */
int bgp_ribout_has_flowspec_tokens(const bgp_ribout_config_t *block);

/*
 * "<keyword> <args>" with keyword "src-prefix" or one of BGP_RIBOUT_FLOWSPEC_OP_COMPONENTS. parse_component replaces
 * the component and returns 0, or returns -1 with an error and leaves the block unchanged; the library checks the
 * RFC 8955 / RFC 8956 encoding rules. clear_component removes one component.
 */
int bgp_ribout_flowspec_parse_component(bgp_ribout_config_t *block, const char *keyword, const char *args);
int bgp_ribout_flowspec_clear_component(bgp_ribout_config_t *block, const char *keyword);

/*
 * "action <args>" lines (args without the "action" word). parse_action adds one line and returns 0, or returns -1
 * with an error and leaves the block unchanged. clear_actions removes all lines.
 */
int bgp_ribout_flowspec_parse_action(bgp_ribout_config_t *block, const char *args);
void bgp_ribout_flowspec_clear_actions(bgp_ribout_config_t *block);

/*
 * Canonical text. component_keyword names a component type ("prefix" for type 1). component_to_string writes
 * "<keyword> <args>" for types 2-13 as running-config prints it, and returns 0 when the component is not set.
 * nlri_to_string writes one generated NLRI and actions_to_string the action values of one path, "; "-joined, both for
 * the preview. Parsing the canonical text gives the same lines.
 */
const char *bgp_ribout_flowspec_component_keyword(uint8_t type);
int bgp_ribout_flowspec_component_to_string(const bgp_ribout_config_t *block, uint8_t type, char *buf, size_t len);
void bgp_ribout_flowspec_nlri_to_string(const bgp_ribout_config_t *block, uint64_t instance, char *buf, size_t len);
void bgp_ribout_flowspec_actions_to_string(const bgp_ribout_config_t *block, uint64_t path_index, char *buf,
                                           size_t len);

/*
 * The instance space: the destination and source prefix counts times the count of every component, rotating or not
 * (0 on overflow). Instance numbers run 0 to that count - 1; the last component steps fastest, the destination
 * slowest.
 */
uint64_t bgp_ribout_flowspec_instances(const bgp_ribout_config_t *block);
/*
 * NLRIs the block generates: as instances, but a rotating component counts once (0 on overflow).
 */
uint64_t bgp_ribout_flowspec_rules(const bgp_ribout_config_t *block);
/*
 * The instance of generated rule number rule (counted over the components that do not rotate) at rotation step
 * rotation: each rotating component takes its value number rotation mod its count.
 */
uint64_t bgp_ribout_flowspec_rule_instance(const bgp_ribout_config_t *block, uint64_t rule, uint64_t rotation);
/*
 * Build one NLRI. materialize_longest builds the NLRI with the longest wire form. Return -1 when the block has no
 * component.
 */
int bgp_ribout_flowspec_materialize(const bgp_ribout_config_t *block, uint64_t instance,
                                    bgp_ribout_flowspec_nlri_t *out);
int bgp_ribout_flowspec_materialize_longest(const bgp_ribout_config_t *block, bgp_ribout_flowspec_nlri_t *out);
/*
 * The community value of an action line on one path: the values rotate. Writes value_len octets.
 */
const uint8_t *bgp_ribout_flowspec_action_value(const bgp_ribout_flowspec_line_t *line, uint64_t path_index);
/*
 * AF of the destination and source prefixes: AF_INET, AF_INET6, 0 (no prefix), or -1 (mixed).
 */
int bgp_ribout_flowspec_af(const bgp_ribout_config_t *block);

#endif /* BGP_RIBOUT_CONFIG_H */
