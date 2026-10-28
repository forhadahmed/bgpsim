#ifndef BGP_UPDATE_H
#define BGP_UPDATE_H

#include <stdint.h>
#include <netinet/in.h>

// BGP Path Attribute Types (RFC 4271)
#define BGP_ATTR_ORIGIN           1
#define BGP_ATTR_AS_PATH          2
#define BGP_ATTR_NEXT_HOP         3
#define BGP_ATTR_MULTI_EXIT_DISC  4
#define BGP_ATTR_LOCAL_PREF       5
#define BGP_ATTR_ATOMIC_AGGREGATE 6
#define BGP_ATTR_AGGREGATOR       7
#define BGP_ATTR_COMMUNITIES      8
#define BGP_ATTR_MP_REACH_NLRI    14
#define BGP_ATTR_MP_UNREACH_NLRI  15
#define BGP_ATTR_EXT_COMM         16
#define BGP_ATTR_AS4_PATH         17
#define BGP_ATTR_AS4_AGGREGATOR   18
#define BGP_ATTR_TUNNEL_ENCAP     23
#define BGP_ATTR_IPV6_EXT_COMM    25
#define BGP_ATTR_BGP_LS           29
#define BGP_ATTR_LARGE_COMMUNITY  32

// BGP Path Attribute Flags
#define BGP_ATTR_FLAG_OPTIONAL     0x80
#define BGP_ATTR_FLAG_TRANSITIVE   0x40
#define BGP_ATTR_FLAG_PARTIAL      0x20
#define BGP_ATTR_FLAG_EXTENDED_LEN 0x10

// BGP ORIGIN values
#define BGP_ORIGIN_IGP        0
#define BGP_ORIGIN_EGP        1
#define BGP_ORIGIN_INCOMPLETE 2

// BGP AS_PATH segment types
#define BGP_AS_SET      1
#define BGP_AS_SEQUENCE 2

/*
 * AFI/SAFI constants, BGP message types, and AS_TRANS live in bgp.h.
 * This header uses them via transitive includes.
 */

// FlowSpec component types (RFC 8955)
#define FLOWSPEC_DEST_PREFIX 1
#define FLOWSPEC_SRC_PREFIX  2
#define FLOWSPEC_IP_PROTOCOL 3
#define FLOWSPEC_PORT        4
#define FLOWSPEC_DEST_PORT   5
#define FLOWSPEC_SRC_PORT    6
#define FLOWSPEC_ICMP_TYPE   7
#define FLOWSPEC_ICMP_CODE   8
#define FLOWSPEC_TCP_FLAGS   9
#define FLOWSPEC_PACKET_LEN  10
#define FLOWSPEC_DSCP        11
#define FLOWSPEC_FRAGMENT    12
#define FLOWSPEC_FLOW_LABEL  13  /* IPv6 only (RFC 8956) */

// Largest FlowSpec NLRI value: the 2-octet length form has 12 bits.
#define FLOWSPEC_MAX_NLRI_LEN 4095

// FlowSpec operator bits
#define FLOWSPEC_OP_END   0x80
#define FLOWSPEC_OP_AND   0x40
#define FLOWSPEC_OP_LEN_1 0x00
#define FLOWSPEC_OP_LEN_2 0x10
#define FLOWSPEC_OP_LEN_4 0x20
#define FLOWSPEC_OP_LEN_8 0x30
#define FLOWSPEC_OP_LT    0x04
#define FLOWSPEC_OP_GT    0x02
#define FLOWSPEC_OP_EQ    0x01
// Bitmask operator bits
#define FLOWSPEC_OP_NOT   0x02
#define FLOWSPEC_OP_MATCH 0x01
// Operator bits that must be zero (RFC 8955 section 4.2.1)
#define FLOWSPEC_NUMERIC_OP_RESERVED 0x08
#define FLOWSPEC_BITMASK_OP_RESERVED 0x0c

// TCP flag bitmask values (type 9)
#define FLOWSPEC_TCP_FIN 0x01
#define FLOWSPEC_TCP_SYN 0x02
#define FLOWSPEC_TCP_RST 0x04
#define FLOWSPEC_TCP_PSH 0x08
#define FLOWSPEC_TCP_ACK 0x10
#define FLOWSPEC_TCP_URG 0x20
#define FLOWSPEC_TCP_ECE 0x40
#define FLOWSPEC_TCP_CWR 0x80

// Fragment bitmask values (type 12). DF is IPv4 only (RFC 8956 3.6).
#define FLOWSPEC_FRAG_DF  0x01
#define FLOWSPEC_FRAG_ISF 0x02
#define FLOWSPEC_FRAG_FF  0x04
#define FLOWSPEC_FRAG_LF  0x08

// Color Extended Community Color-Only types (RFC 9830 section 3)
#define BGP_COLOR_CO_SPECIFIC 0  /* 00: specific endpoint          */
#define BGP_COLOR_CO_NULL     1  /* 01: specific or null endpoint  */
#define BGP_COLOR_CO_ANY      2  /* 10: specific, null, or any     */
#define BGP_COLOR_CO_RESERVED 3  /* 11: SHOULD NOT send; read as 0 */

// Color flags field for a Color-Only type: the type is in the two high-order bits.
#define BGP_COLOR_CO_FLAGS(co_type) ((uint16_t)(((uint16_t)(co_type) & 0x3u) << 14))

// EVPN Route Types
#define EVPN_RT_ETHERNET_AUTO_DISCOVERY 1
#define EVPN_RT_MAC_IP_ADVERTISEMENT    2
#define EVPN_RT_INCLUSIVE_MULTICAST     3
#define EVPN_RT_ETHERNET_SEGMENT        4
#define EVPN_RT_IP_PREFIX               5

// MVPN Route Types (RFC 6514)
#define MVPN_RT_INTRA_AS_IPMSI_AD 1
#define MVPN_RT_INTER_AS_IPMSI_AD 2
#define MVPN_RT_SPMSI_AD          3
#define MVPN_RT_LEAF_AD           4
#define MVPN_RT_SOURCE_ACTIVE_AD  5
#define MVPN_RT_SHARED_TREE_JOIN  6
#define MVPN_RT_SOURCE_TREE_JOIN  7

// BGP Path Attribute for PMSI Tunnel (RFC 6514)
#define BGP_ATTR_PMSI_TUNNEL            22

// BGP-LS NLRI Types (RFC 9552)
#define BGPLS_NLRI_NODE        1
#define BGPLS_NLRI_LINK        2
#define BGPLS_NLRI_IPV4_PREFIX 3
#define BGPLS_NLRI_IPV6_PREFIX 4

// BGP-LS Descriptor TLV Types (RFC 9552)
#define BGPLS_TLV_LOCAL_NODE_DESC    256
#define BGPLS_TLV_REMOTE_NODE_DESC   257
#define BGPLS_TLV_LINK_LOCAL_REMOTE  258
#define BGPLS_TLV_IPV4_IFACE_ADDR    259
#define BGPLS_TLV_IPV4_NEIGHBOR_ADDR 260
#define BGPLS_TLV_IPV6_IFACE_ADDR    261
#define BGPLS_TLV_IPV6_NEIGHBOR_ADDR 262
#define BGPLS_TLV_MT_ID              263
#define BGPLS_TLV_OSPF_ROUTE_TYPE    264
#define BGPLS_TLV_IP_REACH_INFO      265
#define BGPLS_TLV_AS                 512
#define BGPLS_TLV_BGPLS_ID           513
#define BGPLS_TLV_OSPF_AREA          514
#define BGPLS_TLV_IGP_ROUTER_ID      515

// BGP-LS Protocol IDs (RFC 9552)
#define BGPLS_PROTO_ISIS_L1 1
#define BGPLS_PROTO_ISIS_L2 2
#define BGPLS_PROTO_OSPFV2  3
#define BGPLS_PROTO_DIRECT  4
#define BGPLS_PROTO_STATIC  5
#define BGPLS_PROTO_OSPFV3  6

// Default BGP maximum PDU size
#define BGP_MAX_PDU_SIZE 4096
#define BGP_HEADER_SIZE  19
// Header + withdrawn len + attr len
#define BGP_UPDATE_MIN_SIZE         (BGP_HEADER_SIZE + 4)
/*
 * Split generators budget NLRI payload against the worst-case serialized MP
 * attribute framing so they do not need to predict whether the MP attribute
 * itself crosses the 255-byte threshold and flips into extended-length form.
 */
#define BGP_MP_ATTR_HEADER_MAX_SIZE 4
#define BGP_MP_UNREACH_FIXED_SIZE   3
#define BGP_MP_REACH_FIXED_SIZE(nh_len) (2 + 1 + 1 + (nh_len) + 1)

/*
 * Scratch buffers are sized to the strict maximum next-hop forms accepted by
 * each encoder family:
 * - standard MP next hop: IPv6 global + link-local = 32 bytes
 * - EVPN next hop: RFC 7432 helper only permits IPv4 (4) or IPv6 (16)
 * - VPN next hop: zero RD(8) + global(16) + optional zero RD(8) + ll(16)
 */
#define BGP_STANDARD_NEXT_HOP_BUF_SIZE 32
#define BGP_EVPN_NEXT_HOP_BUF_SIZE     16
#define BGP_VPN_NEXT_HOP_BUF_SIZE      48

static inline int bgp_mp_unreach_payload_budget(uint16_t max_pdu_size) {
    return (int)max_pdu_size - (BGP_UPDATE_MIN_SIZE +
                                BGP_MP_ATTR_HEADER_MAX_SIZE +
                                BGP_MP_UNREACH_FIXED_SIZE);
}

static inline int bgp_mp_reach_payload_budget(uint16_t max_pdu_size, uint16_t base_attr_len, uint8_t nh_len) {
    return (int)max_pdu_size - (BGP_UPDATE_MIN_SIZE +
                                base_attr_len +
                                BGP_MP_ATTR_HEADER_MAX_SIZE +
                                BGP_MP_REACH_FIXED_SIZE(nh_len));
}

typedef enum {
    BGP_ASN_ENCODE_2BYTE      = 0,
    BGP_ASN_ENCODE_4BYTE      = 1,
    BGP_ASN_ENCODE_TRANSITION = 2
} bgp_asn_encoding_mode_t;

typedef enum {
    BGP_VPN_TRANSPORT_IPV4 = 1,
    BGP_VPN_TRANSPORT_IPV6 = 2
} bgp_vpn_transport_t;

/*
 * Generic next-hop container shared by UPDATE attribute builders.
 */
typedef struct {
    int af;  /* AF_INET, AF_INET6, or 0 when unspecified */
    union {
        struct in_addr  ipv4;
        struct in6_addr ipv6;
    } address;
    int             has_link_local;
    struct in6_addr link_local;
} bgp_next_hop_t;

/*
 * IPv4 NLRI payload.
 */
typedef struct {
    uint8_t  prefix_len;  /* CIDR prefix length */
    uint32_t prefix;      /* Network byte order */
} ipv4_prefix_t;

/*
 * IPv6 NLRI payload.
 */
typedef struct {
    uint8_t prefix_len;  /* CIDR prefix length */
    uint8_t prefix[16];  /* Network byte order */
} ipv6_prefix_t;

/*
 * Route distinguisher carried inside VPN NLRI.
 */
typedef struct {
    uint16_t type;      /* Type 0, 1, or 2 (network byte order on wire) */
    uint8_t  value[6];  /* Type-specific value                          */
} route_distinguisher_t;

/*
 * Unpacked MPLS shim fields used by labeled NLRI encoders.
 */
typedef struct {
    uint32_t label;  /* 20-bit label value      */
    uint8_t  tc;     /* Traffic class (3 bits)  */
    uint8_t  s;      /* Bottom of stack (1 bit) */
    uint8_t  ttl;    /* TTL                     */
} mpls_label_t;

/*
 * IPv4 labeled-unicast NLRI payload.
 */
typedef struct {
    uint8_t      prefix_len;  /* Total length: label(24) + prefix bits */
    mpls_label_t label;
    uint32_t     prefix;      /* IPv4 prefix, network byte order       */
} labeled_ipv4_prefix_t;

/*
 * IPv6 labeled-unicast NLRI payload.
 */
typedef struct {
    uint8_t      prefix_len;  /* Total length: label(24) + prefix bits */
    mpls_label_t label;
    uint8_t      prefix[16];  /* IPv6 prefix, network byte order       */
} labeled_ipv6_prefix_t;

/*
 * VPNv4 NLRI payload.
 */
typedef struct {
    uint8_t               prefix_len;  /* Total length: label(24) + RD(64) + prefix bits */
    mpls_label_t          label;
    route_distinguisher_t rd;
    uint32_t              prefix;      /* IPv4 prefix, network byte order                */
} vpnv4_prefix_t;

/*
 * VPNv6 NLRI payload.
 */
typedef struct {
    uint8_t               prefix_len;  /* Total length: label(24) + RD(64) + prefix bits */
    mpls_label_t          label;
    route_distinguisher_t rd;
    uint8_t               prefix[16];  /* IPv6 prefix, network byte order                */
} vpnv6_prefix_t;

/*
 * EVPN Ethernet Segment Identifier.
 */
typedef struct {
    uint8_t type;      /* ESI Type            */
    uint8_t value[9];  /* Type-specific value */
} evpn_esi_t;

/*
 * EVPN Type 1 - Ethernet Auto-Discovery route payload.
 */
typedef struct {
    uint8_t               route_type;  /* 1                                     */
    route_distinguisher_t rd;
    evpn_esi_t            esi;
    uint32_t              ethernet_tag_id;
    mpls_label_t          label;
    uint8_t               label_vni;   /* label carries a 24-bit VNI (RFC 8365) */
} evpn_type1_prefix_t;

/*
 * EVPN Type 2 - MAC/IP Advertisement route payload.
 */
typedef struct {
    uint8_t               route_type;   /* 2                                              */
    route_distinguisher_t rd;
    evpn_esi_t            esi;
    uint32_t              ethernet_tag_id;
    uint8_t               mac_addr[6];
    uint8_t               ip_addr_len;  /* 0, 32, or 128                                  */
    uint8_t               ip_addr[16];  /* IPv4 or IPv6                                   */
    mpls_label_t          label1;
    int                   has_label2;
    mpls_label_t          label2;
    uint8_t               label_vni;    /* label1 and label2 carry 24-bit VNIs (RFC 8365) */
} evpn_type2_prefix_t;

/*
 * EVPN Type 3 - Inclusive Multicast Ethernet Tag route payload.
 */
typedef struct {
    uint8_t               route_type;   /* 3         */
    route_distinguisher_t rd;
    uint32_t              ethernet_tag_id;
    uint8_t               ip_addr_len;  /* 32 or 128 */
    uint8_t               orig_router_ip[16];
} evpn_type3_prefix_t;

/*
 * EVPN Type 4 - Ethernet Segment route payload.
 */
typedef struct {
    uint8_t               route_type;   /* 4         */
    route_distinguisher_t rd;
    evpn_esi_t            esi;
    uint8_t               ip_addr_len;  /* 32 or 128 */
    uint8_t               orig_router_ip[16];
} evpn_type4_prefix_t;

/*
 * EVPN type 5 route payload.
 */
typedef struct {
    uint8_t               route_type;      /* 5                                     */
    uint8_t               af;              /* AF_INET or AF_INET6                   */
    route_distinguisher_t rd;
    evpn_esi_t            esi;
    uint32_t              ethernet_tag_id;
    uint8_t               ip_prefix_len;
    uint8_t               ip_prefix[16];   /* IPv4 or IPv6                          */
    uint8_t               gateway_ip[16];  /* Gateway IP (optional)                 */
    mpls_label_t          label;
    uint8_t               label_vni;       /* label carries a 24-bit VNI (RFC 8365) */
} evpn_type5_prefix_t;

/*
 * Generic TLV for BGP-LS encoding (RFC 9552).
 */
typedef struct bgpls_tlv {
    uint16_t          type;
    uint16_t          length;
    uint8_t          *value;
    struct bgpls_tlv *next;
} bgpls_tlv_t;

/*
 * BGP-LS NLRI payload.
 */
typedef struct {
    uint16_t     nlri_type;                /* 1=Node, 2=Link, 3=IPv4Prefix, 4=IPv6Prefix */
    uint8_t      protocol_id;
    uint64_t     identifier;
    bgpls_tlv_t *local_node_descriptors;
    bgpls_tlv_t *remote_node_descriptors;  /* Link NLRI only                             */
    bgpls_tlv_t *link_descriptors;         /* Link NLRI only                             */
    bgpls_tlv_t *prefix_descriptors;       /* Prefix NLRI only                           */
} bgpls_prefix_t;

/*
 * RTC NLRI payload (RFC 4684).
 */
typedef struct {
    uint8_t  prefix_len;       /* Zero (default) or 32-96 bits       */
    uint32_t origin_as;        /* Originating AS, network byte order */
    uint8_t  route_target[8];  /* Route Target, up to 8 bytes        */
} rtc_prefix_t;

/*
 * VPLS NLRI payload (RFC 4761).
 */
typedef struct {
    uint16_t              length;           /* NLRI length field (always 17)  */
    route_distinguisher_t rd;
    uint16_t              ve_id;            /* VE ID, network byte order      */
    uint16_t              ve_block_offset;  /* VE Block Offset, network order */
    uint16_t              ve_block_size;    /* VE Block Size, network order   */
    mpls_label_t          label_base;       /* MPLS Label Base                */
} vpls_prefix_t;

/*
 * MVPN Type 1 - Intra-AS I-PMSI A-D (RFC 6514).
 */
typedef struct {
    uint8_t               route_type;          /* 1                       */
    uint8_t               af;                  /* AF_INET or AF_INET6     */
    route_distinguisher_t rd;
    uint8_t               orig_router_ip[16];  /* Originating Router's IP */
} mvpn_type1_prefix_t;

/*
 * MVPN Type 2 - Inter-AS I-PMSI A-D (RFC 6514).
 */
typedef struct {
    uint8_t               route_type;  /* 2                             */
    route_distinguisher_t rd;
    uint32_t              source_as;   /* Source AS, network byte order */
} mvpn_type2_prefix_t;

/*
 * MVPN Type 3 - S-PMSI A-D (RFC 6514).
 */
typedef struct {
    uint8_t               route_type;          /* 3                       */
    uint8_t               af;                  /* AF_INET or AF_INET6     */
    route_distinguisher_t rd;
    uint8_t               mcast_src_len;       /* 32 or 128               */
    uint8_t               mcast_src[16];       /* Multicast Source        */
    uint8_t               mcast_grp_len;       /* 32 or 128               */
    uint8_t               mcast_grp[16];       /* Multicast Group         */
    uint8_t               orig_router_ip[16];  /* Originating Router's IP */
} mvpn_type3_prefix_t;

/*
 * MVPN Type 4 - Leaf A-D (RFC 6514).
 */
typedef struct {
    uint8_t route_type;          /* 4                          */
    uint8_t af;                  /* AF_INET or AF_INET6        */
    uint8_t route_key_len;       /* Encoded Route Key length   */
    uint8_t route_key[255];      /* Encoded Type-2/3 Route Key */
    uint8_t orig_router_ip[16];  /* Originating Router's IP    */
} mvpn_type4_prefix_t;

/*
 * MVPN Type 5 - Source Active A-D (RFC 6514).
 */
typedef struct {
    uint8_t               route_type;     /* 5                   */
    uint8_t               af;             /* AF_INET or AF_INET6 */
    route_distinguisher_t rd;
    uint8_t               mcast_src_len;  /* 32 or 128           */
    uint8_t               mcast_src[16];  /* Multicast Source    */
    uint8_t               mcast_grp_len;  /* 32 or 128           */
    uint8_t               mcast_grp[16];  /* Multicast Group     */
} mvpn_type5_prefix_t;

/*
 * MVPN Type 6/7 - C-Multicast Routes (RFC 6514).
 */
typedef struct {
    uint8_t               route_type;     /* 6 or 7                        */
    uint8_t               af;             /* AF_INET or AF_INET6           */
    route_distinguisher_t rd;
    uint32_t              source_as;      /* Source AS, network byte order */
    uint8_t               mcast_src_len;  /* 32 or 128                     */
    uint8_t               mcast_src[16];  /* RP or Source address          */
    uint8_t               mcast_grp_len;  /* 32 or 128                     */
    uint8_t               mcast_grp[16];  /* Multicast Group               */
} mvpn_cmulticast_prefix_t;

/*
 * SR Policy NLRI payload (RFC 9830, AFI 1/2 SAFI 73).
 * Fixed-size NLRI: distinguisher + color + endpoint.
 */
typedef struct {
    uint32_t distinguisher;  /* 4 bytes, host order         */
    uint32_t color;          /* 4 bytes, host order         */
    int      endpoint_af;    /* AFI_IPV4 or AFI_IPV6        */
    uint8_t  endpoint[16];   /* IPv4 (4 bytes used) or IPv6 */
} srpolicy_prefix_t;

/*
 * Linked list of SR Policy NLRI entries.
 */
typedef struct srpolicy_nlri_list {
    srpolicy_prefix_t          prefix;    /* Prefix payload                     */
    uint32_t                   path_id;   /* Host-order ADD-PATH path ID        */
    uint8_t                    add_path;  /* Encode path_id before NLRI on wire */
    struct srpolicy_nlri_list *next;      /* Next entry in list                 */
} srpolicy_nlri_list_t;

/*
 * SR segment types for Tunnel Encapsulation attribute.
 */
typedef enum {
    SR_SEGMENT_TYPE_MPLS = 0,
    SR_SEGMENT_TYPE_SRV6 = 1
} sr_segment_type_t;

/*
 * Single segment in an SR segment list.
 */
typedef struct {
    sr_segment_type_t type;     /* MPLS (4 bytes) or SRv6 (16 bytes) */
    uint8_t           sid[16];  /* SID value (4 or 16 bytes used)    */
} sr_segment_t;

/*
 * Optional SRv6 Endpoint Behavior and SID Structure block (RFC 9830).
 */
typedef struct {
    uint16_t endpoint_behavior;
    uint8_t  locator_block_len;
    uint8_t  locator_node_len;
    uint8_t  function_len;
    uint8_t  argument_len;
} srpolicy_srv6_behavior_t;

/*
 * RFC 9830 wire flag positions. Behavior-presence flags are derived from the
 * corresponding has_behavior/has_srv6_behavior fields, not caller flags.
 */
#define SRPOLICY_BSID_FLAG_S      0x80
#define SRPOLICY_BSID_FLAG_I      0x40
#define SRPOLICY_SRV6_BSID_FLAG_B 0x20
#define SRPOLICY_SEGMENT_FLAG_V   0x80
#define SRPOLICY_SEGMENT_FLAG_B   0x10

/*
 * SR Policy segment descriptor. A Type B segment can carry an SRv6 behavior.
 */
typedef struct {
    sr_segment_type_t        type;
    uint8_t                  sid[16];
    uint8_t                  flags;
    uint8_t                  has_srv6_behavior;
    srpolicy_srv6_behavior_t srv6_behavior;
} srpolicy_segment_t;

/*
 * SR Policy segment list descriptor.
 */
typedef struct {
    uint32_t                  weight;
    const srpolicy_segment_t *segments;
    int                       num_segments;
} srpolicy_segment_list_t;

typedef enum {
    SRPOLICY_BINDING_SID_NONE = 0,
    SRPOLICY_BINDING_SID_MPLS = 1,
    SRPOLICY_BINDING_SID_SRV6 = 2
} srpolicy_binding_sid_type_t;

/*
 * Legacy Binding SID sub-TLV payload choice (RFC 9830 section 2.4.2).
 */
typedef struct {
    uint8_t                     flags;
    srpolicy_binding_sid_type_t type;
    uint32_t                    mpls_label;
    uint8_t                     srv6_sid[16];
} srpolicy_binding_sid_t;

/*
 * SRv6 Binding SID sub-TLV descriptor (RFC 9830 section 2.4.3).
 */
typedef struct {
    uint8_t                  flags;
    uint8_t                  sid[16];
    uint8_t                  has_behavior;
    srpolicy_srv6_behavior_t behavior;
} srpolicy_srv6_binding_sid_t;

/*
 * Full SR Policy Tunnel Encapsulation helper input.
 */
typedef struct {
    uint8_t                            has_preference;
    uint32_t                           preference;
    uint8_t                            has_binding_sid;
    srpolicy_binding_sid_t             binding_sid;
    uint8_t                            has_enlp;
    uint8_t                            enlp;
    uint8_t                            has_priority;
    uint8_t                            priority;
    const char                        *candidate_path_name;
    const char                        *policy_name;
    const srpolicy_srv6_binding_sid_t *srv6_binding_sids;
    int                                num_srv6_binding_sids;
    const srpolicy_segment_list_t     *segment_lists;
    int                                num_segment_lists;
} srpolicy_tunnel_encap_t;

/*
 * FlowSpec operator-value pair.
 */
typedef struct {
    uint8_t  op;     /* Operator byte                                       */
    uint32_t value;  /* Numeric value (wire width derived from op len bits) */
} flowspec_op_value_t;

/*
 * FlowSpec component.
 */
typedef struct {
    uint8_t              type;           /* Component type (1-13)            */
    // For prefix types (1, 2):
    uint8_t              prefix_len;
    uint8_t              prefix_offset;  /* IPv6 FlowSpec offset, 0 for IPv4 */
    uint8_t              prefix[16];     /* IPv4 or IPv6 prefix bytes        */
    // For operator-value types (3-13):
    flowspec_op_value_t *values;
    int                  num_values;
} flowspec_component_t;

/*
 * Complete FlowSpec rule (one NLRI entry).
 */
typedef struct {
    flowspec_component_t *components;
    int                   num_components;
} flowspec_rule_t;

/*
 * FlowSpec NLRI linked list.
 */
typedef struct flowspec_nlri {
    flowspec_rule_t       rule;
    uint32_t              path_id;   /* Host-order ADD-PATH path ID        */
    uint8_t               add_path;  /* Encode path_id before NLRI on wire */
    uint8_t               has_rd;    /* VPN FlowSpec (SAFI 134) entry      */
    route_distinguisher_t rd;        /* Route Distinguisher when has_rd    */
    struct flowspec_nlri *next;      /* Next entry in list                 */
} flowspec_nlri_t;

/*
 * One Color Extended Community for FlowSpec SR-TE steering.
 */
typedef struct {
    uint32_t color;    /* Color value                                  */
    uint8_t  co_type;  /* BGP_COLOR_CO_*; only the low 2 bits are sent */
} bgp_color_spec_t;

/*
 * FlowSpec steering into an SR Policy (draft-ietf-idr-ts-flowspec-srv6-policy,
 * section 3.1.1, Mode 1): the redirect target is the policy endpoint and each
 * Color Extended Community gives one candidate Color.
 */
typedef struct {
    bgp_next_hop_t          endpoint;      /* IPv4 or IPv6 policy endpoint    */
    const bgp_color_spec_t *colors;        /* One or more Colors              */
    int                     num_colors;    /* Entries in colors               */
    int                     copy;          /* C bit: steer a copy of the flow */
    int                     via_next_hop;  /* Use 0x0800 + MP_REACH next hop  */
} bgp_flowspec_srte_t;

/*
 * One logical AS_PATH segment.
 */
typedef struct {
    uint8_t   type;        /* AS_SET or AS_SEQUENCE */
    uint8_t   length;      /* Number of AS numbers  */
    uint32_t *as_numbers;  /* Array of AS numbers   */
} as_path_segment_t;

/*
 * Generic linked-list node for caller-supplied path attributes.
 */
typedef struct bgp_path_attr {
    uint8_t               flags;
    uint8_t               type_code;
    uint16_t              length;
    uint8_t              *value;
    struct bgp_path_attr *next;
} bgp_path_attr_t;

/*
 * Linked list of IPv4 NLRI entries.
 */
typedef struct ipv4_nlri_list {
    ipv4_prefix_t          prefix;    /* Prefix payload                     */
    uint32_t               path_id;   /* Host-order ADD-PATH path ID        */
    uint8_t                add_path;  /* Encode path_id before NLRI on wire */
    struct ipv4_nlri_list *next;      /* Next entry in list                 */
} ipv4_nlri_list_t;

/*
 * Linked list of IPv6 unicast NLRI entries.
 */
typedef struct ipv6_nlri_list {
    ipv6_prefix_t          prefix;    /* Prefix payload                     */
    uint32_t               path_id;   /* Host-order ADD-PATH path ID        */
    uint8_t                add_path;  /* Encode path_id before NLRI on wire */
    struct ipv6_nlri_list *next;      /* Next entry in list                 */
} ipv6_nlri_list_t;

/*
 * Linked list of IPv4 labeled-unicast NLRI entries.
 */
typedef struct labeled_ipv4_nlri {
    labeled_ipv4_prefix_t     prefix;    /* Prefix payload                     */
    uint32_t                  path_id;   /* Host-order ADD-PATH path ID        */
    uint8_t                   add_path;  /* Encode path_id before NLRI on wire */
    struct labeled_ipv4_nlri *next;      /* Next entry in list                 */
} labeled_ipv4_nlri_t;

/*
 * Linked list of IPv6 labeled-unicast NLRI entries.
 */
typedef struct labeled_ipv6_nlri {
    labeled_ipv6_prefix_t     prefix;    /* Prefix payload                     */
    uint32_t                  path_id;   /* Host-order ADD-PATH path ID        */
    uint8_t                   add_path;  /* Encode path_id before NLRI on wire */
    struct labeled_ipv6_nlri *next;      /* Next entry in list                 */
} labeled_ipv6_nlri_t;

/*
 * Linked list of VPNv4 NLRI entries.
 */
typedef struct vpnv4_nlri_list {
    vpnv4_prefix_t          prefix;    /* Prefix payload                     */
    uint32_t                path_id;   /* Host-order ADD-PATH path ID        */
    uint8_t                 add_path;  /* Encode path_id before NLRI on wire */
    struct vpnv4_nlri_list *next;      /* Next entry in list                 */
} vpnv4_nlri_list_t;

/*
 * Linked list of VPNv6 NLRI entries.
 */
typedef struct vpnv6_nlri_list {
    vpnv6_prefix_t          prefix;    /* Prefix payload                     */
    uint32_t                path_id;   /* Host-order ADD-PATH path ID        */
    uint8_t                 add_path;  /* Encode path_id before NLRI on wire */
    struct vpnv6_nlri_list *next;      /* Next entry in list                 */
} vpnv6_nlri_list_t;

/*
 * Linked list of EVPN type 1 NLRI entries.
 */
typedef struct evpn_type1_nlri {
    evpn_type1_prefix_t     prefix;    /* Prefix payload                     */
    uint32_t                path_id;   /* Host-order ADD-PATH path ID        */
    uint8_t                 add_path;  /* Encode path_id before NLRI on wire */
    struct evpn_type1_nlri *next;      /* Next entry in list                 */
} evpn_type1_nlri_t;

/*
 * Linked list of EVPN type 2 NLRI entries.
 */
typedef struct evpn_type2_nlri {
    evpn_type2_prefix_t     prefix;    /* Prefix payload                     */
    uint32_t                path_id;   /* Host-order ADD-PATH path ID        */
    uint8_t                 add_path;  /* Encode path_id before NLRI on wire */
    struct evpn_type2_nlri *next;      /* Next entry in list                 */
} evpn_type2_nlri_t;

/*
 * Linked list of EVPN type 3 NLRI entries.
 */
typedef struct evpn_type3_nlri {
    evpn_type3_prefix_t     prefix;    /* Prefix payload                     */
    uint32_t                path_id;   /* Host-order ADD-PATH path ID        */
    uint8_t                 add_path;  /* Encode path_id before NLRI on wire */
    struct evpn_type3_nlri *next;      /* Next entry in list                 */
} evpn_type3_nlri_t;

/*
 * Linked list of EVPN type 4 NLRI entries.
 */
typedef struct evpn_type4_nlri {
    evpn_type4_prefix_t     prefix;    /* Prefix payload                     */
    uint32_t                path_id;   /* Host-order ADD-PATH path ID        */
    uint8_t                 add_path;  /* Encode path_id before NLRI on wire */
    struct evpn_type4_nlri *next;      /* Next entry in list                 */
} evpn_type4_nlri_t;

/*
 * Linked list of EVPN type 5 NLRI entries.
 */
typedef struct evpn_type5_nlri {
    evpn_type5_prefix_t     prefix;    /* Prefix payload                     */
    uint32_t                path_id;   /* Host-order ADD-PATH path ID        */
    uint8_t                 add_path;  /* Encode path_id before NLRI on wire */
    struct evpn_type5_nlri *next;      /* Next entry in list                 */
} evpn_type5_nlri_t;

/*
 * Linked list of BGP-LS NLRI entries.
 */
typedef struct bgpls_nlri {
    bgpls_prefix_t     prefix;    /* Prefix payload                     */
    uint32_t           path_id;   /* Host-order ADD-PATH path ID        */
    uint8_t            add_path;  /* Encode path_id before NLRI on wire */
    struct bgpls_nlri *next;      /* Next entry in list                 */
} bgpls_nlri_t;

/*
 * Linked list of RTC NLRI entries.
 */
typedef struct rtc_nlri_list {
    rtc_prefix_t          prefix;    /* Prefix payload                     */
    uint32_t              path_id;   /* Host-order ADD-PATH path ID        */
    uint8_t               add_path;  /* Encode path_id before NLRI on wire */
    struct rtc_nlri_list *next;      /* Next entry in list                 */
} rtc_nlri_list_t;

/*
 * Linked list of VPLS NLRI entries.
 */
typedef struct vpls_nlri_list {
    vpls_prefix_t          prefix;    /* Prefix payload                     */
    uint32_t               path_id;   /* Host-order ADD-PATH path ID        */
    uint8_t                add_path;  /* Encode path_id before NLRI on wire */
    struct vpls_nlri_list *next;      /* Next entry in list                 */
} vpls_nlri_list_t;

/*
 * Linked list of MVPN Type 1 NLRI entries.
 */
typedef struct mvpn_type1_nlri {
    mvpn_type1_prefix_t     prefix;    /* Prefix payload                     */
    uint32_t                path_id;   /* Host-order ADD-PATH path ID        */
    uint8_t                 add_path;  /* Encode path_id before NLRI on wire */
    struct mvpn_type1_nlri *next;      /* Next entry in list                 */
} mvpn_type1_nlri_t;

/*
 * Linked list of MVPN Type 2 NLRI entries.
 */
typedef struct mvpn_type2_nlri {
    mvpn_type2_prefix_t     prefix;    /* Prefix payload                     */
    uint32_t                path_id;   /* Host-order ADD-PATH path ID        */
    uint8_t                 add_path;  /* Encode path_id before NLRI on wire */
    struct mvpn_type2_nlri *next;      /* Next entry in list                 */
} mvpn_type2_nlri_t;

/*
 * Linked list of MVPN Type 3 NLRI entries.
 */
typedef struct mvpn_type3_nlri {
    mvpn_type3_prefix_t     prefix;    /* Prefix payload                     */
    uint32_t                path_id;   /* Host-order ADD-PATH path ID        */
    uint8_t                 add_path;  /* Encode path_id before NLRI on wire */
    struct mvpn_type3_nlri *next;      /* Next entry in list                 */
} mvpn_type3_nlri_t;

/*
 * Linked list of MVPN Type 4 NLRI entries.
 */
typedef struct mvpn_type4_nlri {
    mvpn_type4_prefix_t     prefix;    /* Prefix payload                     */
    uint32_t                path_id;   /* Host-order ADD-PATH path ID        */
    uint8_t                 add_path;  /* Encode path_id before NLRI on wire */
    struct mvpn_type4_nlri *next;      /* Next entry in list                 */
} mvpn_type4_nlri_t;

/*
 * Linked list of MVPN Type 5 NLRI entries.
 */
typedef struct mvpn_type5_nlri {
    mvpn_type5_prefix_t     prefix;    /* Prefix payload                     */
    uint32_t                path_id;   /* Host-order ADD-PATH path ID        */
    uint8_t                 add_path;  /* Encode path_id before NLRI on wire */
    struct mvpn_type5_nlri *next;      /* Next entry in list                 */
} mvpn_type5_nlri_t;

/*
 * Linked list of MVPN Type 6 NLRI entries.
 */
typedef struct mvpn_type6_nlri {
    mvpn_cmulticast_prefix_t prefix;    /* Prefix payload                     */
    uint32_t                 path_id;   /* Host-order ADD-PATH path ID        */
    uint8_t                  add_path;  /* Encode path_id before NLRI on wire */
    struct mvpn_type6_nlri  *next;      /* Next entry in list                 */
} mvpn_type6_nlri_t;

/*
 * Linked list of MVPN Type 7 NLRI entries.
 */
typedef struct mvpn_type7_nlri {
    mvpn_cmulticast_prefix_t prefix;    /* Prefix payload                     */
    uint32_t                 path_id;   /* Host-order ADD-PATH path ID        */
    uint8_t                  add_path;  /* Encode path_id before NLRI on wire */
    struct mvpn_type7_nlri  *next;      /* Next entry in list                 */
} mvpn_type7_nlri_t;

/*
 * Owned set of encoded UPDATE messages returned by a generator.
 */
typedef struct {
    uint8_t **messages;      /* Array of message buffers     */
    uint16_t *message_lens;  /* Array of message lengths     */
    int       num_messages;  /* Number of messages generated */
} bgp_update_result_t;

/*
 * Internal growable collector used while splitting UPDATE output.
 */
typedef struct {
    bgp_update_result_t *result;
    int                  capacity;
} bgp_builder_t;

/*
 * Arguments for bgp_builder_append_mp(). This is the normalized "one MP UPDATE
 * worth of already-serialized parts" view used by IPv6, labeled-unicast, VPN,
 * and EVPN generators. Callers use C99 designated initializers; unspecified
 * fields zero-initialize.
 */
typedef struct {
    const uint8_t *withdrawn;      /* Encoded withdrawn routes (NULL if none)        */
    uint16_t       withdrawn_len;  /* Length of withdrawn data                       */
    const uint8_t *attrs;          /* Pre-serialized base path attributes            */
    uint16_t       attrs_len;      /* Length of attrs data                           */
    int            is_reach;       /* 1 = MP_REACH_NLRI, 0 = MP_UNREACH_NLRI         */
    uint16_t       afi;            /* Address Family (AFI_IPV4, AFI_IPV6, AFI_L2VPN) */
    uint8_t        safi;           /* Sub-Address Family (SAFI_UNICAST, etc.)        */
    const uint8_t *next_hop;       /* Next-hop address bytes (reach only)            */
    uint8_t        nh_len;         /* Length of next_hop                             */
    const uint8_t *mp_nlri;        /* NLRI data for the MP attribute                 */
    uint16_t       mp_nlri_len;    /* Length of mp_nlri                              */
    const uint8_t *nlri;           /* Traditional IPv4 NLRI (NULL if none)           */
    uint16_t       nlri_len;       /* Length of nlri                                 */
} bgp_mp_args_t;

/*
 * Helper functions for creating path attributes
 */
bgp_path_attr_t* bgp_attr_alloc(uint8_t flags, uint8_t type_code, uint16_t length);
uint8_t bgp_attr_wire_flags(const bgp_path_attr_t *attr);
int bgp_prefix_bytes_needed(uint8_t prefix_len);
int bgp_marshaled_attr_size(uint8_t flags, uint16_t value_len);
int bgp_attr_list_contains_type(const bgp_path_attr_t *attr_list, uint8_t type_code);
int bgp_validate_ipv4_attrs(const bgp_path_attr_t *attr_list);
int bgp_validate_mp_attrs(const bgp_path_attr_t *attr_list);
bgp_path_attr_t* bgp_attr_create_origin(uint8_t origin);
bgp_path_attr_t* bgp_attr_create_as_path(as_path_segment_t *segments, int num_segments);
/*
 * Write the AS_PATH attribute of bgp_attr_create_as_path() (4-octet ASNs), header included, at buffer. Returns its
 * length, or -1 when it is longer than capacity.
 */
int bgp_serialize_as_path_attr(uint8_t *buffer, size_t capacity, as_path_segment_t *segments, int num_segments);
bgp_path_attr_t* bgp_attr_create_as_path_mode(as_path_segment_t *segments,
                                              int num_segments,
                                              bgp_asn_encoding_mode_t mode);
bgp_path_attr_t* bgp_attr_create_as_path_transition(
    as_path_segment_t *segments,
    int num_segments,
    bgp_path_attr_t **as4_path_out);
bgp_path_attr_t* bgp_attr_create_as4_path(as_path_segment_t *segments, int num_segments);
bgp_path_attr_t* bgp_attr_create_next_hop(const bgp_next_hop_t *next_hop);
bgp_path_attr_t* bgp_attr_create_med(uint32_t med);
bgp_path_attr_t* bgp_attr_create_local_pref(uint32_t local_pref);
bgp_path_attr_t* bgp_attr_create_mp_reach_ipv6(const bgp_next_hop_t *next_hop, ipv6_nlri_list_t *nlri_list);
bgp_path_attr_t* bgp_attr_create_mp_unreach_ipv6(ipv6_nlri_list_t *withdrawn_list);
/*
 * Zeroed 8-octet Extended Community with Type and Sub-Type set.
 */
bgp_path_attr_t* bgp_attr_alloc_ext_comm(uint8_t type, uint8_t sub_type);
/*
 * RFC 4360 admin layouts: 2-octet global + 4-octet local, and 4-octet global
 * (IPv4 address in host order, or 4-octet AS) + 2-octet local.
 */
bgp_path_attr_t* bgp_attr_create_ext_comm_global2(uint8_t type, uint8_t sub_type,
                                                  uint16_t global_admin, uint32_t local_admin);
bgp_path_attr_t* bgp_attr_create_ext_comm_global4(uint8_t type, uint8_t sub_type,
                                                  uint32_t global_admin, uint16_t local_admin);
bgp_path_attr_t* bgp_attr_create_ext_comm_encap(uint16_t tunnel_type);
bgp_path_attr_t* bgp_attr_create_ext_comm_rt(uint16_t global_admin, uint32_t local_admin);
bgp_path_attr_t* bgp_attr_create_ext_comm_rt_as4(uint32_t global_admin, uint16_t local_admin);
bgp_path_attr_t* bgp_attr_create_ext_comm_rt_ip(uint32_t ipv4_address, uint16_t local_admin);
int bgp_attr_ext_comm_append_attr(bgp_path_attr_t *dst, const bgp_path_attr_t *src);

/*
 * Color Extended Community (RFC 9012 section 4.3). co_type is the 2-bit
 * Color-Only type of RFC 9830 section 3 (BGP_COLOR_CO_*).
 */
bgp_path_attr_t* bgp_attr_create_ext_comm_color(uint32_t color, uint8_t co_type);
/*
 * Same community with the whole 16-bit flags field given by the caller.
 */
bgp_path_attr_t* bgp_attr_create_ext_comm_color_flags(uint32_t color, uint16_t flags);
/*
 * Write the 8 octets of that community to out (no attribute allocation).
 */
void bgp_ext_comm_color_write(uint8_t out[8], uint32_t color, uint16_t flags);

/*
 * IPv6 Address Specific Extended Community attribute (RFC 5701).
 */
bgp_path_attr_t* bgp_attr_create_ipv6_ext_comm(uint8_t type,
                                               uint8_t sub_type,
                                               const struct in6_addr *address,
                                               uint16_t local_admin);
int bgp_attr_ipv6_ext_comm_append_attr(bgp_path_attr_t *dst, const bgp_path_attr_t *src);

/*
 * Helper functions for creating NLRI lists
 */
ipv4_nlri_list_t* ipv4_nlri_create(const char *prefix_str, uint8_t prefix_len);
ipv4_nlri_list_t* ipv4_nlri_create_path_id(const char *prefix_str, uint8_t prefix_len, uint32_t path_id);
ipv6_nlri_list_t* ipv6_nlri_create(const char *prefix_str, uint8_t prefix_len);
ipv6_nlri_list_t* ipv6_nlri_create_path_id(const char *prefix_str, uint8_t prefix_len, uint32_t path_id);
void ipv4_nlri_append(ipv4_nlri_list_t **list_head, ipv4_nlri_list_t **list_tail, ipv4_nlri_list_t *new_nlri);
void ipv6_nlri_append(ipv6_nlri_list_t **list_head, ipv6_nlri_list_t **list_tail, ipv6_nlri_list_t *new_nlri);
labeled_ipv4_nlri_t* labeled_ipv4_nlri_create(const char *prefix_str, uint8_t prefix_len, uint32_t label);
labeled_ipv4_nlri_t* labeled_ipv4_nlri_create_path_id(const char *prefix_str,
                                                           uint8_t prefix_len,
                                                           uint32_t label,
                                                           uint32_t path_id);
labeled_ipv6_nlri_t* labeled_ipv6_nlri_create(const char *prefix_str, uint8_t prefix_len, uint32_t label);
labeled_ipv6_nlri_t* labeled_ipv6_nlri_create_path_id(const char *prefix_str,
                                                           uint8_t prefix_len,
                                                           uint32_t label,
                                                           uint32_t path_id);
void labeled_ipv4_nlri_append(labeled_ipv4_nlri_t **list_head,
                              labeled_ipv4_nlri_t **list_tail,
                              labeled_ipv4_nlri_t *new_nlri);
void labeled_ipv6_nlri_append(labeled_ipv6_nlri_t **list_head,
                              labeled_ipv6_nlri_t **list_tail,
                              labeled_ipv6_nlri_t *new_nlri);
void ipv4_nlri_add_tail(ipv4_nlri_list_t **list_head,
                        ipv4_nlri_list_t **list_tail,
                        const char *prefix_str,
                        uint8_t prefix_len);
void ipv4_nlri_add_tail_path_id(ipv4_nlri_list_t **list_head,
                                ipv4_nlri_list_t **list_tail,
                                const char *prefix_str,
                                uint8_t prefix_len,
                                uint32_t path_id);
void ipv6_nlri_add_tail(ipv6_nlri_list_t **list_head,
                        ipv6_nlri_list_t **list_tail,
                        const char *prefix_str,
                        uint8_t prefix_len);
void ipv6_nlri_add_tail_path_id(ipv6_nlri_list_t **list_head,
                                ipv6_nlri_list_t **list_tail,
                                const char *prefix_str,
                                uint8_t prefix_len,
                                uint32_t path_id);
void labeled_ipv4_nlri_add_tail(labeled_ipv4_nlri_t **list_head,
                                labeled_ipv4_nlri_t **list_tail,
                                const char *prefix_str,
                                uint8_t prefix_len,
                                uint32_t label);
void labeled_ipv4_nlri_add_tail_path_id(labeled_ipv4_nlri_t **list_head,
                                        labeled_ipv4_nlri_t **list_tail,
                                        const char *prefix_str,
                                        uint8_t prefix_len,
                                        uint32_t label,
                                        uint32_t path_id);
void labeled_ipv6_nlri_add_tail(labeled_ipv6_nlri_t **list_head,
                                labeled_ipv6_nlri_t **list_tail,
                                const char *prefix_str,
                                uint8_t prefix_len,
                                uint32_t label);
void labeled_ipv6_nlri_add_tail_path_id(labeled_ipv6_nlri_t **list_head,
                                        labeled_ipv6_nlri_t **list_tail,
                                        const char *prefix_str,
                                        uint8_t prefix_len,
                                        uint32_t label,
                                        uint32_t path_id);
int ipv4_nlri_count(ipv4_nlri_list_t *list);
int ipv6_nlri_count(ipv6_nlri_list_t *list);
int labeled_ipv4_nlri_count(labeled_ipv4_nlri_t *list);
int labeled_ipv6_nlri_count(labeled_ipv6_nlri_t *list);

/*
 * Main UPDATE message generation functions
 */
bgp_update_result_t* bgp_generate_update_ipv4(
    ipv4_nlri_list_t *nlri_list,
    bgp_path_attr_t *attributes,
    ipv4_nlri_list_t *withdrawn_list,
    uint16_t max_pdu_size
);

/*
 * IPv4 unicast UPDATE generation using MP_REACH_NLRI / MP_UNREACH_NLRI.
 * This is used for cross-AF next-hop encodings such as RFC 8950
 * (IPv4 NLRI with an IPv6 next hop).
 */
bgp_update_result_t* bgp_generate_update_ipv4_mp(
    ipv4_nlri_list_t *nlri_list,
    bgp_path_attr_t *attributes,
    ipv4_nlri_list_t *withdrawn_list,
    uint16_t max_pdu_size,
    const bgp_next_hop_t *next_hop
);

/*
 * AFI 2 unicast uses MP_REACH_NLRI / MP_UNREACH_NLRI and follows the
 * IPv6-family next-hop rules, which allow either IPv6 or an IPv4-mapped
 * IPv6 next hop.
 */
bgp_update_result_t* bgp_generate_update_ipv6(
    ipv6_nlri_list_t *nlri_list,
    bgp_path_attr_t *attributes,
    ipv6_nlri_list_t *withdrawn_list,
    uint16_t max_pdu_size,
    const bgp_next_hop_t *next_hop
);

/*
 * RFC 8277 single-label labeled-unicast UPDATE generators.
 * IPv4 labeled-unicast may use either an IPv4 next hop or, per RFC 8950,
 * an IPv6 next hop. IPv6 labeled-unicast uses the AFI 2 next-hop rules,
 * which allow either IPv6 or an IPv4-mapped IPv6 next hop.
 */
bgp_update_result_t* bgp_generate_update_labeled_ipv4(
    labeled_ipv4_nlri_t *nlri_list,
    bgp_path_attr_t *attributes,
    labeled_ipv4_nlri_t *withdrawn_list,
    uint16_t max_pdu_size,
    const bgp_next_hop_t *next_hop
);

bgp_update_result_t* bgp_generate_update_labeled_ipv6(
    labeled_ipv6_nlri_t *nlri_list,
    bgp_path_attr_t *attributes,
    labeled_ipv6_nlri_t *withdrawn_list,
    uint16_t max_pdu_size,
    const bgp_next_hop_t *next_hop
);

/*
 * VPNv4/VPNv6 low-level UPDATE generators.
 * Low-level callers must pass the transport family explicitly.
 * next_hop is the transport address encoded in MP_REACH_NLRI.
 * Passing NULL encodes an all-zero next hop in the selected transport family.
 */
bgp_update_result_t* bgp_generate_update_vpnv4(
    vpnv4_nlri_list_t *nlri_list,
    bgp_path_attr_t *attributes,
    vpnv4_nlri_list_t *withdrawn_list,
    uint16_t max_pdu_size,
    bgp_vpn_transport_t transport,
    const bgp_next_hop_t *next_hop
);

bgp_update_result_t* bgp_generate_update_vpnv6(
    vpnv6_nlri_list_t *nlri_list,
    bgp_path_attr_t *attributes,
    vpnv6_nlri_list_t *withdrawn_list,
    uint16_t max_pdu_size,
    bgp_vpn_transport_t transport,
    const bgp_next_hop_t *next_hop
);

bgp_update_result_t* bgp_generate_update_evpn_type5(
    evpn_type5_nlri_t *nlri_list,
    bgp_path_attr_t *attributes,
    evpn_type5_nlri_t *withdrawn_list,
    uint16_t max_pdu_size,
    const bgp_next_hop_t *next_hop
);

/*
 * EVPN Type 1-4 UPDATE generators.
 */
bgp_update_result_t* bgp_generate_update_evpn_type1(
    evpn_type1_nlri_t *nlri_list,
    bgp_path_attr_t *attributes,
    evpn_type1_nlri_t *withdrawn_list,
    uint16_t max_pdu_size,
    const bgp_next_hop_t *next_hop
);

bgp_update_result_t* bgp_generate_update_evpn_type2(
    evpn_type2_nlri_t *nlri_list,
    bgp_path_attr_t *attributes,
    evpn_type2_nlri_t *withdrawn_list,
    uint16_t max_pdu_size,
    const bgp_next_hop_t *next_hop
);

bgp_update_result_t* bgp_generate_update_evpn_type3(
    evpn_type3_nlri_t *nlri_list,
    bgp_path_attr_t *attributes,
    evpn_type3_nlri_t *withdrawn_list,
    uint16_t max_pdu_size,
    const bgp_next_hop_t *next_hop
);

bgp_update_result_t* bgp_generate_update_evpn_type4(
    evpn_type4_nlri_t *nlri_list,
    bgp_path_attr_t *attributes,
    evpn_type4_nlri_t *withdrawn_list,
    uint16_t max_pdu_size,
    const bgp_next_hop_t *next_hop
);

/*
 * SR Policy UPDATE generator (AFI 1/2, SAFI 73).
 * nlri_afi selects the NLRI address family (AFI_IPV4 or AFI_IPV6).
 * next_hop is AFI-independent: IPv4 NLRI may carry an IPv6 next hop.
 */
bgp_update_result_t* bgp_generate_update_srpolicy(
    srpolicy_nlri_list_t *nlri_list,
    bgp_path_attr_t *attributes,
    srpolicy_nlri_list_t *withdrawn_list,
    uint16_t max_pdu_size,
    uint16_t nlri_afi,
    const bgp_next_hop_t *next_hop
);

/*
 * RTC (RFC 4684) UPDATE generator.
 * next_hop follows standard IPv4/IPv6 rules (no VPN RD padding).
 */
bgp_update_result_t* bgp_generate_update_rtc(
    rtc_nlri_list_t *nlri_list,
    bgp_path_attr_t *attributes,
    rtc_nlri_list_t *withdrawn_list,
    uint16_t max_pdu_size,
    const bgp_next_hop_t *next_hop
);

/*
 * VPLS (RFC 4761) UPDATE generator.
 * next_hop follows standard IPv4/IPv6 rules.
 */
bgp_update_result_t* bgp_generate_update_vpls(
    vpls_nlri_list_t *nlri_list,
    bgp_path_attr_t *attributes,
    vpls_nlri_list_t *withdrawn_list,
    uint16_t max_pdu_size,
    const bgp_next_hop_t *next_hop
);

/*
 * MVPN Type 1 (Intra-AS I-PMSI A-D, RFC 6514) UPDATE generator.
 * afi selects AFI_IPV4 or AFI_IPV6.
 * next_hop follows standard IPv4/IPv6 rules.
 */
bgp_update_result_t* bgp_generate_update_mvpn_type1(
    mvpn_type1_nlri_t *nlri_list,
    bgp_path_attr_t *attributes,
    mvpn_type1_nlri_t *withdrawn_list,
    uint16_t max_pdu_size,
    uint16_t afi,
    const bgp_next_hop_t *next_hop
);

/*
 * MVPN Type 2 (Inter-AS I-PMSI A-D, RFC 6514) UPDATE generator.
 * afi selects AFI_IPV4 or AFI_IPV6.
 */
bgp_update_result_t* bgp_generate_update_mvpn_type2(
    mvpn_type2_nlri_t *nlri_list,
    bgp_path_attr_t *attributes,
    mvpn_type2_nlri_t *withdrawn_list,
    uint16_t max_pdu_size,
    uint16_t afi,
    const bgp_next_hop_t *next_hop
);

/*
 * MVPN Type 3 (S-PMSI A-D, RFC 6514) UPDATE generator.
 * afi selects AFI_IPV4 or AFI_IPV6.
 * next_hop follows standard IPv4/IPv6 rules.
 */
bgp_update_result_t* bgp_generate_update_mvpn_type3(
    mvpn_type3_nlri_t *nlri_list,
    bgp_path_attr_t *attributes,
    mvpn_type3_nlri_t *withdrawn_list,
    uint16_t max_pdu_size,
    uint16_t afi,
    const bgp_next_hop_t *next_hop
);

/*
 * MVPN Type 4 (Leaf A-D, RFC 6514) UPDATE generator.
 * afi selects AFI_IPV4 or AFI_IPV6 for the Originating Router field.
 */
bgp_update_result_t* bgp_generate_update_mvpn_type4(
    mvpn_type4_nlri_t *nlri_list,
    bgp_path_attr_t *attributes,
    mvpn_type4_nlri_t *withdrawn_list,
    uint16_t max_pdu_size,
    uint16_t afi,
    const bgp_next_hop_t *next_hop
);

/*
 * MVPN Type 5 (Source Active A-D, RFC 6514) UPDATE generator.
 * afi selects AFI_IPV4 or AFI_IPV6.
 */
bgp_update_result_t* bgp_generate_update_mvpn_type5(
    mvpn_type5_nlri_t *nlri_list,
    bgp_path_attr_t *attributes,
    mvpn_type5_nlri_t *withdrawn_list,
    uint16_t max_pdu_size,
    uint16_t afi,
    const bgp_next_hop_t *next_hop
);

/*
 * MVPN Type 6/7 (C-Multicast, RFC 6514) UPDATE generators.
 * afi selects AFI_IPV4 or AFI_IPV6.
 */
bgp_update_result_t* bgp_generate_update_mvpn_type6(
    mvpn_type6_nlri_t *nlri_list,
    bgp_path_attr_t *attributes,
    mvpn_type6_nlri_t *withdrawn_list,
    uint16_t max_pdu_size,
    uint16_t afi,
    const bgp_next_hop_t *next_hop
);

bgp_update_result_t* bgp_generate_update_mvpn_type7(
    mvpn_type7_nlri_t *nlri_list,
    bgp_path_attr_t *attributes,
    mvpn_type7_nlri_t *withdrawn_list,
    uint16_t max_pdu_size,
    uint16_t afi,
    const bgp_next_hop_t *next_hop
);

/*
 * Options for bgp_generate_update_flowspec().
 */
typedef struct {
    uint16_t afi;           /* AFI_IPV4 or AFI_IPV6               */
    uint8_t  safi;          /* SAFI_FLOWSPEC or SAFI_FLOWSPEC_VPN */
    uint16_t max_pdu_size;  /* 0 selects BGP_MAX_PDU_SIZE         */
    /*
     * NULL gives the zero-length next hop that RFC 8955 section 4 requires.
     * Set it only for the redirect-to-next-hop community (type 0x08,
     * draft-simpson-idr-flowspec-redirect), which reads the target from here.
     */
    const bgp_next_hop_t *next_hop;
} bgp_flowspec_update_opts_t;

/*
 * FlowSpec UPDATE generator (RFC 8955; AFI 2 uses the RFC 8956 prefix-offset encoding).
 * SAFI 134 entries must carry a Route Distinguisher (RFC 8955 section 8).
 */
bgp_update_result_t* bgp_generate_update_flowspec(
    flowspec_nlri_t *nlri_list,
    bgp_path_attr_t *attributes,
    flowspec_nlri_t *withdrawn_list,
    const bgp_flowspec_update_opts_t *opts
);

/*
 * Helper functions for VPNv4/VPNv6/EVPN NLRI lists
 */
vpnv4_nlri_list_t* vpnv4_nlri_create(const char *prefix_str, uint8_t prefix_len,
                                     uint32_t label, route_distinguisher_t rd);
vpnv4_nlri_list_t* vpnv4_nlri_create_path_id(const char *prefix_str,
                                             uint8_t prefix_len,
                                             uint32_t label,
                                             route_distinguisher_t rd,
                                             uint32_t path_id);
vpnv6_nlri_list_t* vpnv6_nlri_create(const char *prefix_str, uint8_t prefix_len,
                                     uint32_t label, route_distinguisher_t rd);
vpnv6_nlri_list_t* vpnv6_nlri_create_path_id(const char *prefix_str,
                                             uint8_t prefix_len,
                                             uint32_t label,
                                             route_distinguisher_t rd,
                                             uint32_t path_id);
evpn_type5_nlri_t* evpn_type5_nlri_create_ipv4(
    const char *prefix_str, uint8_t prefix_len,
    route_distinguisher_t rd,
    uint32_t ethernet_tag_id,
    const char *gateway_ip,
    uint32_t label);
evpn_type5_nlri_t* evpn_type5_nlri_create_ipv4_path_id(
    const char *prefix_str, uint8_t prefix_len,
    route_distinguisher_t rd,
    uint32_t ethernet_tag_id,
    const char *gateway_ip,
    uint32_t label,
    uint32_t path_id);
evpn_type5_nlri_t* evpn_type5_nlri_create_ipv6(
    const char *prefix_str, uint8_t prefix_len,
    route_distinguisher_t rd,
    uint32_t ethernet_tag_id,
    const char *gateway_ip,
    uint32_t label);
evpn_type5_nlri_t* evpn_type5_nlri_create_ipv6_path_id(
    const char *prefix_str, uint8_t prefix_len,
    route_distinguisher_t rd,
    uint32_t ethernet_tag_id,
    const char *gateway_ip,
    uint32_t label,
    uint32_t path_id);
void evpn_type5_prefix_set_esi(evpn_type5_prefix_t *prefix, evpn_esi_t esi);
void evpn_type5_nlri_set_esi(evpn_type5_nlri_t *nlri, evpn_esi_t esi);

void vpnv4_nlri_append(vpnv4_nlri_list_t **list_head, vpnv4_nlri_list_t **list_tail, vpnv4_nlri_list_t *new_nlri);
void vpnv6_nlri_append(vpnv6_nlri_list_t **list_head, vpnv6_nlri_list_t **list_tail, vpnv6_nlri_list_t *new_nlri);
void evpn_type5_nlri_append(evpn_type5_nlri_t **list_head, evpn_type5_nlri_t **list_tail, evpn_type5_nlri_t *new_nlri);
void vpnv4_nlri_add_tail(vpnv4_nlri_list_t **list_head,
                         vpnv4_nlri_list_t **list_tail,
                         const char *prefix_str,
                         uint8_t prefix_len,
                         uint32_t label,
                         route_distinguisher_t rd);
void vpnv4_nlri_add_tail_path_id(vpnv4_nlri_list_t **list_head,
                                 vpnv4_nlri_list_t **list_tail,
                                 const char *prefix_str,
                                 uint8_t prefix_len,
                                 uint32_t label,
                                 route_distinguisher_t rd,
                                 uint32_t path_id);
void vpnv6_nlri_add_tail(vpnv6_nlri_list_t **list_head,
                         vpnv6_nlri_list_t **list_tail,
                         const char *prefix_str,
                         uint8_t prefix_len,
                         uint32_t label,
                         route_distinguisher_t rd);
void vpnv6_nlri_add_tail_path_id(vpnv6_nlri_list_t **list_head,
                                 vpnv6_nlri_list_t **list_tail,
                                 const char *prefix_str,
                                 uint8_t prefix_len,
                                 uint32_t label,
                                 route_distinguisher_t rd,
                                 uint32_t path_id);
int vpnv4_nlri_count(vpnv4_nlri_list_t *list);
int vpnv6_nlri_count(vpnv6_nlri_list_t *list);
int evpn_type5_nlri_count(evpn_type5_nlri_t *list);

/*
 * EVPN Type 1 NLRI helpers
 */
evpn_type1_nlri_t* evpn_type1_nlri_create(
    route_distinguisher_t rd, evpn_esi_t esi,
    uint32_t ethernet_tag_id, uint32_t label);
evpn_type1_nlri_t* evpn_type1_nlri_create_path_id(
    route_distinguisher_t rd, evpn_esi_t esi,
    uint32_t ethernet_tag_id, uint32_t label,
    uint32_t path_id);
void evpn_type1_nlri_append(evpn_type1_nlri_t **list_head, evpn_type1_nlri_t **list_tail, evpn_type1_nlri_t *new_nlri);
int evpn_type1_nlri_count(evpn_type1_nlri_t *list);
void evpn_type1_nlri_list_free(evpn_type1_nlri_t *list);
int bgp_encode_evpn_type1_prefix(uint8_t *buffer, evpn_type1_prefix_t *prefix);

/*
 * EVPN Type 2 NLRI helpers
 */
evpn_type2_nlri_t* evpn_type2_nlri_create_ipv4(
    route_distinguisher_t rd, evpn_esi_t esi,
    uint32_t ethernet_tag_id, const uint8_t *mac_addr,
    const char *ip_addr, uint32_t label1);
evpn_type2_nlri_t* evpn_type2_nlri_create_ipv4_path_id(
    route_distinguisher_t rd, evpn_esi_t esi,
    uint32_t ethernet_tag_id, const uint8_t *mac_addr,
    const char *ip_addr, uint32_t label1,
    uint32_t path_id);
evpn_type2_nlri_t* evpn_type2_nlri_create_ipv6(
    route_distinguisher_t rd, evpn_esi_t esi,
    uint32_t ethernet_tag_id, const uint8_t *mac_addr,
    const char *ip_addr, uint32_t label1);
evpn_type2_nlri_t* evpn_type2_nlri_create_ipv6_path_id(
    route_distinguisher_t rd, evpn_esi_t esi,
    uint32_t ethernet_tag_id, const uint8_t *mac_addr,
    const char *ip_addr, uint32_t label1,
    uint32_t path_id);
evpn_type2_nlri_t* evpn_type2_nlri_create_mac_only(
    route_distinguisher_t rd, evpn_esi_t esi,
    uint32_t ethernet_tag_id, const uint8_t *mac_addr,
    uint32_t label1);
evpn_type2_nlri_t* evpn_type2_nlri_create_mac_only_path_id(
    route_distinguisher_t rd, evpn_esi_t esi,
    uint32_t ethernet_tag_id, const uint8_t *mac_addr,
    uint32_t label1, uint32_t path_id);
void evpn_type2_nlri_set_label2(evpn_type2_nlri_t *nlri, uint32_t label2);
void evpn_type2_nlri_append(evpn_type2_nlri_t **list_head, evpn_type2_nlri_t **list_tail, evpn_type2_nlri_t *new_nlri);
int evpn_type2_nlri_count(evpn_type2_nlri_t *list);
void evpn_type2_nlri_list_free(evpn_type2_nlri_t *list);
int bgp_encode_evpn_type2_prefix(uint8_t *buffer, evpn_type2_prefix_t *prefix);

/*
 * EVPN Type 3 NLRI helpers
 */
evpn_type3_nlri_t* evpn_type3_nlri_create_ipv4(
    route_distinguisher_t rd, uint32_t ethernet_tag_id,
    const char *orig_router_ip);
evpn_type3_nlri_t* evpn_type3_nlri_create_ipv4_path_id(
    route_distinguisher_t rd, uint32_t ethernet_tag_id,
    const char *orig_router_ip, uint32_t path_id);
evpn_type3_nlri_t* evpn_type3_nlri_create_ipv6(
    route_distinguisher_t rd, uint32_t ethernet_tag_id,
    const char *orig_router_ip);
evpn_type3_nlri_t* evpn_type3_nlri_create_ipv6_path_id(
    route_distinguisher_t rd, uint32_t ethernet_tag_id,
    const char *orig_router_ip, uint32_t path_id);
void evpn_type3_nlri_append(evpn_type3_nlri_t **list_head, evpn_type3_nlri_t **list_tail, evpn_type3_nlri_t *new_nlri);
int evpn_type3_nlri_count(evpn_type3_nlri_t *list);
void evpn_type3_nlri_list_free(evpn_type3_nlri_t *list);
int bgp_encode_evpn_type3_prefix(uint8_t *buffer, evpn_type3_prefix_t *prefix);

/*
 * EVPN Type 4 NLRI helpers
 */
evpn_type4_nlri_t* evpn_type4_nlri_create_ipv4(route_distinguisher_t rd, evpn_esi_t esi, const char *orig_router_ip);
evpn_type4_nlri_t* evpn_type4_nlri_create_ipv4_path_id(
    route_distinguisher_t rd, evpn_esi_t esi,
    const char *orig_router_ip, uint32_t path_id);
evpn_type4_nlri_t* evpn_type4_nlri_create_ipv6(route_distinguisher_t rd, evpn_esi_t esi, const char *orig_router_ip);
evpn_type4_nlri_t* evpn_type4_nlri_create_ipv6_path_id(
    route_distinguisher_t rd, evpn_esi_t esi,
    const char *orig_router_ip, uint32_t path_id);
void evpn_type4_nlri_append(evpn_type4_nlri_t **list_head, evpn_type4_nlri_t **list_tail, evpn_type4_nlri_t *new_nlri);
int evpn_type4_nlri_count(evpn_type4_nlri_t *list);
void evpn_type4_nlri_list_free(evpn_type4_nlri_t *list);
int bgp_encode_evpn_type4_prefix(uint8_t *buffer, evpn_type4_prefix_t *prefix);

/*
 * EVPN Extended Community helpers
 */
bgp_path_attr_t* bgp_attr_create_ext_comm_mac_mobility(uint8_t flags, uint32_t seq_number);
bgp_path_attr_t* bgp_attr_create_ext_comm_esi_label(uint8_t flags, uint32_t esi_label);
bgp_path_attr_t* bgp_attr_create_ext_comm_default_gateway(void);
bgp_path_attr_t* bgp_attr_create_ext_comm_router_mac(const uint8_t router_mac[6]);

/*
 * Helper functions for SR Policy NLRI lists
 */
srpolicy_nlri_list_t* srpolicy_nlri_create(uint32_t distinguisher,
                                           uint32_t color,
                                           int endpoint_af,
                                           const char *endpoint_str);
srpolicy_nlri_list_t* srpolicy_nlri_create_path_id(uint32_t distinguisher,
                                                   uint32_t color,
                                                   int endpoint_af,
                                                   const char *endpoint_str,
                                                   uint32_t path_id);
void srpolicy_nlri_append(srpolicy_nlri_list_t **list_head,
                          srpolicy_nlri_list_t **list_tail,
                          srpolicy_nlri_list_t *new_nlri);
int srpolicy_nlri_count(srpolicy_nlri_list_t *list);

/*
 * Helper functions for FlowSpec NLRI lists
 */
flowspec_nlri_t* flowspec_nlri_create(const flowspec_rule_t *rule);
flowspec_nlri_t* flowspec_nlri_create_path_id(const flowspec_rule_t *rule, uint32_t path_id);
/*
 * VPN FlowSpec (SAFI 134) entries: Route Distinguisher before the rule.
 */
flowspec_nlri_t* flowspec_nlri_create_vpn(const flowspec_rule_t *rule, route_distinguisher_t rd);
flowspec_nlri_t* flowspec_nlri_create_vpn_path_id(const flowspec_rule_t *rule,
                                                  route_distinguisher_t rd,
                                                  uint32_t path_id);
void flowspec_nlri_append(flowspec_nlri_t **list_head, flowspec_nlri_t **list_tail, flowspec_nlri_t *new_nlri);
int flowspec_nlri_count(flowspec_nlri_t *list);

/*
 * FlowSpec encoding functions
 */
int bgp_encode_flowspec_op_value(uint8_t *buffer, const flowspec_op_value_t *ov);
int bgp_encode_flowspec_component(uint8_t *buffer, const flowspec_component_t *comp);
int bgp_encode_flowspec_component_afi(uint8_t *buffer, const flowspec_component_t *comp, uint16_t afi);
int bgp_encode_flowspec_rule(uint8_t *buffer, const flowspec_rule_t *rule);
int bgp_encode_flowspec_rule_afi(uint8_t *buffer, const flowspec_rule_t *rule, uint16_t afi);
int bgp_validate_flowspec_rule(const flowspec_rule_t *rule);
// Largest encoded NLRI entry: path-id(4) + length(2) + value(4095).
#define FLOWSPEC_MAX_NLRI_ENTRY_LEN (4 + 2 + FLOWSPEC_MAX_NLRI_LEN)
/*
 * One NLRI entry ([path-id] length [RD] components); the buffer must hold
 * FLOWSPEC_MAX_NLRI_ENTRY_LEN octets. rd is NULL for SAFI 133.
 */
int bgp_encode_flowspec_nlri_entry(uint8_t *buffer,
                                   const flowspec_rule_t *rule,
                                   const route_distinguisher_t *rd,
                                   uint16_t afi,
                                   int add_path,
                                   uint32_t path_id);

/*
 * FlowSpec traffic filtering extended community helpers
 */
bgp_path_attr_t* bgp_attr_create_flowspec_rate(uint16_t as, float rate);
bgp_path_attr_t* bgp_attr_create_flowspec_rate_pkts(uint16_t as, float rate);
bgp_path_attr_t* bgp_attr_create_flowspec_action(int terminal, int sample);
bgp_path_attr_t* bgp_attr_create_flowspec_redirect_rt(uint16_t as, uint32_t value);
bgp_path_attr_t* bgp_attr_create_flowspec_redirect_rt_ip(uint32_t ipv4_address, uint16_t local_admin);
bgp_path_attr_t* bgp_attr_create_flowspec_redirect_rt_as4(uint32_t asn, uint16_t local_admin);
bgp_path_attr_t* bgp_attr_create_flowspec_marking(uint8_t dscp);

/*
 * FlowSpec redirect actions outside RFC 8955.
 * Redirect-to-IPv4, type 0x010c (draft-ietf-idr-flowspec-redirect-ip).
 */
bgp_path_attr_t* bgp_attr_create_flowspec_redirect_ipv4(uint32_t ipv4_address, int copy);
/*
 * Redirect-to-IPv6, IPv6 Address Specific type 0x000c (same draft).
 */
bgp_path_attr_t* bgp_attr_create_flowspec_redirect_ipv6(const struct in6_addr *ipv6_address, int copy);
/*
 * Redirect to the MP_REACH next hop, type 0x0800
 * (draft-simpson-idr-flowspec-redirect).
 */
bgp_path_attr_t* bgp_attr_create_flowspec_redirect_nexthop(int copy);
/*
 * rt-redirect-ipv6, IPv6 Address Specific type 0x000d (RFC 8956 6.1).
 */
bgp_path_attr_t* bgp_attr_create_flowspec_redirect_rt_ipv6(const struct in6_addr *ipv6_address, uint16_t local_admin);
/*
 * Interface-set, type 0x0702 or 0x4702 (draft-ietf-idr-flowspec-interfaceset).
 */
bgp_path_attr_t* bgp_attr_create_flowspec_interface_set(uint32_t asn,
                                                        uint16_t group_id,
                                                        int inbound,
                                                        int outbound,
                                                        int transitive);

/*
 * SR-TE steering actions (draft-ietf-idr-ts-flowspec-srv6-policy section
 * 3.1.1). Returns an attribute list: one Extended Communities attribute with
 * the redirect (IPv4 endpoint or next-hop form) and every Color, plus, for an
 * IPv6 endpoint, one IPv6 Address Specific Extended Community attribute with
 * the redirect. With via_next_hop, pass the endpoint as the MP_REACH next hop
 * (bgp_flowspec_update_opts_t.next_hop). Append other action communities to
 * the first attribute with bgp_attr_ext_comm_append_attr().
 */
bgp_path_attr_t* bgp_attr_create_flowspec_srte(const bgp_flowspec_srte_t *steer);

/*
 * Helper functions for RTC/VPLS/MVPN NLRI lists (bgp_update_misc.c)
 */
rtc_nlri_list_t* rtc_nlri_create(uint32_t origin_as, const uint8_t *rt_data, uint8_t rt_len);
rtc_nlri_list_t* rtc_nlri_create_path_id(uint32_t origin_as, const uint8_t *rt_data, uint8_t rt_len, uint32_t path_id);
rtc_nlri_list_t* rtc_nlri_create_default(void);
rtc_nlri_list_t* rtc_nlri_create_default_path_id(uint32_t path_id);
void rtc_nlri_append(rtc_nlri_list_t **list_head, rtc_nlri_list_t **list_tail, rtc_nlri_list_t *new_nlri);
int rtc_nlri_count(rtc_nlri_list_t *list);
void rtc_nlri_list_free(rtc_nlri_list_t *list);

vpls_nlri_list_t* vpls_nlri_create(route_distinguisher_t rd,
                                   uint16_t ve_id,
                                   uint16_t ve_block_offset,
                                   uint16_t ve_block_size,
                                   uint32_t label_base);
vpls_nlri_list_t* vpls_nlri_create_path_id(route_distinguisher_t rd,
                                           uint16_t ve_id,
                                           uint16_t ve_block_offset,
                                           uint16_t ve_block_size,
                                           uint32_t label_base,
                                           uint32_t path_id);
void vpls_nlri_append(vpls_nlri_list_t **list_head, vpls_nlri_list_t **list_tail, vpls_nlri_list_t *new_nlri);
int vpls_nlri_count(vpls_nlri_list_t *list);
void vpls_nlri_list_free(vpls_nlri_list_t *list);

mvpn_type1_nlri_t* mvpn_type1_nlri_create_ipv4(route_distinguisher_t rd, const char *orig_router_ip);
mvpn_type1_nlri_t* mvpn_type1_nlri_create_ipv4_path_id(
    route_distinguisher_t rd,
    const char *orig_router_ip,
    uint32_t path_id);
mvpn_type1_nlri_t* mvpn_type1_nlri_create_ipv6(route_distinguisher_t rd, const char *orig_router_ip);
mvpn_type1_nlri_t* mvpn_type1_nlri_create_ipv6_path_id(
    route_distinguisher_t rd,
    const char *orig_router_ip,
    uint32_t path_id);
void mvpn_type1_nlri_append(mvpn_type1_nlri_t **list_head, mvpn_type1_nlri_t **list_tail, mvpn_type1_nlri_t *new_nlri);
int mvpn_type1_nlri_count(mvpn_type1_nlri_t *list);
void mvpn_type1_nlri_list_free(mvpn_type1_nlri_t *list);

mvpn_type2_nlri_t* mvpn_type2_nlri_create(route_distinguisher_t rd, uint32_t source_as);
mvpn_type2_nlri_t* mvpn_type2_nlri_create_path_id(route_distinguisher_t rd, uint32_t source_as, uint32_t path_id);
void mvpn_type2_nlri_append(mvpn_type2_nlri_t **list_head, mvpn_type2_nlri_t **list_tail, mvpn_type2_nlri_t *new_nlri);
int mvpn_type2_nlri_count(mvpn_type2_nlri_t *list);
void mvpn_type2_nlri_list_free(mvpn_type2_nlri_t *list);

mvpn_type3_nlri_t* mvpn_type3_nlri_create_ipv4(route_distinguisher_t rd,
                                               const char *mcast_src,
                                               const char *mcast_grp,
                                               const char *orig_router_ip);
mvpn_type3_nlri_t* mvpn_type3_nlri_create_ipv4_path_id(
    route_distinguisher_t rd,
    const char *mcast_src,
    const char *mcast_grp,
    const char *orig_router_ip,
    uint32_t path_id);
mvpn_type3_nlri_t* mvpn_type3_nlri_create_ipv6(route_distinguisher_t rd,
                                               const char *mcast_src,
                                               const char *mcast_grp,
                                               const char *orig_router_ip);
mvpn_type3_nlri_t* mvpn_type3_nlri_create_ipv6_path_id(
    route_distinguisher_t rd,
    const char *mcast_src,
    const char *mcast_grp,
    const char *orig_router_ip,
    uint32_t path_id);
void mvpn_type3_nlri_append(mvpn_type3_nlri_t **list_head, mvpn_type3_nlri_t **list_tail, mvpn_type3_nlri_t *new_nlri);
int mvpn_type3_nlri_count(mvpn_type3_nlri_t *list);
void mvpn_type3_nlri_list_free(mvpn_type3_nlri_t *list);

mvpn_type4_nlri_t* mvpn_type4_nlri_create_ipv4(route_distinguisher_t rd,
                                               const uint8_t *route_key,
                                               uint8_t route_key_len,
                                               const char *orig_router_ip);
mvpn_type4_nlri_t* mvpn_type4_nlri_create_ipv4_path_id(
    route_distinguisher_t rd,
    const uint8_t *route_key,
    uint8_t route_key_len,
    const char *orig_router_ip,
    uint32_t path_id);
mvpn_type4_nlri_t* mvpn_type4_nlri_create_ipv6(route_distinguisher_t rd,
                                               const uint8_t *route_key,
                                               uint8_t route_key_len,
                                               const char *orig_router_ip);
mvpn_type4_nlri_t* mvpn_type4_nlri_create_ipv6_path_id(
    route_distinguisher_t rd,
    const uint8_t *route_key,
    uint8_t route_key_len,
    const char *orig_router_ip,
    uint32_t path_id);
void mvpn_type4_nlri_append(mvpn_type4_nlri_t **list_head, mvpn_type4_nlri_t **list_tail, mvpn_type4_nlri_t *new_nlri);
int mvpn_type4_nlri_count(mvpn_type4_nlri_t *list);
void mvpn_type4_nlri_list_free(mvpn_type4_nlri_t *list);

mvpn_type5_nlri_t* mvpn_type5_nlri_create_ipv4(route_distinguisher_t rd, const char *mcast_src, const char *mcast_grp);
mvpn_type5_nlri_t* mvpn_type5_nlri_create_ipv4_path_id(
    route_distinguisher_t rd,
    const char *mcast_src,
    const char *mcast_grp,
    uint32_t path_id);
mvpn_type5_nlri_t* mvpn_type5_nlri_create_ipv6(route_distinguisher_t rd, const char *mcast_src, const char *mcast_grp);
mvpn_type5_nlri_t* mvpn_type5_nlri_create_ipv6_path_id(
    route_distinguisher_t rd,
    const char *mcast_src,
    const char *mcast_grp,
    uint32_t path_id);
void mvpn_type5_nlri_append(mvpn_type5_nlri_t **list_head, mvpn_type5_nlri_t **list_tail, mvpn_type5_nlri_t *new_nlri);
int mvpn_type5_nlri_count(mvpn_type5_nlri_t *list);
void mvpn_type5_nlri_list_free(mvpn_type5_nlri_t *list);

mvpn_type6_nlri_t* mvpn_type6_nlri_create_ipv4(route_distinguisher_t rd,
                                               uint32_t source_as,
                                               const char *mcast_src,
                                               const char *mcast_grp);
mvpn_type6_nlri_t* mvpn_type6_nlri_create_ipv4_path_id(
    route_distinguisher_t rd,
    uint32_t source_as,
    const char *mcast_src,
    const char *mcast_grp,
    uint32_t path_id);
mvpn_type6_nlri_t* mvpn_type6_nlri_create_ipv6(route_distinguisher_t rd,
                                               uint32_t source_as,
                                               const char *mcast_src,
                                               const char *mcast_grp);
mvpn_type6_nlri_t* mvpn_type6_nlri_create_ipv6_path_id(
    route_distinguisher_t rd,
    uint32_t source_as,
    const char *mcast_src,
    const char *mcast_grp,
    uint32_t path_id);
void mvpn_type6_nlri_append(mvpn_type6_nlri_t **list_head, mvpn_type6_nlri_t **list_tail, mvpn_type6_nlri_t *new_nlri);
int mvpn_type6_nlri_count(mvpn_type6_nlri_t *list);
void mvpn_type6_nlri_list_free(mvpn_type6_nlri_t *list);

mvpn_type7_nlri_t* mvpn_type7_nlri_create_ipv4(route_distinguisher_t rd,
                                               uint32_t source_as,
                                               const char *mcast_src,
                                               const char *mcast_grp);
mvpn_type7_nlri_t* mvpn_type7_nlri_create_ipv4_path_id(
    route_distinguisher_t rd,
    uint32_t source_as,
    const char *mcast_src,
    const char *mcast_grp,
    uint32_t path_id);
mvpn_type7_nlri_t* mvpn_type7_nlri_create_ipv6(route_distinguisher_t rd,
                                               uint32_t source_as,
                                               const char *mcast_src,
                                               const char *mcast_grp);
mvpn_type7_nlri_t* mvpn_type7_nlri_create_ipv6_path_id(
    route_distinguisher_t rd,
    uint32_t source_as,
    const char *mcast_src,
    const char *mcast_grp,
    uint32_t path_id);
void mvpn_type7_nlri_append(mvpn_type7_nlri_t **list_head, mvpn_type7_nlri_t **list_tail, mvpn_type7_nlri_t *new_nlri);
int mvpn_type7_nlri_count(mvpn_type7_nlri_t *list);
void mvpn_type7_nlri_list_free(mvpn_type7_nlri_t *list);

/*
 * Helper functions for Route Distinguisher
 */
route_distinguisher_t rd_create_type0(uint16_t admin, uint32_t assigned);
route_distinguisher_t rd_create_type1(uint32_t ip, uint16_t assigned);
route_distinguisher_t rd_create_type2(uint32_t asn, uint16_t assigned);
void bgp_encode_rd(uint8_t *buffer, const route_distinguisher_t *rd);

/*
 * Cleanup functions
 */
void bgp_path_attr_free(bgp_path_attr_t *attr);
void bgp_path_attr_list_free(bgp_path_attr_t *list);
void ipv4_nlri_list_free(ipv4_nlri_list_t *list);
void ipv6_nlri_list_free(ipv6_nlri_list_t *list);
void labeled_ipv4_nlri_list_free(labeled_ipv4_nlri_t *list);
void labeled_ipv6_nlri_list_free(labeled_ipv6_nlri_t *list);
void vpnv4_nlri_list_free(vpnv4_nlri_list_t *list);
void vpnv6_nlri_list_free(vpnv6_nlri_list_t *list);
void evpn_type5_nlri_list_free(evpn_type5_nlri_t *list);
void srpolicy_nlri_list_free(srpolicy_nlri_list_t *list);
void rtc_nlri_list_free(rtc_nlri_list_t *list);
void vpls_nlri_list_free(vpls_nlri_list_t *list);
void mvpn_type1_nlri_list_free(mvpn_type1_nlri_t *list);
void mvpn_type2_nlri_list_free(mvpn_type2_nlri_t *list);
void mvpn_type3_nlri_list_free(mvpn_type3_nlri_t *list);
void mvpn_type4_nlri_list_free(mvpn_type4_nlri_t *list);
void mvpn_type5_nlri_list_free(mvpn_type5_nlri_t *list);
void mvpn_type6_nlri_list_free(mvpn_type6_nlri_t *list);
void mvpn_type7_nlri_list_free(mvpn_type7_nlri_t *list);
void flowspec_nlri_list_free(flowspec_nlri_t *list);
void bgp_update_result_free(bgp_update_result_t *result);

/*
 * Utility functions
 */
int bgp_encode_ipv4_prefix(uint8_t *buffer, ipv4_prefix_t *prefix);
int bgp_encode_ipv6_prefix(uint8_t *buffer, ipv6_prefix_t *prefix);
int bgp_encode_labeled_ipv4_prefix(uint8_t *buffer, labeled_ipv4_prefix_t *prefix);
int bgp_encode_labeled_ipv6_prefix(uint8_t *buffer, labeled_ipv6_prefix_t *prefix);
int bgp_encode_vpnv4_prefix(uint8_t *buffer, vpnv4_prefix_t *prefix);
int bgp_encode_vpnv6_prefix(uint8_t *buffer, vpnv6_prefix_t *prefix);
int bgp_encode_evpn_type5_prefix(uint8_t *buffer, evpn_type5_prefix_t *prefix);
int bgp_encode_srpolicy_prefix(uint8_t *buffer, srpolicy_prefix_t *prefix);
int bgp_encode_rtc_prefix(uint8_t *buffer, rtc_prefix_t *prefix);
int bgp_encode_vpls_prefix(uint8_t *buffer, vpls_prefix_t *prefix);
int bgp_encode_mvpn_type1_prefix(uint8_t *buffer, mvpn_type1_prefix_t *prefix);
int bgp_encode_mvpn_type2_prefix(uint8_t *buffer, mvpn_type2_prefix_t *prefix);
int bgp_encode_mvpn_type3_prefix(uint8_t *buffer, mvpn_type3_prefix_t *prefix);
int bgp_encode_mvpn_type4_prefix(uint8_t *buffer, mvpn_type4_prefix_t *prefix);
int bgp_encode_mvpn_type5_prefix(uint8_t *buffer, mvpn_type5_prefix_t *prefix);
int bgp_encode_mvpn_type6_prefix(uint8_t *buffer, mvpn_cmulticast_prefix_t *prefix);
int bgp_encode_mvpn_type7_prefix(uint8_t *buffer, mvpn_cmulticast_prefix_t *prefix);
int bgp_encode_srpolicy_next_hop(const bgp_next_hop_t *next_hop, uint8_t *buffer, uint8_t *nh_len_out);
int bgp_encode_standard_next_hop(const bgp_next_hop_t *next_hop, uint8_t *buffer, uint8_t *nh_len_out);
bgp_path_attr_t* bgp_attr_create_ext_comm_l2info(uint8_t encap_type, uint8_t control_flags, uint16_t mtu);
bgp_path_attr_t* bgp_attr_create_pmsi_tunnel(uint8_t flags,
                                             uint8_t tunnel_type,
                                             uint32_t label,
                                             const uint8_t *tunnel_id,
                                             uint16_t tunnel_id_len);
bgp_path_attr_t* bgp_attr_create_tunnel_encap_srpolicy(const srpolicy_tunnel_encap_t *spec);
/*
 * Write the attribute of bgp_attr_create_tunnel_encap_srpolicy(), header included, at buffer. Returns its length,
 * or -1 when spec is not valid or the attribute is longer than capacity.
 */
int bgp_serialize_tunnel_encap_srpolicy_attr(uint8_t *buffer, size_t capacity, const srpolicy_tunnel_encap_t *spec);
int bgp_serialize_path_attributes(uint8_t *buffer, bgp_path_attr_t *attr_list);
int bgp_serialize_path_attributes_alloc(bgp_path_attr_t *attr_list, uint8_t **data_out, uint16_t *len_out);
int bgp_serialize_raw_path_attr(uint8_t *buffer,
                                uint8_t flags,
                                uint8_t type_code,
                                uint16_t value_len,
                                const uint8_t *value);
int bgp_serialize_mp_reach_attr(uint8_t *buffer,
                                uint16_t afi,
                                uint8_t safi,
                                const uint8_t *next_hop,
                                uint8_t nh_len,
                                const uint8_t *nlri_data,
                                uint16_t nlri_len);
int bgp_serialize_mp_unreach_attr(uint8_t *buffer,
                                  uint16_t afi,
                                  uint8_t safi,
                                  const uint8_t *nlri_data,
                                  uint16_t nlri_len);
int bgp_serialize_mp_reach_attr_alloc(uint16_t afi,
                                      uint8_t safi,
                                      const uint8_t *next_hop,
                                      uint8_t nh_len,
                                      const uint8_t *nlri_data,
                                      uint16_t nlri_len,
                                      uint8_t **data_out,
                                      uint16_t *len_out);
int bgp_serialize_mp_unreach_attr_alloc(uint16_t afi,
                                        uint8_t safi,
                                        const uint8_t *nlri_data,
                                        uint16_t nlri_len,
                                        uint8_t **data_out,
                                        uint16_t *len_out);
int bgp_builder_init(bgp_builder_t *builder);
void bgp_builder_release(bgp_builder_t *builder);
/*
 * Free the messages that builder holds (a caller that took a message sets its slot to NULL) and keep the result
 * and its arrays for the next messages.
 */
void bgp_builder_clear(bgp_builder_t *builder);
bgp_update_result_t* bgp_builder_take(bgp_builder_t *builder);
int bgp_builder_append(bgp_builder_t *builder,
                       const uint8_t *withdrawn,
                       uint16_t withdrawn_len,
                       const uint8_t *attrs,
                       uint16_t attrs_len,
                       const uint8_t *nlri,
                       uint16_t nlri_len);
int bgp_builder_append_attrs_only(bgp_builder_t *builder, const uint8_t *attrs, uint16_t attrs_len);
int bgp_builder_append_mp(bgp_builder_t *builder, const bgp_mp_args_t *args);
int bgp_encode_ipv6_next_hop(const bgp_next_hop_t *next_hop, uint8_t *buffer, uint8_t *nh_len_out);
int bgp_encode_ipv6_family_next_hop(const bgp_next_hop_t *next_hop, uint8_t *buffer, uint8_t *nh_len_out);
int bgp_encode_labeled_ipv4_next_hop(const bgp_next_hop_t *next_hop, uint8_t *buffer, uint8_t *nh_len_out);
int bgp_encode_evpn_next_hop(const bgp_next_hop_t *next_hop, uint8_t *buffer, uint8_t *nh_len_out);
int bgp_encode_vpn_next_hop(uint16_t afi,
                            bgp_vpn_transport_t transport,
                            const bgp_next_hop_t *next_hop,
                            uint8_t *buffer,
                            uint8_t *nh_len_out);
void bgp_encode_mpls_label(uint8_t *buffer, const mpls_label_t *label);
bgp_path_attr_t* bgp_attr_create_mp_reach_raw(uint16_t afi,
                                              uint8_t safi,
                                              const uint8_t *next_hop,
                                              uint8_t nh_len,
                                              const uint8_t *nlri_data,
                                              uint16_t nlri_len);
bgp_path_attr_t* bgp_attr_create_mp_unreach_raw(uint16_t afi,
                                                uint8_t safi,
                                                const uint8_t *nlri_data,
                                                uint16_t nlri_len);

/*
 * BGP-LS TLV helpers
 */
bgpls_tlv_t* bgpls_tlv_create(uint16_t type, uint16_t length, const uint8_t *value);
bgpls_tlv_t* bgpls_tlv_create_u32(uint16_t type, uint32_t value);
bgpls_tlv_t* bgpls_tlv_create_as(uint32_t as_number);
bgpls_tlv_t* bgpls_tlv_create_bgpls_id(uint32_t bgpls_id);
bgpls_tlv_t* bgpls_tlv_create_ospf_area(uint32_t area_id);
bgpls_tlv_t* bgpls_tlv_create_igp_router_id(const uint8_t *id, uint16_t id_len);
bgpls_tlv_t* bgpls_tlv_create_ipv4_iface(uint32_t addr);
bgpls_tlv_t* bgpls_tlv_create_ipv4_neighbor(uint32_t addr);
bgpls_tlv_t* bgpls_tlv_create_ipv6_iface(const uint8_t *addr);
bgpls_tlv_t* bgpls_tlv_create_ipv6_neighbor(const uint8_t *addr);
bgpls_tlv_t* bgpls_tlv_create_link_local_remote(uint32_t local_id, uint32_t remote_id);
void bgpls_tlv_append(bgpls_tlv_t **head, bgpls_tlv_t **tail, bgpls_tlv_t *tlv);
void bgpls_tlv_list_free(bgpls_tlv_t *list);
int bgpls_encode_tlv(uint8_t *buffer, const bgpls_tlv_t *tlv);
int bgpls_encode_tlv_chain(uint8_t *buffer, const bgpls_tlv_t *chain);
int bgpls_tlv_chain_wire_len(const bgpls_tlv_t *chain);

/*
 * BGP-LS node descriptor builder
 */
bgpls_tlv_t* bgpls_node_desc_create(uint32_t as_number, const uint8_t *router_id, uint16_t router_id_len);

/*
 * BGP-LS NLRI creation functions
 */
bgpls_nlri_t* bgpls_nlri_create_node(uint8_t protocol_id, uint64_t identifier, bgpls_tlv_t *local_desc);
bgpls_nlri_t* bgpls_nlri_create_node_path_id(uint8_t protocol_id,
                                              uint64_t identifier,
                                              bgpls_tlv_t *local_desc,
                                              uint32_t path_id);
bgpls_nlri_t* bgpls_nlri_create_link(uint8_t protocol_id,
                                     uint64_t identifier,
                                     bgpls_tlv_t *local_desc,
                                     bgpls_tlv_t *remote_desc,
                                     bgpls_tlv_t *link_desc);
bgpls_nlri_t* bgpls_nlri_create_link_path_id(uint8_t protocol_id,
                                              uint64_t identifier,
                                              bgpls_tlv_t *local_desc,
                                              bgpls_tlv_t *remote_desc,
                                              bgpls_tlv_t *link_desc,
                                              uint32_t path_id);
bgpls_nlri_t* bgpls_nlri_create_prefix_ipv4(uint8_t protocol_id,
                                             uint64_t identifier,
                                             bgpls_tlv_t *local_desc,
                                             bgpls_tlv_t *prefix_desc);
bgpls_nlri_t* bgpls_nlri_create_prefix_ipv4_path_id(
    uint8_t protocol_id, uint64_t identifier,
    bgpls_tlv_t *local_desc, bgpls_tlv_t *prefix_desc,
    uint32_t path_id);
bgpls_nlri_t* bgpls_nlri_create_prefix_ipv6(uint8_t protocol_id,
                                             uint64_t identifier,
                                             bgpls_tlv_t *local_desc,
                                             bgpls_tlv_t *prefix_desc);
bgpls_nlri_t* bgpls_nlri_create_prefix_ipv6_path_id(
    uint8_t protocol_id, uint64_t identifier,
    bgpls_tlv_t *local_desc, bgpls_tlv_t *prefix_desc,
    uint32_t path_id);

/*
 * BGP-LS NLRI list utilities
 */
void bgpls_nlri_append(bgpls_nlri_t **head, bgpls_nlri_t **tail, bgpls_nlri_t *nlri);
int bgpls_nlri_count(bgpls_nlri_t *list);
void bgpls_nlri_list_free(bgpls_nlri_t *list);

/*
 * BGP-LS prefix encoding
 */
int bgp_encode_bgpls_prefix(uint8_t *buffer, bgpls_prefix_t *prefix);

/*
 * BGP-LS path attribute (type 29, optional non-transitive)
 */
bgp_path_attr_t* bgp_attr_create_bgpls(bgpls_tlv_t *tlv_chain);

/*
 * BGP-LS next-hop encoding (standard IPv4/IPv6, no RD padding)
 */
int bgp_encode_bgpls_next_hop(const bgp_next_hop_t *next_hop, uint8_t *buffer, uint8_t *nh_len_out);

/*
 * BGP-LS UPDATE generator
 */
bgp_update_result_t* bgp_generate_update_bgpls(
    bgpls_nlri_t *nlri_list,
    bgp_path_attr_t *attributes,
    bgpls_nlri_t *withdrawn_list,
    uint16_t max_pdu_size,
    const bgp_next_hop_t *next_hop
);

/*
 * NLRI List Macros
 *
 * Shared intrusive-list helpers and code-generation macros for the typed
 * NLRI families.  Previously lived in bgp_update_macros.h; folded here
 * since every includer of the macros already includes this header.
 */

#define DEFINE_NLRI_LIST_UTILS(list_type, prefix) \
void prefix##_append(list_type **list_head,       \
                     list_type **list_tail,       \
                     list_type *new_nlri) {       \
    if (!new_nlri) {                              \
        return;                                   \
    }                                             \
                                                  \
    if (*list_tail) {                             \
        (*list_tail)->next = new_nlri;            \
        *list_tail = new_nlri;                    \
    } else {                                      \
        *list_head = new_nlri;                    \
        *list_tail = new_nlri;                    \
    }                                             \
}                                                 \
                                                  \
int prefix##_count(list_type *list) {             \
    int count = 0;                                \
                                                  \
    while (list) {                                \
        count++;                                  \
        list = list->next;                        \
    }                                             \
                                                  \
    return count;                                 \
}                                                 \
                                                  \
void prefix##_list_free(list_type *list) {        \
    while (list) {                                \
        list_type *next = list->next;             \
        free(list);                               \
        list = next;                              \
    }                                             \
}

#define DEFINE_ADD_PATH_DETECTOR(func_name, list_type, validate_stmt) \
static int func_name(const list_type *list,                           \
                     int *add_path_out) {                             \
    int add_path = -1;                                                \
                                                                      \
    while (list) {                                                    \
        validate_stmt;                                                \
                                                                      \
        if (add_path == -1) {                                         \
            add_path = list->add_path ? 1 : 0;                        \
        } else if ((list->add_path ? 1 : 0) != add_path) {            \
            return -1;                                                \
        }                                                             \
                                                                      \
        if (!list->add_path && list->path_id != 0) {                  \
            return -1;                                                \
        }                                                             \
                                                                      \
        list = list->next;                                            \
    }                                                                 \
                                                                      \
    *add_path_out = (add_path < 0) ? 0 : add_path;                    \
    return 0;                                                         \
}

#define DEFINE_BASIC_NLRI_CREATE_WRAPPERS(list_type, prefix)             \
list_type* prefix##_create(const char *prefix_str, uint8_t prefix_len) { \
    return prefix##_create_internal(prefix_str, prefix_len, 0, 0);       \
}                                                                        \
                                                                         \
list_type* prefix##_create_path_id(const char *prefix_str,               \
                                   uint8_t prefix_len,                   \
                                   uint32_t path_id) {                   \
    return prefix##_create_internal(prefix_str, prefix_len, 1, path_id); \
}

#define DEFINE_BASIC_NLRI_TAIL_WRAPPERS(list_type, prefix)    \
void prefix##_add_tail(list_type **list_head,                 \
                       list_type **list_tail,                 \
                       const char *prefix_str,                \
                       uint8_t prefix_len) {                  \
    prefix##_append(list_head,                                \
                    list_tail,                                \
                    prefix##_create(prefix_str, prefix_len)); \
}                                                             \
                                                              \
void prefix##_add_tail_path_id(list_type **list_head,         \
                               list_type **list_tail,         \
                               const char *prefix_str,        \
                               uint8_t prefix_len,            \
                               uint32_t path_id) {            \
    prefix##_append(list_head,                                \
                    list_tail,                                \
                    prefix##_create_path_id(prefix_str,       \
                                            prefix_len,       \
                                            path_id));        \
}

#define DEFINE_LABELED_NLRI_CREATE_WRAPPERS(list_type, prefix)            \
list_type* prefix##_create(const char *prefix_str,                        \
                           uint8_t prefix_len,                            \
                           uint32_t label) {                              \
    return prefix##_create_internal(prefix_str, prefix_len, label, 0, 0); \
}                                                                         \
                                                                          \
list_type* prefix##_create_path_id(const char *prefix_str,                \
                                   uint8_t prefix_len,                    \
                                   uint32_t label,                        \
                                   uint32_t path_id) {                    \
    return prefix##_create_internal(prefix_str,                           \
                                    prefix_len,                           \
                                    label,                                \
                                    1,                                    \
                                    path_id);                             \
}

#define DEFINE_LABELED_NLRI_TAIL_WRAPPERS(list_type, prefix)         \
void prefix##_add_tail(list_type **list_head,                        \
                       list_type **list_tail,                        \
                       const char *prefix_str,                       \
                       uint8_t prefix_len,                           \
                       uint32_t label) {                             \
    prefix##_append(list_head,                                       \
                    list_tail,                                       \
                    prefix##_create(prefix_str, prefix_len, label)); \
}                                                                    \
                                                                     \
void prefix##_add_tail_path_id(list_type **list_head,                \
                               list_type **list_tail,                \
                               const char *prefix_str,               \
                               uint8_t prefix_len,                   \
                               uint32_t label,                       \
                               uint32_t path_id) {                   \
    prefix##_append(list_head,                                       \
                    list_tail,                                       \
                    prefix##_create_path_id(prefix_str,              \
                                            prefix_len,              \
                                            label,                   \
                                            path_id));               \
}

#define DEFINE_VPN_NLRI_CREATE_WRAPPERS(list_type, prefix)   \
list_type* prefix##_create(const char *prefix_str,           \
                           uint8_t prefix_len,               \
                           uint32_t label,                   \
                           route_distinguisher_t rd) {       \
    return prefix##_create_internal(prefix_str,              \
                                    prefix_len,              \
                                    label,                   \
                                    rd,                      \
                                    0,                       \
                                    0);                      \
}                                                            \
                                                             \
list_type* prefix##_create_path_id(const char *prefix_str,   \
                                   uint8_t prefix_len,       \
                                   uint32_t label,           \
                                   route_distinguisher_t rd, \
                                   uint32_t path_id) {       \
    return prefix##_create_internal(prefix_str,              \
                                    prefix_len,              \
                                    label,                   \
                                    rd,                      \
                                    1,                       \
                                    path_id);                \
}

#define DEFINE_VPN_NLRI_TAIL_WRAPPERS(list_type, prefix)                 \
void prefix##_add_tail(list_type **list_head,                            \
                       list_type **list_tail,                            \
                       const char *prefix_str,                           \
                       uint8_t prefix_len,                               \
                       uint32_t label,                                   \
                       route_distinguisher_t rd) {                       \
    prefix##_append(list_head,                                           \
                    list_tail,                                           \
                    prefix##_create(prefix_str, prefix_len, label, rd)); \
}                                                                        \
                                                                         \
void prefix##_add_tail_path_id(list_type **list_head,                    \
                               list_type **list_tail,                    \
                               const char *prefix_str,                   \
                               uint8_t prefix_len,                       \
                               uint32_t label,                           \
                               route_distinguisher_t rd,                 \
                               uint32_t path_id) {                       \
    prefix##_append(list_head,                                           \
                    list_tail,                                           \
                    prefix##_create_path_id(prefix_str,                  \
                                            prefix_len,                  \
                                            label,                       \
                                            rd,                          \
                                            path_id));                   \
}

#define DEFINE_EVPN_TYPE5_CREATE_WRAPPERS(af_suffix)             \
evpn_type5_nlri_t* evpn_type5_nlri_create_##af_suffix(           \
    const char *prefix_str, uint8_t prefix_len,                  \
    route_distinguisher_t rd,                                    \
    uint32_t ethernet_tag_id,                                    \
    const char *gateway_ip,                                      \
    uint32_t label) {                                            \
    return evpn_type5_nlri_create_##af_suffix##_internal(        \
        prefix_str, prefix_len, rd,                              \
        ethernet_tag_id, gateway_ip, label,                      \
        0,                                                       \
        0);                                                      \
}                                                                \
                                                                 \
evpn_type5_nlri_t* evpn_type5_nlri_create_##af_suffix##_path_id( \
    const char *prefix_str, uint8_t prefix_len,                  \
    route_distinguisher_t rd,                                    \
    uint32_t ethernet_tag_id,                                    \
    const char *gateway_ip,                                      \
    uint32_t label,                                              \
    uint32_t path_id) {                                          \
    return evpn_type5_nlri_create_##af_suffix##_internal(        \
        prefix_str, prefix_len, rd,                              \
        ethernet_tag_id, gateway_ip, label,                      \
        1,                                                       \
        path_id);                                                \
}

#endif /* BGP_UPDATE_H */
