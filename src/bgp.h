#ifndef BGP_H
#define BGP_H

#include <stdint.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "cli.h"
#include "util.h"
#include "output.h"
#include "bgp_router.h"
#include "bgp_neighbor.h"

/*
 * Forward declarations
 */
typedef struct bgp_sim bgp_sim_t;

#define MAX_LINE_LENGTH BGPSIM_COMMAND_SIZE
#define BGP_PORT        179
// Base port for listening (each router gets base + index*100)
#define BGP_LISTEN_BASE_PORT 20000

// BGP Protocol Constants
#define BGP_VERSION            4
#define BGP_HEADER_SIZE        19
#define BGP_MAX_MESSAGE_SIZE   4096
#define BGP_MARKER_SIZE        16
#define BGP_HOLD_TIME          180
#define BGP_KEEPALIVE_INTERVAL 60  /* Send keepalive every N seconds */

// Connection Retry Constants
#define BGP_MIN_RETRY_INTERVAL 2   /* Initial retry interval */
// Maximum retry interval (linear backoff: 2, 4, 6, ..., 16)
#define BGP_MAX_RETRY_INTERVAL 16

// BGP Message Types
#define BGP_MSG_OPEN          1
#define BGP_MSG_UPDATE        2
#define BGP_MSG_NOTIFICATION  3
#define BGP_MSG_KEEPALIVE     4
#define BGP_MSG_ROUTE_REFRESH 5

// BGP Capability Codes (RFC 5492)
#define BGP_CAP_MP_BGP           1   /* Multiprotocol BGP (RFC 4760)          */
#define BGP_CAP_ROUTE_REFRESH    2   /* Route Refresh (RFC 2918)              */
#define BGP_CAP_EXTENDED_NEXTHOP 5   /* Extended Next Hop Encoding (RFC 8950) */
#define BGP_CAP_GRACEFUL_RESTART 64  /* Graceful Restart (RFC 4724)           */
#define BGP_CAP_4BYTE_ASN        65  /* 4-byte AS Number (RFC 6793)           */
#define BGP_CAP_ADD_PATH         69  /* ADD-PATH (RFC 7911)                   */

/*
 * RFC 9072 reuses value 255 in two adjacent OPEN fields to signal that the
 * optional-parameters block uses the extended two-octet length encoding.
 */
#define BGP_OPEN_EXTENDED_OPT_PARAMS_MARKER 255

// Address Family Identifiers (AFI)
#define AFI_IPV4   1
#define AFI_IPV6   2
#define AFI_L2VPN  25
#define AFI_BGP_LS 16388

// Subsequent Address Family Identifiers (SAFI)
#define SAFI_UNICAST         1
#define SAFI_MULTICAST       2
#define SAFI_LABELED_UNICAST 4
#define SAFI_MVPN            5    /* MCAST-VPN (RFC 6514)        */
#define SAFI_VPLS            65   /* Virtual Private LAN Service */
#define SAFI_EVPN            70   /* EVPN                        */
#define SAFI_BGP_LS          71   /* BGP Link-State              */
#define SAFI_SR_POLICY       73   /* Segment Routing Policy      */
#define SAFI_MPLS_VPN        128  /* VPNv4/VPNv6                 */
#define SAFI_RTC             132  /* Route Target Constraint     */
#define SAFI_FLOWSPEC        133  /* Flow Specification          */
#define SAFI_FLOWSPEC_VPN    134  /* VPN Flow Specification      */

// ADD-PATH Send/Receive flags
#define ADD_PATH_RECEIVE 0x01
#define ADD_PATH_SEND    0x02

/*
 * Sentinel value indicating a capability field has no corresponding
 * offset in bgp_capabilities_t (e.g., ext-nh is only supported by * three families).
 */
#define NO_CAP_OFFSET ((size_t)-1)

/*
 * Unified address-family descriptor.  One row per supported AFI/SAFI
 * combination.  Used by OPEN encode/parse, CLI display, capability
 * helpers, and command handlers so that adding a new family is a
 * single table entry instead of touching 6+ files.
 */
#define BGP_NUM_FAMILIES 18

typedef struct {
    uint16_t    afi;
    uint8_t     safi;
    size_t      mp_offset;        /* offsetof(bgp_capabilities_t, <af_flag>)     */
    size_t      add_path_offset;  /* offsetof(bgp_capabilities_t, add_path_<af>) */
    size_t      ext_nh_offset;    /* offsetof(...) or NO_CAP_OFFSET              */
    const char *cli_name;         /* CLI keyword: "ipv4", "l2vpn evpn", etc.     */
    const char *display_name;     /* Show output: "IPv4 Unicast", etc.           */
} bgp_family_t;

extern const bgp_family_t bgp_families[BGP_NUM_FAMILIES];

/*
 * The bgp_families[] row with this CLI keyword, or NULL.
 */
const bgp_family_t *bgp_family_find(const char *cli_name);
/*
 * The bgp_families[] row for an AFI/SAFI pair, or NULL.
 */
const bgp_family_t *bgp_family_lookup(uint16_t afi, uint8_t safi);

// 4-byte AS special value
#define AS_TRANS 23456  /* Used in 2-byte AS field when AS > 65535 */

// BGP Error Codes
#define BGP_ERR_MESSAGE_HEADER     1
#define BGP_ERR_OPEN_MESSAGE       2
#define BGP_ERR_UPDATE_MESSAGE     3
#define BGP_ERR_HOLD_TIMER_EXPIRED 4
#define BGP_ERR_FSM                5
#define BGP_ERR_CEASE              6

// OPEN Message Error subcodes (RFC 4271 section 4.5).
#define BGP_OPEN_ERR_UNSPECIFIC            0
#define BGP_OPEN_ERR_UNSUPPORTED_VERSION   1
#define BGP_OPEN_ERR_BAD_PEER_AS           2
#define BGP_OPEN_ERR_BAD_IDENTIFIER        3
#define BGP_OPEN_ERR_UNSUPPORTED_PARAMETER 4
#define BGP_OPEN_ERR_UNACCEPTABLE_HOLD     6

/*
 * Fixed header present on every BGP protocol message.
 */
typedef struct {
    uint8_t  marker[BGP_MARKER_SIZE];  /* All ones (0xFF)                       */
    uint16_t length;                   /* Total message length including header */
    uint8_t  type;                     /* Message type                          */
} __attribute__((packed)) bgp_header_t;

/*
 * Fixed portion of a BGP OPEN before optional parameters.
 */
typedef struct {
    uint8_t  version;         /* BGP version (4)            */
    uint16_t my_as;           /* Autonomous System number   */
    uint16_t hold_time;       /* Hold time in seconds       */
    uint32_t bgp_identifier;  /* BGP Identifier (router ID) */
    uint8_t  opt_param_len;   /* Optional parameters length */
    // Optional parameters follow
} __attribute__((packed)) bgp_open_t;

/*
 * Fixed portion of a BGP NOTIFICATION before any data payload.
 */
typedef struct {
    uint8_t error_code;     /* Error code    */
    uint8_t error_subcode;  /* Error subcode */
    // Error data follows
} __attribute__((packed)) bgp_notification_t;

typedef struct {
    uint32_t           remote_as;
    uint16_t           hold_time;
    uint32_t           remote_id;
    bgp_capabilities_t capabilities;
    int                peer_supports_4byte_asn;
    int                mp_capability_received;  /* Any Multiprotocol capability, known family or not */
    uint8_t            error_subcode;           /* OPEN error to report when parsing fails           */
} bgp_open_info_t;

/*
 * Function declarations
 */
int parse_config_file(const char *filename, bgp_sim_t *sim);
int parse_config_file_with_output(const char *filename, bgp_sim_t *sim, const output_t *output);

/*
 * BGP Protocol Functions (bgp.c)
 */
int bgp_send_open(bgp_neighbor_t *neighbor, uint32_t my_as, uint32_t router_id);
int bgp_build_open_with_capabilities(uint8_t *buffer,
                                     size_t buffer_size,
                                     uint32_t my_as,
                                     uint32_t router_id,
                                     bgp_capabilities_t *caps);
int bgp_build_keepalive(uint8_t *buffer, size_t buffer_size);
int bgp_build_notification(uint8_t *buffer, size_t buffer_size, uint8_t error_code, uint8_t error_subcode);
int bgp_send_keepalive(bgp_neighbor_t *neighbor);
int bgp_send_notification(bgp_neighbor_t *neighbor, uint8_t error_code, uint8_t error_subcode);
int bgp_recv_message(int sock_fd, uint8_t *buffer, size_t buffer_size, uint8_t *msg_type);
int bgp_configure_peer_socket(int sock_fd);
int bgp_parse_open_message(const uint8_t *msg, size_t msg_len,
                           const bgp_capabilities_t *local_caps,
                           bgp_open_info_t *open_info);
int bgp_process_open(bgp_router_t *router, bgp_neighbor_t *neighbor, uint8_t *msg, size_t msg_len);
int bgp_accept_open(bgp_router_t *router, bgp_neighbor_t *neighbor, const uint8_t *msg,
                     size_t msg_len, bgp_open_info_t *open_info);
const char* bgp_state_to_string(bgp_state_t state);
uint8_t bgp_caps_get_add_path(const bgp_capabilities_t *caps, uint16_t afi, uint8_t safi);
void bgp_caps_set_add_path(bgp_capabilities_t *caps, uint16_t afi, uint8_t safi, uint8_t mode);
int bgp_caps_has_gr_family(const bgp_capabilities_t *caps, uint16_t afi, uint8_t safi);
uint8_t bgp_caps_get_gr_flags(const bgp_capabilities_t *caps, uint16_t afi, uint8_t safi);
void bgp_caps_set_gr_flags(bgp_capabilities_t *caps, uint16_t afi, uint8_t safi, uint8_t flags);
int bgp_caps_add_path_can_send(const bgp_capabilities_t *local_caps,
                               const bgp_capabilities_t *peer_caps,
                               uint16_t afi, uint8_t safi);
int bgp_caps_add_path_can_recv(const bgp_capabilities_t *local_caps,
                               const bgp_capabilities_t *peer_caps,
                               uint16_t afi, uint8_t safi);
int bgp_caps_has_ext_nh(const bgp_capabilities_t *caps, uint16_t nlri_afi, uint8_t nlri_safi, uint16_t next_hop_afi);
void bgp_caps_set_ext_nh(bgp_capabilities_t *caps,
                         uint16_t nlri_afi, uint8_t nlri_safi,
                         uint16_t next_hop_afi, int enabled);

// Router management functions - see bgp_router.h
// Neighbor management functions - see bgp_neighbor.h

/*
 * cli.c
 */
int cli_process_command(cli_session_t *session, bgp_sim_t *sim, cli_mode_t *mode, const char *line);
int cli_process_command_with_output(cli_session_t *session, bgp_sim_t *sim,
                                    cli_mode_t *mode, const char *line,
                                    const output_t *output);

#endif /* BGP_H */
