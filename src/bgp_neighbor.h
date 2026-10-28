#ifndef BGP_NEIGHBOR_H
#define BGP_NEIGHBOR_H

#include <uv.h>
#include <time.h>
#include <stddef.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/*
 * Forward declarations
 */
struct bgp_router;
typedef struct bgp_router bgp_router_t;
struct bgp_sim;
typedef struct bgp_sim bgp_sim_t;
struct bgpsim_peer_write;
typedef struct bgpsim_peer_write bgpsim_peer_write_t;
struct bgp_peer_tx;  /* bgp_peer_tx.h */

#define BGP_NEIGHBOR_RIBOUT_NAME   32  /* BGP_RIBOUT_NAME_SIZE                                 */

/*
 * BGP FSM States
 */
typedef enum {
    BGP_STATE_IDLE,
    BGP_STATE_CONNECT,
    BGP_STATE_ACTIVE,
    BGP_STATE_OPENSENT,
    BGP_STATE_OPENCONFIRM,
    BGP_STATE_ESTABLISHED
} bgp_state_t;

/*
 * The last NOTIFICATION received or sent on a session (RFC 4271 section 4.5); time 0 when there was none.
 */
typedef struct {
    time_t   time;           /* When it was received or sent                                    */
    uint8_t  code;           /* Error code                                                      */
    uint8_t  subcode;        /* Error subcode                                                   */
    uint16_t data_len;       /* Data octets after the subcode                                   */
    char     shutdown[256];  /* RFC 9003 Shutdown Communication, control characters as ?; or "" */
} bgp_notification_record_t;

/*
 * Neighbor capability state used for local advertisement and parsed peer OPENs.
 */
typedef struct {
    // Address families enabled for this neighbor
    int ipv4_unicast;          /* Enable IPv4 unicast                  */
    int ipv6_unicast;          /* Enable IPv6 unicast                  */
    int ipv4_labeled_unicast;  /* Enable IPv4 labeled unicast (SAFI 4) */
    int ipv6_labeled_unicast;  /* Enable IPv6 labeled unicast (SAFI 4) */
    int vpnv4_unicast;         /* Enable VPNv4                         */
    int vpnv6_unicast;         /* Enable VPNv6                         */
    int evpn;                  /* Enable EVPN                          */
    int ipv4_flowspec;         /* Enable IPv4 FlowSpec (SAFI 133)      */
    int ipv6_flowspec;         /* Enable IPv6 FlowSpec (SAFI 133)      */
    int ipv4_srpolicy;         /* Enable IPv4 SR Policy (SAFI 73)      */
    int ipv6_srpolicy;         /* Enable IPv6 SR Policy (SAFI 73)      */
    int bgp_ls;                /* Enable BGP-LS (AFI 16388, SAFI 71)   */
    int ipv4_mvpn;             /* Enable IPv4 MVPN (SAFI 5)            */
    int ipv6_mvpn;             /* Enable IPv6 MVPN (SAFI 5)            */
    int ipv4_rtc;              /* Enable RTC (SAFI 132)                */
    int vpls;                  /* Enable VPLS (AFI 25, SAFI 65)        */
    int ipv4_flowspec_vpn;     /* Enable IPv4 VPN FlowSpec (SAFI 134)  */
    int ipv6_flowspec_vpn;     /* Enable IPv6 VPN FlowSpec (SAFI 134)  */

    // Route Refresh capability
    int route_refresh;  /* Enable route refresh                         */
    int four_byte_asn;  /* Advertise RFC 6793 four-octet ASN capability */

    // Graceful Restart capability
    int      graceful_restart;    /* Enable graceful restart          */
    uint16_t restart_time;        /* Restart time in seconds (0-4095) */
    uint32_t gr_family_mask;      /* AFI/SAFI tuples present in GR    */
    uint32_t gr_forwarding_mask;  /* Per-family forwarding-state bit  */

    // ADD-PATH capability per address family
    uint8_t add_path_ipv4;               /* 0=disabled, 1=receive, 2=send, 3=both */
    uint8_t add_path_ipv6;               /* 0=disabled, 1=receive, 2=send, 3=both */
    uint8_t add_path_ipv4_labeled;       /* 0=disabled, 1=receive, 2=send, 3=both */
    uint8_t add_path_ipv6_labeled;       /* 0=disabled, 1=receive, 2=send, 3=both */
    uint8_t add_path_vpnv4;              /* 0=disabled, 1=receive, 2=send, 3=both */
    uint8_t add_path_vpnv6;              /* 0=disabled, 1=receive, 2=send, 3=both */
    uint8_t add_path_evpn;               /* 0=disabled, 1=receive, 2=send, 3=both */
    uint8_t add_path_ipv4_flowspec;      /* 0=disabled, 1=receive, 2=send, 3=both */
    uint8_t add_path_ipv6_flowspec;      /* 0=disabled, 1=receive, 2=send, 3=both */
    uint8_t add_path_ipv4_srpolicy;      /* 0=disabled, 1=receive, 2=send, 3=both */
    uint8_t add_path_ipv6_srpolicy;      /* 0=disabled, 1=receive, 2=send, 3=both */
    uint8_t add_path_bgp_ls;             /* 0=disabled, 1=receive, 2=send, 3=both */
    uint8_t add_path_ipv4_mvpn;          /* 0=disabled, 1=receive, 2=send, 3=both */
    uint8_t add_path_ipv6_mvpn;          /* 0=disabled, 1=receive, 2=send, 3=both */
    uint8_t add_path_ipv4_rtc;           /* 0=disabled, 1=receive, 2=send, 3=both */
    uint8_t add_path_vpls;               /* 0=disabled, 1=receive, 2=send, 3=both */
    uint8_t add_path_ipv4_flowspec_vpn;  /* 0=disabled, 1=receive, 2=send, 3=both */
    uint8_t add_path_ipv6_flowspec_vpn;  /* 0=disabled, 1=receive, 2=send, 3=both */

    // RFC 8950 extended next-hop tuples currently supported by bgpsim
    int ext_nh_ipv4_unicast_over_ipv6;
    int ext_nh_ipv4_labeled_unicast_over_ipv6;
    int ext_nh_vpnv4_unicast_over_ipv6;
} bgp_capabilities_t;

/*
 * Per-neighbor session state owned by the peer FSM.
 */
typedef struct {
    char        ip[INET6_ADDRSTRLEN];                    /* Neighbor IP address (IPv4 or IPv6)              */
    char        source_ip[INET6_ADDRSTRLEN];             /* Optional per-neighbor update-source override    */
    int         af;                                      /* Address family: AF_INET or AF_INET6             */
    uint32_t    remote_as;                               /* Remote AS number                                */
    bgp_state_t state;                                   /* Connection state                                */
    int         sock_fd;                                 /* Socket file descriptor                          */
    time_t      uptime;                                  /* Time when connection established                */
    int         active;                                  /* Is this neighbor active                         */
    time_t      last_msg_time;                           /* Time of last message received                   */
    time_t      last_keepalive_sent;                     /* Time of last KEEPALIVE transmission             */
    uint32_t    remote_id;                               /* Remote BGP identifier                           */
    uint16_t    hold_time;                               /* Negotiated hold time                            */
    int         is_passive;                              /* True if this is a passive (accepted) connection */
    time_t      last_connect_attempt;                    /* Time of last connection attempt                 */
    int         retry_count;                             /* Number of connection retry attempts             */
    char        (*advertise)[BGP_NEIGHBOR_RIBOUT_NAME];  /* Standing ribouts, config order                  */
    int advertise_count;                                 /* Entries in advertise                            */
    int advertise_capacity;

    // Message counters - transmitted (TX)
    uint64_t tx_open;          /* OPEN messages sent         */
    uint64_t tx_update;        /* UPDATE messages sent       */
    uint64_t tx_notification;  /* NOTIFICATION messages sent */
    uint64_t tx_keepalive;     /* KEEPALIVE messages sent    */

    // Message counters - received (RX)
    uint64_t rx_open;          /* OPEN messages received         */
    uint64_t rx_update;        /* UPDATE messages received       */
    uint64_t rx_notification;  /* NOTIFICATION messages received */
    uint64_t rx_keepalive;     /* KEEPALIVE messages received    */

    // Session statistics
    uint64_t                  session_resets;        /* Number of times session was reset        */
    time_t                    last_reset_time;       /* Time of last session reset (for backoff) */
    bgp_notification_record_t last_notification_rx;  /* Last NOTIFICATION received               */
    bgp_notification_record_t last_notification_tx;  /* Last NOTIFICATION sent                   */

    // BGP Capabilities
    // Configured capabilities for this neighbor (advertised)
    bgp_capabilities_t capabilities;
    bgp_capabilities_t peer_capabilities;            /* Capabilities from peer                 */
    int                peer_capabilities_received;   /* Peer OPEN received?                    */
    int                peer_mp_capability_received;  /* Peer sent any MP capability (RFC 4760) */

    struct bgp_router  *router;          /* Back-reference to parent router                   */

    /*
     * Loop-owned runtime state. The event loop owns these fields whenever a
     * runtime is active; config helpers may still read the stable counters and
     * state values, but they must not manipulate the libuv handles directly.
     */
    uv_tcp_t             stream;
    uv_connect_t         connect_req;
    uv_timer_t           reconnect_timer;
    uv_timer_t           connect_timer;
    uv_timer_t           open_timer;
    uv_timer_t           hold_timer;
    uv_timer_t           keepalive_timer;
    int                  runtime_initialized;
    int                  stream_initialized;
    int                  stream_open;
    int                  read_started;
    int                  connect_pending;
    int                  closing;
    int                  destroy_pending;
    int                  close_refs;
    int                  pending_reconnect;
    uint64_t             connect_epoch;
    uint64_t             session_epoch;
    uint8_t             *rx_data;
    size_t               rx_len;
    size_t               rx_cap;
    bgpsim_peer_write_t *tx_head;
    bgpsim_peer_write_t *tx_tail;
    bgpsim_peer_write_t *tx_active;
    int                  write_in_flight;
    int                  notification_pending;  /* Drain fatal NOTIFICATION before resetting */
    int                  reading;               /* The read callback is parsing: writes wait */
    struct bgp_peer_tx  *tx;                    /* Outbound UPDATE state (loop-owned)        */
} bgp_neighbor_t;

/*
 * Neighbor management functions
 */
bgp_neighbor_t *bgp_find_neighbor(bgp_router_t *router, const char *ip);
int bgp_add_neighbor(bgp_sim_t *sim, uint32_t as_number, const char *ip, uint32_t remote_as);
int bgp_remove_neighbor(bgp_sim_t *sim, uint32_t as_number, const char *ip);
int bgp_set_neighbor_source_ip(bgp_sim_t *sim, uint32_t as_number, const char *ip, const char *source_ip);
int bgp_clear_neighbor_source_ip(bgp_sim_t *sim, uint32_t as_number, const char *ip);
void bgp_clear_neighbor(bgp_neighbor_t *neighbor);
/*
 * Reset only after all runtime callbacks have finished.
 */
void bgp_neighbor_reset(bgp_neighbor_t *neighbor);

/*
 * NOTIFICATION reasons
 */
const char *bgp_notification_code_name(uint8_t code);
const char *bgp_notification_subcode_name(uint8_t code, uint8_t subcode);
void bgp_notification_record(bgp_notification_record_t *record, const uint8_t *body, size_t body_len);
void bgp_notification_describe(const bgp_notification_record_t *record, char *buffer, size_t size);

#endif /* BGP_NEIGHBOR_H */
