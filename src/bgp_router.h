#ifndef BGP_ROUTER_H
#define BGP_ROUTER_H

#include <stdint.h>
#include "bgp_neighbor.h"

/*
 * Forward declaration
 */
struct bgp_sim;

#define BGP_LISTEN_BACKLOG 32

/*
 * One simulated BGP speaker and its configured peers.
 */
typedef struct bgp_router {
    uint32_t         local_as;              /* Local AS number                                                     */
    uint32_t         router_id;             /* BGP Router ID (host byte order)                                     */
    int              router_id_configured;  /* True if router ID manually set                                      */
    // Source IP for outbound connections (update-source)
    char             source_ip[INET6_ADDRSTRLEN];
    bgp_neighbor_t **neighbors;             /* Growable table; peer addresses never move                           */
    int              neighbor_count;        /* Number of active neighbors                                          */
    int              neighbor_capacity;     /* Allocated size of neighbors[]                                       */
    int              active;                /* Is this router active                                               */
    uint16_t         listen_port;           /* Port this router listens on                                         */
    int              router_index;          /* Index in routers array                                              */
    struct bgp_sim  *sim;                   /* Back-reference to simulator                                         */
    uv_tcp_t         listener;
    int              listener_initialized;
    int              listener_open;
    int              listener_closing;
    int              listener_error;        /* Passive mode: last bind/listen error (libuv code), 0 once listening */
} bgp_router_t;

/*
 * Forward declaration for function parameters
 */
typedef struct bgp_sim bgp_sim_t;

/*
 * Router management functions
 */
bgp_router_t* bgp_find_router(bgp_sim_t *sim, uint32_t as_number);
int bgp_add_router(bgp_sim_t *sim, uint32_t as_number);
int bgp_remove_router(bgp_sim_t *sim, uint32_t as_number);
int bgp_set_router_id(bgp_sim_t *sim, uint32_t as_number, const char *router_id_str);
int bgp_set_source_ip(bgp_sim_t *sim, uint32_t as_number, const char *source_ip);
int bgp_clear_source_ip(bgp_sim_t *sim, uint32_t as_number);

/*
 * Called only after all listener/peer callbacks have finished. Retains reusable storage.
 */
void bgp_router_reset(bgp_router_t *router);

#endif /* BGP_ROUTER_H */
