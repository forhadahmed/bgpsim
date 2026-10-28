#ifndef BGP_TX_H
#define BGP_TX_H

#include <stddef.h>
#include <stdint.h>
#include "bgp_neighbor.h"
#include "bgp_ribout_snapshot.h"

/*
 * Whether a peer's negotiated session accepts the bytes of a snapshot. bgpsim does not re-encode per peer: a
 * snapshot whose wire profile the session cannot parse is withheld from that peer, with the reason shown.
 */
typedef enum {
    BGP_TX_COMPAT_OK = 0,
    BGP_TX_COMPAT_FAMILY,              /* AFI/SAFI not negotiated                                  */
    BGP_TX_COMPAT_AS4,                 /* AS_PATH is 4-octet; 4-octet AS not negotiated (RFC 6793) */
    BGP_TX_COMPAT_ADDPATH_REQUIRED,    /* Path IDs in the snapshot; ADD-PATH send not negotiated   */
    BGP_TX_COMPAT_ADDPATH_UNEXPECTED,  /* ADD-PATH send negotiated; the snapshot has no Path IDs   */
    BGP_TX_COMPAT_EXT_NH,              /* IPv4 NLRI over an IPv6 next hop; RFC 8950 not negotiated */
} bgp_tx_compat_t;

/*
 * Both sides support the family: each lists it in a Multiprotocol capability, or sent no Multiprotocol capability
 * at all and the family is IPv4 unicast (RFC 4760 section 8). 0 before the peer's OPEN.
 */
int bgp_tx_family_negotiated(const bgp_neighbor_t *neighbor, uint16_t afi, uint8_t safi);

/*
 * We may send Path IDs to the peer for the family (RFC 7911): Multiprotocol on locally, we advertised send, and the
 * peer advertised receive.
 */
int bgp_tx_add_path_send(const bgp_neighbor_t *neighbor, uint16_t afi, uint8_t safi);

/*
 * Check the snapshot profile against the session; the first failing rule wins.
 */
bgp_tx_compat_t bgp_tx_check(const bgp_tx_profile_t *profile, const bgp_neighbor_t *neighbor);

/*
 * Show text for a result, naming the family of profile.
 */
void bgp_tx_compat_reason(bgp_tx_compat_t result, const bgp_tx_profile_t *profile, char *buf, size_t len);

#endif /* BGP_TX_H */
