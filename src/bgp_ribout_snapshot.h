#ifndef BGP_RIBOUT_SNAPSHOT_H
#define BGP_RIBOUT_SNAPSHOT_H

#include <stddef.h>
#include <stdint.h>
#include "bgp_ribout_config.h"

/*
 * Published UPDATE output of a ribout block. A successful `update generate` publishes a new snapshot; a snapshot never
 * changes after that. The block holds a reference to its current snapshot and every peer that has it bound or queued
 * holds one too, so a regeneration or `no ribout` never frees bytes that a peer still sends or must withdraw.
 *
 * Every command runs on the runtime loop thread, as do the peer write callbacks, so the reference counts need no
 * atomics.
 */

/*
 * A reference-counted list of complete UPDATE messages in send order.
 */
typedef struct bgp_msg_stream {
    uint32_t                refs;       /* References held by snapshots, peers and jobs */
    bgp_msg_t              *msgs;       /* Owned message list                           */
    size_t                  count;      /* Messages in msgs                             */
    uint64_t                bytes;      /* Sum of the message lengths                   */
    struct bgp_msg_stream **weak_slot;  /* Cache pointer cleared when freed, or NULL    */
} bgp_msg_stream_t;

/*
 * What the bytes of a snapshot require from a peer's negotiated session.
 */
typedef struct {
    uint16_t afi;
    uint8_t  safi;
    uint8_t  family;        /* bgp_ribout_family_t                                */
    uint8_t  add_path;      /* Every NLRI carries a Path ID (RFC 7911)            */
    uint8_t  classic;       /* IPv4 unicast in the classic NLRI field             */
    uint8_t  next_hop_af;   /* AF_INET, AF_INET6, or 0 for no next hop (FlowSpec) */
    uint8_t  needs_ext_nh;  /* IPv4 NLRI over an IPv6 next hop (RFC 8950)         */
} bgp_tx_profile_t;

typedef struct bgp_ribout_snapshot {
    uint64_t             id;                          /* Increasing over the process, never 0             */
    uint32_t             refs;                        /* The block's reference and every peer's           */
    char                 name[BGP_RIBOUT_NAME_SIZE];  /* Ribout name when published                       */
    bgp_tx_profile_t     profile;                     /* What a peer session must accept                  */
    bgp_ribout_config_t *config;                      /* Frozen configuration the snapshot was built from */
    bgp_msg_stream_t    *adv;                         /* Advertisement UPDATEs                            */
    bgp_msg_stream_t    *withdrawal;                  /* Derived withdrawal while held elsewhere (weak)   */
} bgp_ribout_snapshot_t;

/*
 * One AFI/SAFI, for End-of-RIB markers.
 */
typedef struct {
    uint16_t afi;
    uint8_t  safi;
} bgp_afi_safi_t;

/*
 * The wire profile of the messages that block generates. map is the block's grouped map (all its entries share one
 * next-hop family); NULL or empty gives no next hop.
 */
void bgp_ribout_snapshot_profile(const bgp_ribout_config_t *block, const bgp_ribout_map_t *map,
                                 bgp_tx_profile_t *profile);

/*
 * Publish msgs (count messages, bytes octets) as a new snapshot of block with one reference. On success the snapshot
 * owns msgs; on failure (no memory) it returns NULL and msgs still belongs to the caller.
 */
bgp_ribout_snapshot_t *bgp_ribout_snapshot_create(const bgp_ribout_config_t *block, const bgp_tx_profile_t *profile,
                                                  bgp_msg_t *msgs, size_t count, uint64_t bytes);

/*
 * Take and drop references. ref returns its argument; unref of NULL does nothing.
 */
bgp_ribout_snapshot_t *bgp_ribout_snapshot_ref(bgp_ribout_snapshot_t *snapshot);
void bgp_ribout_snapshot_unref(bgp_ribout_snapshot_t *snapshot);

/*
 * A stream that owns msgs (count messages, bytes octets), with one reference; NULL (msgs still the caller's) when
 * there is no memory.
 */
bgp_msg_stream_t *bgp_msg_stream_create(bgp_msg_t *msgs, size_t count, uint64_t bytes);
bgp_msg_stream_t *bgp_msg_stream_ref(bgp_msg_stream_t *stream);
/*
 * Both streams hold the same messages, byte for byte.
 */
int bgp_msg_stream_equal(const bgp_msg_stream_t *a, const bgp_msg_stream_t *b);
void bgp_msg_stream_unref(bgp_msg_stream_t *stream);

/*
 * The withdrawal stream of snapshot, with a new reference. It is derived from the advertisement bytes, not from the
 * map or configuration, so it carries exactly the advertised route keys and Add-Path IDs in advertisement order:
 * classic IPv4 NLRI become Withdrawn Routes, MP NLRI become MP_UNREACH_NLRI, and labeled-unicast and VPN labels
 * become the compatibility label 0x800000 (RFC 8277 section 2.4). Every UPDATE is filled up to 4096 octets. Peers
 * withdrawing the same snapshot share one stream; it is freed with its last reference. NULL when there is no memory
 * or the advertisement bytes do not parse.
 */
bgp_msg_stream_t *bgp_ribout_snapshot_withdrawal(bgp_ribout_snapshot_t *snapshot);

/*
 * End-of-RIB markers (RFC 4724 section 2), one UPDATE per family in order: an empty UPDATE for IPv4 unicast and an
 * MP_UNREACH_NLRI with no NLRI for any other family. NULL when there is no memory.
 */
bgp_msg_stream_t *bgp_msg_stream_eor(const bgp_afi_safi_t *families, size_t count);

/*
 * Route-key comparison from the frozen configurations (bgp_ribout_keyspace.c). The Add-Path ID is part of a key when
 * Add-Path is on; labels, ESI and EVPN Type 5 gateway IP are not.
 * keys_overlap is sound: 1 whenever a and b can generate a common route key, and 1 when unsure.
 * same_keys is conservative: 1 only when a and b generate the same set of route keys.
 */
int bgp_ribout_snapshot_keys_overlap(const bgp_ribout_snapshot_t *a, const bgp_ribout_snapshot_t *b);
int bgp_ribout_snapshot_same_keys(const bgp_ribout_snapshot_t *a, const bgp_ribout_snapshot_t *b);

/*
 * "<family>, add-path on|off, classic|MP[, ext-nh]" for show output.
 */
void bgp_tx_profile_to_string(const bgp_tx_profile_t *profile, char *buf, size_t len);

#endif /* BGP_RIBOUT_SNAPSHOT_H */
