#include <stdio.h>
#include "bgp.h"
#include "bgp_tx.h"

static int caps_mp(const bgp_capabilities_t *caps, const bgp_family_t *family) {
    return *(const int *)((const char *)caps + family->mp_offset);
}

static int caps_any_mp(const bgp_capabilities_t *caps) {
    for (int i = 0; i < BGP_NUM_FAMILIES; i++) {
        if (bgp_families[i].mp_offset != NO_CAP_OFFSET && caps_mp(caps, &bgp_families[i])) {
            return 1;
        }
    }
    return 0;
}

int bgp_tx_family_negotiated(const bgp_neighbor_t *neighbor, uint16_t afi, uint8_t safi) {
    const bgp_family_t *family = bgp_family_lookup(afi, safi);
    int                 ipv4_unicast = afi == AFI_IPV4 && safi == SAFI_UNICAST;
    int local, peer;

    if (!neighbor || !neighbor->peer_capabilities_received || !family || family->mp_offset == NO_CAP_OFFSET) {
        return 0;
    }
    // Our OPEN lists exactly the families enabled locally; with none, it sends no Multiprotocol capability.
    local = caps_mp(&neighbor->capabilities, family) || (ipv4_unicast && !caps_any_mp(&neighbor->capabilities));
    peer = caps_mp(&neighbor->peer_capabilities, family) ||
           (ipv4_unicast && !neighbor->peer_mp_capability_received);
    return local && peer;
}

int bgp_tx_add_path_send(const bgp_neighbor_t *neighbor, uint16_t afi, uint8_t safi) {
    const bgp_family_t *family = bgp_family_lookup(afi, safi);

    // Our OPEN carries ADD-PATH only for families with Multiprotocol on, whatever the configured mode says.
    return neighbor && family && family->mp_offset != NO_CAP_OFFSET &&
           caps_mp(&neighbor->capabilities, family) &&
           bgp_caps_add_path_can_send(&neighbor->capabilities, &neighbor->peer_capabilities, afi, safi);
}

bgp_tx_compat_t bgp_tx_check(const bgp_tx_profile_t *profile, const bgp_neighbor_t *neighbor) {
    const bgp_family_t *family = bgp_family_lookup(profile->afi, profile->safi);

    if (!bgp_tx_family_negotiated(neighbor, profile->afi, profile->safi)) {
        return BGP_TX_COMPAT_FAMILY;
    }
    if (!neighbor->capabilities.four_byte_asn || !neighbor->peer_capabilities.four_byte_asn) {
        return BGP_TX_COMPAT_AS4;
    }
    if (profile->add_path != (uint8_t)bgp_tx_add_path_send(neighbor, profile->afi, profile->safi)) {
        return profile->add_path ? BGP_TX_COMPAT_ADDPATH_REQUIRED : BGP_TX_COMPAT_ADDPATH_UNEXPECTED;
    }
    if (profile->needs_ext_nh &&
        !(caps_mp(&neighbor->capabilities, family) &&
          bgp_caps_has_ext_nh(&neighbor->capabilities, profile->afi, profile->safi, AFI_IPV6) &&
          bgp_caps_has_ext_nh(&neighbor->peer_capabilities, profile->afi, profile->safi, AFI_IPV6))) {
        return BGP_TX_COMPAT_EXT_NH;
    }
    return BGP_TX_COMPAT_OK;
}

void bgp_tx_compat_reason(bgp_tx_compat_t result, const bgp_tx_profile_t *profile, char *buf, size_t len) {
    const bgp_family_t *family = bgp_family_lookup(profile->afi, profile->safi);
    const char         *name = family ? family->display_name : "unknown family";

    switch (result) {
        case BGP_TX_COMPAT_OK:
            snprintf(buf, len, "compatible");
            break;
        case BGP_TX_COMPAT_FAMILY:
            snprintf(buf, len, "%s not negotiated", name);
            break;
        case BGP_TX_COMPAT_AS4:
            snprintf(buf, len, "4-octet AS not negotiated (AS_PATH is 4-octet)");
            break;
        case BGP_TX_COMPAT_ADDPATH_REQUIRED:
            snprintf(buf, len, "ribout has path-id but ADD-PATH send is not negotiated for %s", name);
            break;
        case BGP_TX_COMPAT_ADDPATH_UNEXPECTED:
            snprintf(buf, len, "ADD-PATH is negotiated for %s but the ribout has no path-id", name);
            break;
        case BGP_TX_COMPAT_EXT_NH:
            snprintf(buf, len, "extended next hop for %s over IPv6 not negotiated", name);
            break;
    }
}
