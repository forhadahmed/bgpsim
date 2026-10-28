#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "bgp.h"
#include "bgp_ribout.h"
#include "bgp_update.h"
#include "bgp_ribout_snapshot.h"

/*
 * Snapshot ids only increase, so a script run can tell generations apart by id alone. Snapshots are created on the
 * loop thread (or by a single-threaded test).
 */
static uint64_t g_next_snapshot_id = 1;

void bgp_ribout_snapshot_profile(const bgp_ribout_config_t *block, const bgp_ribout_map_t *map,
                                 bgp_tx_profile_t *profile) {
    bgp_ribout_family_t             family = bgp_ribout_resolve_family(block);
    const bgp_ribout_family_info_t *info = bgp_ribout_family_info(family);
    int ipv4_nlri = family == BGP_RIBOUT_FAMILY_IPV4_UNICAST || family == BGP_RIBOUT_FAMILY_LABELED_IPV4 ||
                    family == BGP_RIBOUT_FAMILY_VPNV4;

    memset(profile, 0, sizeof(*profile));
    profile->afi = info->afi;
    profile->safi = info->safi;
    profile->family = (uint8_t)family;
    profile->add_path = block->path_id_count > 0;
    profile->next_hop_af = (map && map->order_head) ? map->order_head->next_hop_af : 0;
    /*
     * The same choices as bgp_ribout_generate_entry_messages(): classic NEXT_HOP and NLRI only for IPv4 unicast over
     * IPv4. The extended next-hop capability covers IPv4 unicast, labeled-unicast and VPNv4 over IPv6.
     */
    profile->classic = family == BGP_RIBOUT_FAMILY_IPV4_UNICAST && profile->next_hop_af == AF_INET;
    profile->needs_ext_nh = ipv4_nlri && profile->next_hop_af == AF_INET6;
}

bgp_msg_stream_t *bgp_msg_stream_create(bgp_msg_t *msgs, size_t count, uint64_t bytes) {
    bgp_msg_stream_t *stream = calloc(1, sizeof(*stream));

    if (!stream) {
        return NULL;
    }
    stream->refs = 1;
    stream->msgs = msgs;
    stream->count = count;
    stream->bytes = bytes;
    return stream;
}

bgp_msg_stream_t *bgp_msg_stream_ref(bgp_msg_stream_t *stream) {
    if (stream) {
        stream->refs++;
    }
    return stream;
}

int bgp_msg_stream_equal(const bgp_msg_stream_t *a, const bgp_msg_stream_t *b) {
    const bgp_msg_t *x, *y;

    if (a->count != b->count || a->bytes != b->bytes) {
        return 0;
    }
    for (x = a->msgs, y = b->msgs; x && y; x = x->next, y = y->next) {
        if (x->length != y->length || memcmp(x->data, y->data, x->length) != 0) {
            return 0;
        }
    }
    return x == NULL && y == NULL;
}

void bgp_msg_stream_unref(bgp_msg_stream_t *stream) {
    if (!stream || --stream->refs > 0) {
        return;
    }
    if (stream->weak_slot) {
        *stream->weak_slot = NULL;
    }
    bgp_msg_list_free(stream->msgs);
    free(stream);
}

bgp_ribout_snapshot_t *bgp_ribout_snapshot_create(const bgp_ribout_config_t *block, const bgp_tx_profile_t *profile,
                                                  bgp_msg_t *msgs, size_t count, uint64_t bytes) {
    bgp_ribout_snapshot_t *snapshot = calloc(1, sizeof(*snapshot));

    if (!snapshot) {
        return NULL;
    }
    // The stream is the last allocation, so msgs changes owner only when nothing else can fail.
    snapshot->config = bgp_ribout_config_clone(block);
    snapshot->adv = snapshot->config ? bgp_msg_stream_create(msgs, count, bytes) : NULL;
    if (!snapshot->adv) {
        bgp_ribout_config_clone_free(snapshot->config);
        free(snapshot);
        return NULL;
    }
    snapshot->id = g_next_snapshot_id++;
    snapshot->refs = 1;
    snprintf(snapshot->name, sizeof(snapshot->name), "%s", block->name);
    snapshot->profile = *profile;
    return snapshot;
}

bgp_ribout_snapshot_t *bgp_ribout_snapshot_ref(bgp_ribout_snapshot_t *snapshot) {
    if (snapshot) {
        snapshot->refs++;
    }
    return snapshot;
}

void bgp_ribout_snapshot_unref(bgp_ribout_snapshot_t *snapshot) {
    if (!snapshot || --snapshot->refs > 0) {
        return;
    }
    // A derived withdrawal can outlive its snapshot in a peer queue; it must not clear a freed cache slot.
    if (snapshot->withdrawal) {
        snapshot->withdrawal->weak_slot = NULL;
    }
    bgp_msg_stream_unref(snapshot->adv);
    bgp_ribout_config_clone_free(snapshot->config);
    free(snapshot);
}

void bgp_tx_profile_to_string(const bgp_tx_profile_t *profile, char *buf, size_t len) {
    snprintf(buf, len, "%s, add-path %s, %s%s",
             bgp_ribout_family_info((bgp_ribout_family_t)profile->family)->name,
             profile->add_path ? "on" : "off",
             profile->classic ? "classic" : "MP",
             profile->needs_ext_nh ? ", ext-nh" : "");
}

// Withdrawal and End-of-RIB streams

/*
 * Collects UPDATEs from a builder into a message list.
 */
typedef struct {
    bgp_builder_t builder;
    bgp_msg_t    *head;
    bgp_msg_t    *tail;
    size_t        count;
    uint64_t      bytes;
} stream_writer_t;

static int stream_writer_init(stream_writer_t *writer) {
    memset(writer, 0, sizeof(*writer));
    return bgp_builder_init(&writer->builder);
}

/*
 * Move the builder's UPDATEs to the list.
 */
static int stream_writer_collect(stream_writer_t *writer) {
    bgp_update_result_t *result = writer->builder.result;

    for (int i = 0; i < result->num_messages; i++) {
        bgp_msg_t *msg = malloc(sizeof(*msg));

        if (!msg) {
            return -1;
        }
        msg->data = result->messages[i];
        msg->length = result->message_lens[i];
        msg->next = NULL;
        result->messages[i] = NULL;
        if (writer->tail) {
            writer->tail->next = msg;
        } else {
            writer->head = msg;
        }
        writer->tail = msg;
        writer->count++;
        writer->bytes += msg->length;
    }
    bgp_builder_clear(&writer->builder);
    return 0;
}

/*
 * The stream of the collected UPDATEs, or NULL (everything freed) on failure.
 */
static bgp_msg_stream_t *stream_writer_finish(stream_writer_t *writer, int failed) {
    bgp_msg_stream_t *stream = NULL;

    bgp_builder_release(&writer->builder);
    if (!failed) {
        stream = bgp_msg_stream_create(writer->head, writer->count, writer->bytes);
    }
    if (!stream) {
        bgp_msg_list_free(writer->head);
    }
    return stream;
}

/*
 * Withdrawn NLRI packed into UPDATEs of at most BGP_MAX_PDU_SIZE octets.
 */
typedef struct {
    stream_writer_t         out;
    const bgp_tx_profile_t *profile;
    int                     budget;  /* NLRI octets per UPDATE */
    int                     used;
    uint8_t                 nlri[BGP_MAX_PDU_SIZE];
} withdrawal_writer_t;

static int withdrawal_flush(withdrawal_writer_t *writer) {
    int rc;

    if (writer->used == 0) {
        return 0;
    }
    if (writer->profile->classic) {
        rc = bgp_builder_append(&writer->out.builder, writer->nlri, (uint16_t)writer->used, NULL, 0, NULL, 0);
    } else {
        bgp_mp_args_t args = {
            .is_reach    = 0,
            .afi         = writer->profile->afi,
            .safi        = writer->profile->safi,
            .mp_nlri     = writer->nlri,
            .mp_nlri_len = (uint16_t)writer->used,
        };
        rc = bgp_builder_append_mp(&writer->out.builder, &args);
    }
    writer->used = 0;
    return (rc < 0) ? -1 : stream_writer_collect(&writer->out);
}

/*
 * Octets of the NLRI at p, Add-Path ID included; -1 when it does not fit in len octets. The rules follow the family
 * encoders: a prefix length in bits for unicast, labeled-unicast and VPN (RFC 4271, RFC 8277, RFC 4364), a route-type
 * length for EVPN (RFC 7432), a length in bits for SR Policy (RFC 9830), and a one- or two-octet length for FlowSpec
 * (RFC 8955 section 4).
 */
static int withdrawal_nlri_size(const bgp_tx_profile_t *profile, const uint8_t *p, size_t len) {
    size_t ap = profile->add_path ? 4 : 0;
    size_t size;

    if (len < ap + 1) {
        return -1;
    }
    switch (bgp_ribout_family_info((bgp_ribout_family_t)profile->family)->kind) {
        case BGP_RIBOUT_KIND_PREFIX:
            if (profile->afi == AFI_L2VPN) {
                if (len < ap + 2) {
                    return -1;
                }
                size = ap + 2 + p[ap + 1];
            } else {
                size = ap + 1 + ((size_t)p[ap] + 7) / 8;
            }
            break;
        case BGP_RIBOUT_KIND_EVPN_TYPE2:
            if (len < ap + 2) {
                return -1;
            }
            size = ap + 2 + p[ap + 1];
            break;
        case BGP_RIBOUT_KIND_SR_POLICY:
            size = ap + 1 + (size_t)p[ap] / 8;
            break;
        case BGP_RIBOUT_KIND_FLOWSPEC:
            if (p[ap] >= 0xF0) {
                if (len < ap + 2) {
                    return -1;
                }
                size = ap + 2 + ((((size_t)p[ap] & 0x0F) << 8) | p[ap + 1]);
            } else {
                size = ap + 1 + p[ap];
            }
            break;
        case BGP_RIBOUT_KIND_TEMPLATE:
            if (profile->safi == SAFI_RTC) {
                size = ap + 1 + ((size_t)p[ap] + 7) / 8;
            } else if (profile->afi == AFI_BGP_LS) {
                if (len < ap + 4) return -1;
                size = ap + 4 + ((size_t)p[ap + 2] << 8) + p[ap + 3];
            } else if (profile->safi == SAFI_VPLS) {
                if (len < ap + 2) return -1;
                size = ap + 2 + ((size_t)p[ap] << 8) + p[ap + 1];
            } else {
                // EVPN and MVPN: route type plus one-octet body length.
                if (len < ap + 2) return -1;
                size = ap + 2 + p[ap + 1];
            }
            break;
        default:
            return -1;
    }
    return (size <= len) ? (int)size : -1;
}

static int withdrawal_needs_compat_label(const bgp_tx_profile_t *profile) {
    return profile->safi == SAFI_LABELED_UNICAST || profile->safi == SAFI_MPLS_VPN;
}

/*
 * Copy the NLRI field of one advertisement into withdrawal UPDATEs: runs of whole NLRI that fit, labels rewritten.
 */
static int withdrawal_append(withdrawal_writer_t *writer, const uint8_t *nlri, size_t len) {
    size_t off = 0;
    size_t ap = writer->profile->add_path ? 4 : 0;

    while (off < len) {
        size_t run = 0;
        size_t room = (size_t)(writer->budget - writer->used);

        while (off + run < len) {
            int size = withdrawal_nlri_size(writer->profile, nlri + off + run, len - off - run);

            if (size < 0 || (size_t)size > (size_t)writer->budget ||
                (withdrawal_needs_compat_label(writer->profile) && (size_t)size < ap + 4)) {
                return -1;
            }
            if (run + (size_t)size > room) {
                break;
            }
            run += (size_t)size;
        }
        if (run == 0) {
            if (withdrawal_flush(writer) < 0) {
                return -1;
            }
            continue;
        }

        memcpy(writer->nlri + writer->used, nlri + off, run);
        if (withdrawal_needs_compat_label(writer->profile)) {
            uint8_t *p = writer->nlri + writer->used;

            for (size_t at = 0; at < run;
                 at += (size_t)withdrawal_nlri_size(writer->profile, p + at, run - at)) {
                p[at + ap + 1] = 0x80;
                p[at + ap + 2] = 0x00;
                p[at + ap + 3] = 0x00;
            }
        }
        writer->used += (int)run;
        off += run;
    }
    return 0;
}

static uint16_t read_u16_be(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

/*
 * The NLRI field of one advertisement: in MP_REACH_NLRI, or after the path attributes (classic IPv4). -1 when the
 * UPDATE does not parse.
 */
static int advertisement_nlri(const bgp_msg_t *msg, const uint8_t **nlri, size_t *nlri_len) {
    const uint8_t *p = msg->data;
    size_t         len = msg->length;
    size_t         off = BGP_HEADER_SIZE;
    size_t         attrs_end;

    if (len < BGP_HEADER_SIZE + 4 || read_u16_be(p + 16) != len) {
        return -1;
    }
    off += 2 + read_u16_be(p + off);
    if (off + 2 > len) {
        return -1;
    }
    attrs_end = off + 2 + read_u16_be(p + off);
    off += 2;
    if (attrs_end > len) {
        return -1;
    }

    *nlri = p + attrs_end;
    *nlri_len = len - attrs_end;
    while (off < attrs_end) {
        size_t header = (off + 1 < attrs_end && (p[off] & BGP_ATTR_FLAG_EXTENDED_LEN)) ? 4 : 3;
        size_t value_len;

        if (off + header > attrs_end) {
            return -1;
        }
        value_len = (header == 4) ? read_u16_be(p + off + 2) : p[off + 2];
        if (off + header + value_len > attrs_end) {
            return -1;
        }
        if (p[off + 1] == BGP_ATTR_MP_REACH_NLRI) {
            const uint8_t *v = p + off + header;
            size_t         skip;

            // AFI (2), SAFI (1), next-hop length (1), next hop, reserved (1)
            if (value_len < 5 || (skip = (size_t)5 + v[3]) > value_len) {
                return -1;
            }
            *nlri = v + skip;
            *nlri_len = value_len - skip;
        }
        off += header + value_len;
    }
    return 0;
}

bgp_msg_stream_t *bgp_ribout_snapshot_withdrawal(bgp_ribout_snapshot_t *snapshot) {
    withdrawal_writer_t *writer;
    bgp_msg_stream_t    *stream;
    int                  failed = 0;

    if (!snapshot) {
        return NULL;
    }
    if (snapshot->withdrawal) {
        return bgp_msg_stream_ref(snapshot->withdrawal);
    }

    writer = malloc(sizeof(*writer));
    if (!writer) {
        return NULL;
    }
    if (stream_writer_init(&writer->out) < 0) {
        free(writer);
        return NULL;
    }
    writer->profile = &snapshot->profile;
    writer->used = 0;
    /*
     * Header, Withdrawn Routes Length (2) and Total Path Attribute Length (2); MP adds an extended-length
     * MP_UNREACH_NLRI header (4), AFI (2) and SAFI (1).
     */
    writer->budget = BGP_MAX_PDU_SIZE - BGP_HEADER_SIZE - 2 - 2 - (snapshot->profile.classic ? 0 : 4 + 2 + 1);

    for (const bgp_msg_t *msg = snapshot->adv->msgs; msg && !failed; msg = msg->next) {
        const uint8_t *nlri;
        size_t         nlri_len;

        failed = advertisement_nlri(msg, &nlri, &nlri_len) < 0 || withdrawal_append(writer, nlri, nlri_len) < 0;
    }
    if (!failed) {
        failed = withdrawal_flush(writer) < 0;
    }
    stream = stream_writer_finish(&writer->out, failed);
    free(writer);

    if (stream) {
        stream->weak_slot = &snapshot->withdrawal;
        snapshot->withdrawal = stream;
    }
    return stream;
}

bgp_msg_stream_t *bgp_msg_stream_eor(const bgp_afi_safi_t *families, size_t count) {
    stream_writer_t writer;
    int             failed;

    if (stream_writer_init(&writer) < 0) {
        return NULL;
    }
    failed = 0;
    for (size_t i = 0; i < count && !failed; i++) {
        int rc;

        if (families[i].afi == AFI_IPV4 && families[i].safi == SAFI_UNICAST) {
            rc = bgp_builder_append(&writer.builder, NULL, 0, NULL, 0, NULL, 0);
        } else {
            bgp_mp_args_t args = {.is_reach = 0, .afi = families[i].afi, .safi = families[i].safi};
            rc = bgp_builder_append_mp(&writer.builder, &args);
        }
        failed = rc < 0 || stream_writer_collect(&writer) < 0;
    }
    return stream_writer_finish(&writer, failed);
}
