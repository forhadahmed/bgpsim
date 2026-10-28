#ifndef BGPSIM_TEST_ROUTE_KEYS_H
#define BGPSIM_TEST_ROUTE_KEYS_H

/*
 * Route keys read from advertised UPDATE bytes with the test-side readers of test_wire.h: the ground truth that
 * keyspace and churn tests compare bgpsim's answers with.
 */
#include <stdlib.h>
#include <string.h>
#include "bgp.h"
#include "test_wire.h"

typedef struct {
    uint8_t len;
    uint8_t bytes[255];
} route_key_t;

typedef struct {
    route_key_t *keys;
    size_t       count;
    size_t       cap;
} key_set_t;

/*
 * The route key of one NLRI from its wire layout: the Path ID with Add-Path; labels masked for labeled-unicast and
 * VPN (RFC 8277); for EVPN only RD, Ethernet tag, MAC and IP of Type 2 (RFC 7432 section 7.2) and RD, Ethernet tag
 * and IP prefix of Type 5 (RFC 9136); the whole NLRI otherwise.
 */
static int route_key(uint16_t afi, uint8_t safi, int add_path, const uint8_t *p, size_t size, route_key_t *key) {
    size_t id = add_path ? 4 : 0;

    key->len = 0;
    memcpy(key->bytes, p, id);
    key->len = (uint8_t)id;
    if (afi == 25 && safi == 70 && (p[id] == 1 || p[id] == 2 || p[id] == 5)) {
        const uint8_t *v = p + id + 2;
        uint8_t        type = p[id], len = p[id + 1];

        key->bytes[key->len++] = type;
        if (type == 1) {
            memcpy(key->bytes + key->len, v, 22); /* RD, ESI, Ethernet tag; label is not a key. */
            key->len += 22;
            return 1;
        }
        memcpy(key->bytes + key->len, v, 8);       /* RD           */
        key->len += 8;
        memcpy(key->bytes + key->len, v + 18, 4);  /* Ethernet tag */
        key->len += 4;
        if (type == 2) {
            size_t ip_bytes = v[29] / 8;

            memcpy(key->bytes + key->len, v + 22, 8 + ip_bytes);  /* MAC length, MAC, IP length, IP */
            key->len += (uint8_t)(8 + ip_bytes);
        } else if (type == 5) {
            size_t ip_bytes = (len == 34) ? 4 : 16;

            memcpy(key->bytes + key->len, v + 22, 1 + ip_bytes);  /* IP prefix length, IP prefix */
            key->len += (uint8_t)(1 + ip_bytes);
        } else {
            return 0;
        }
        return 1;
    }
    if (size - id > sizeof(key->bytes) - id) {
        return 0;
    }
    memcpy(key->bytes + id, p + id, size - id);
    key->len = (uint8_t)size;
    if (safi == 4 || safi == 128) {
        key->bytes[id + 1] = key->bytes[id + 2] = key->bytes[id + 3] = 0;
    }
    if (afi == 25 && safi == 65) {
        // VPLS identity: RD, VE ID and label-block offset, not size or label base.
        memset(key->bytes + id + 14, 0, 5);
    }
    return 1;
}

static int key_compare(const void *a, const void *b) {
    const route_key_t *x = a, *y = b;

    if (x->len != y->len) {
        return x->len < y->len ? -1 : 1;
    }
    return memcmp(x->bytes, y->bytes, x->len);
}

/*
 * The sorted, distinct route keys of an UPDATE list of one family; total, when not NULL, counts every NLRI (a key
 * sent twice counts twice). Returns 0 when an UPDATE or NLRI does not decode.
 */
static int route_key_set(const bgp_msg_t *msgs, uint16_t afi, uint8_t safi, int add_path, key_set_t *set,
                         size_t *total) {
    memset(set, 0, sizeof(*set));
    for (const bgp_msg_t *msg = msgs; msg; msg = msg->next) {
        test_wire_update_t view;
        const uint8_t     *nlri;
        size_t             len;

        if (!test_wire_update_view(msg->data, msg->length, &view)) {
            return 0;
        }
        nlri = view.has_reach ? view.reach : view.nlri;
        len = view.has_reach ? view.reach_len : view.nlri_len;
        for (size_t off = 0; off < len;) {
            size_t size = test_wire_nlri_size(afi, safi, add_path, nlri + off, len - off);

            if (size == 0) {
                return 0;
            }
            if (set->count == set->cap) {
                set->cap = set->cap ? set->cap * 2 : 64;
                set->keys = realloc(set->keys, set->cap * sizeof(*set->keys));
            }
            if (!route_key(afi, safi, add_path, nlri + off, size, &set->keys[set->count++])) {
                return 0;
            }
            off += size;
        }
    }
    if (total) {
        *total = set->count;
    }
    qsort(set->keys, set->count, sizeof(*set->keys), key_compare);
    size_t distinct = 0;
    for (size_t i = 0; i < set->count; i++) {
        if (distinct == 0 || key_compare(&set->keys[distinct - 1], &set->keys[i]) != 0) {
            set->keys[distinct++] = set->keys[i];
        }
    }
    set->count = distinct;
    return 1;
}

#endif /* BGPSIM_TEST_ROUTE_KEYS_H */
