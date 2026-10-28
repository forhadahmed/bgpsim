#define OUTPUT_STDIO_REMAP

#include <errno.h>
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/socket.h>
#include "log.h"
#include "bgpsim.h"
#include "output.h"
#include "runtime.h"
#include "bgp_peer_tx.h"

static int bgp_neighbor_error_not_found(const char *ip, uint32_t as_number) {
    fprintf(stderr, "Error: Neighbor %s not found in router BGP %u\n", ip, as_number);
    return -1;
}

static void bgp_close_socket(bgp_neighbor_t *neighbor) {
    if (neighbor->sock_fd >= 0) {
        shutdown(neighbor->sock_fd, SHUT_RDWR);
        close(neighbor->sock_fd);
        neighbor->sock_fd = -1;
    }
}

static void bgp_reset_session(bgp_neighbor_t *neighbor, int record_reset) {
    bgp_close_socket(neighbor);

    if (record_reset) {
        neighbor->session_resets++;
        neighbor->last_reset_time = time(NULL);
    }

    neighbor->state = BGP_STATE_IDLE;
    neighbor->uptime = 0;
    neighbor->last_msg_time = 0;
    neighbor->last_keepalive_sent = 0;
    neighbor->remote_id = 0;
    neighbor->hold_time = 0;
    neighbor->peer_capabilities_received = 0;
    neighbor->peer_mp_capability_received = 0;
    memset(&neighbor->peer_capabilities, 0, sizeof(neighbor->peer_capabilities));
    neighbor->is_passive = 0;
}

void bgp_neighbor_reset(bgp_neighbor_t *neighbor) {
    bgp_peer_tx_destroy(neighbor->tx);
    free(neighbor->advertise);
    memset(neighbor, 0, sizeof(*neighbor));
    neighbor->sock_fd = -1;
}

static int bgp_validate_source_ip_for_af(const char *source_ip, int af) {
    struct in_addr  addr4;
    struct in6_addr addr6;

    if (source_ip == NULL || source_ip[0] == '\0') {
        return -1;
    }

    if (af == AF_INET) {
        return inet_pton(AF_INET, source_ip, &addr4) == 1 ? 0 : -1;
    }

    if (af == AF_INET6) {
        return inet_pton(AF_INET6, source_ip, &addr6) == 1 ? 0 : -1;
    }

    return -1;
}

static int bgp_find_free_neighbor_slot(const bgp_router_t *router) {
    for (int i = 0; i < router->neighbor_count; i++) {
        if (!router->neighbors[i]->active &&
            !router->neighbors[i]->runtime_initialized &&
            !router->neighbors[i]->stream_initialized &&
            !router->neighbors[i]->destroy_pending) {
            return i;
        }
    }

    return router->neighbor_count;
}

static void bgp_trim_neighbor_tail(bgp_router_t *router) {
    while (router->neighbor_count > 0 && !router->neighbors[router->neighbor_count - 1]->active) {
        router->neighbor_count--;
    }
}

bgp_neighbor_t *bgp_find_neighbor(bgp_router_t *router, const char *ip) {
    char canonical[INET6_ADDRSTRLEN];
    if (!router || canonical_ip_address(ip, canonical, sizeof(canonical)) < 0) return NULL;
    for (int i = 0; i < router->neighbor_count; i++) {
        if (router->neighbors[i]->active && strcmp(router->neighbors[i]->ip, canonical) == 0) {
            return router->neighbors[i];
        }
    }

    return NULL;
}

/*
 * Add neighbor ip with remote_as to router BGP as_number. Returns 1 when added, 0 when the same neighbor exists
 * already, and -1 on error (no router, other remote AS, no free slot, bad address). A new neighbor has IPv4 and IPv6
 * unicast and 4-octet AS on, and the runtime is told to connect.
 */
int bgp_add_neighbor(bgp_sim_t *sim, uint32_t as_number, const char *ip, uint32_t remote_as) {
    char            canonical[INET6_ADDRSTRLEN];
    int             af = canonical_ip_address(ip, canonical, sizeof(canonical));
    bgp_router_t   *router;
    bgp_neighbor_t *neighbor;
    int             slot;

    if (af < 0) {
        fprintf(stderr, "Error: Invalid IP address format: %s\n", ip ? ip : "(null)");
        return -1;
    }
    router = bgp_lock_router(sim, as_number);
    if (!router) {
        return -1;
    }

    neighbor = bgp_find_neighbor(router, canonical);
    if (neighbor) {
        if (neighbor->remote_as != remote_as) {
            pthread_mutex_unlock(&sim->model_lock);
            fprintf(stderr, "Error: Neighbor %s already exists with remote-as %u\n", ip, neighbor->remote_as);
            return -1;
        }

        log_write("Neighbor %s already exists for BGP %u\n", ip, as_number);
        pthread_mutex_unlock(&sim->model_lock);
        return 0;
    }

    slot = bgp_find_free_neighbor_slot(router);
    if (slot == INT_MAX) {
        pthread_mutex_unlock(&sim->model_lock);
        fprintf(stderr, "Error: Maximum number of neighbors reached for BGP %u\n", as_number);
        return -1;
    }

    neighbor = slot < router->neighbor_capacity ? router->neighbors[slot] : NULL;
    if (!neighbor) {
        neighbor = calloc(1, sizeof(*neighbor));
        bgp_neighbor_t **table = neighbor ? array_reserve(router->neighbors, sizeof(*table),
                                                          &router->neighbor_capacity, slot + 1) : NULL;
        if (!table) {
            free(neighbor);
            pthread_mutex_unlock(&sim->model_lock);
            fprintf(stderr, "Error: Failed to allocate neighbor %s\n", ip);
            return -1;
        }
        router->neighbors = table;
        router->neighbors[slot] = neighbor;
    }
    bgp_neighbor_reset(neighbor);
    snprintf(neighbor->ip, sizeof(neighbor->ip), "%s", canonical);
    neighbor->remote_as = remote_as;
    neighbor->state = BGP_STATE_IDLE;
    neighbor->sock_fd = -1;
    neighbor->active = 1;
    neighbor->router = router;

    neighbor->af = af;

    neighbor->capabilities = bgp_default_capabilities;
    neighbor->hold_time_config = BGP_HOLD_TIME;

    if (slot == router->neighbor_count) {
        router->neighbor_count++;
    }

    log_write("Added neighbor %s (AS %u) to router BGP %u\n", ip, remote_as, as_number);

    pthread_mutex_unlock(&sim->model_lock);

    if (sim->runtime) {
        bgpsim_runtime_reconcile(sim->runtime);
    }

    return 1;
}

int bgp_remove_neighbor(bgp_sim_t *sim, uint32_t as_number, const char *ip) {
    bgp_router_t   *router;
    bgp_neighbor_t *neighbor = NULL;

    router = bgp_lock_router(sim, as_number);
    if (!router) {
        return -1;
    }

    neighbor = bgp_find_neighbor(router, ip);
    if (neighbor) {
        neighbor->active = 0;
    }

    pthread_mutex_unlock(&sim->model_lock);

    if (!neighbor) {
        return bgp_neighbor_error_not_found(ip, as_number);
    }

    if (sim->runtime) {
        bgpsim_runtime_reconcile(sim->runtime);
    } else {
        pthread_mutex_lock(&sim->model_lock);
        bgp_neighbor_reset(neighbor);
        bgp_trim_neighbor_tail(router);
        pthread_mutex_unlock(&sim->model_lock);
    }

    log_write("Removed neighbor %s from router BGP %u\n", ip, as_number);
    return 1;
}

int bgp_set_neighbor_source_ip(bgp_sim_t *sim, uint32_t as_number, const char *ip, const char *source_ip) {
    bgp_router_t   *router;
    bgp_neighbor_t *neighbor;

    router = bgp_lock_router(sim, as_number);
    if (!router) {
        return -1;
    }

    neighbor = bgp_find_neighbor(router, ip);
    if (!neighbor) {
        pthread_mutex_unlock(&sim->model_lock);
        return bgp_neighbor_error_not_found(ip, as_number);
    }

    if (bgp_validate_source_ip_for_af(source_ip, neighbor->af) != 0) {
        pthread_mutex_unlock(&sim->model_lock);
        fprintf(stderr, "Error: Invalid %s update-source for neighbor %s: %s\n",
                neighbor->af == AF_INET ? "IPv4" : "IPv6", ip, source_ip);
        return -1;
    }

    strncpy(neighbor->source_ip, source_ip, sizeof(neighbor->source_ip) - 1);
    neighbor->source_ip[sizeof(neighbor->source_ip) - 1] = '\0';

    pthread_mutex_unlock(&sim->model_lock);

    printf("Set neighbor update-source %s for %s in BGP %u\n", source_ip, ip, as_number);
    fflush(stdout);
    return 1;
}

int bgp_clear_neighbor_source_ip(bgp_sim_t *sim, uint32_t as_number, const char *ip) {
    bgp_router_t   *router;
    bgp_neighbor_t *neighbor;

    router = bgp_lock_router(sim, as_number);
    if (!router) {
        return -1;
    }

    neighbor = bgp_find_neighbor(router, ip);
    if (!neighbor) {
        pthread_mutex_unlock(&sim->model_lock);
        return bgp_neighbor_error_not_found(ip, as_number);
    }

    neighbor->source_ip[0] = '\0';

    pthread_mutex_unlock(&sim->model_lock);

    printf("Cleared neighbor update-source for %s in BGP %u\n", ip, as_number);
    fflush(stdout);
    return 1;
}

void bgp_clear_neighbor(bgp_neighbor_t *neighbor) {
    if (!neighbor || !neighbor->active) {
        return;
    }

    if (neighbor->router && neighbor->router->sim && neighbor->router->sim->runtime) {
        bgpsim_runtime_clear_neighbor(neighbor, 1);
        return;
    }

    bgp_reset_session(neighbor, 1);
    LOG_INFO("BGP session cleared for %s (reset #%" PRIu64 ")", neighbor->ip, neighbor->session_resets);
}

/*
 * A setting of the OPEN or of the socket changed: a session that is up or coming up starts again. Not while a configuration file
 * is loading, when no session has started.
 */
static void bgp_neighbor_renegotiate(bgp_neighbor_t *neighbor) {
    if (!neighbor->router->sim->config_loading &&
        (neighbor->stream_open || neighbor->connect_pending || neighbor->sock_fd >= 0 ||
         neighbor->state != BGP_STATE_IDLE)) {
        bgp_clear_neighbor(neighbor);
    }
}

int bgp_neighbor_set_hold_time(bgp_neighbor_t *neighbor, uint32_t seconds) {
    if (!neighbor || !neighbor->active || !neighbor->router) {
        return -1;
    }
    // RFC 4271 section 4.2: zero, or at least three seconds.
    if (seconds > UINT16_MAX || seconds == 1 || seconds == 2) {
        fprintf(stderr, "Error: hold-time is 0, or 3-65535 seconds\n");
        return -1;
    }
    if (neighbor->hold_time_config == seconds) {
        return 0;
    }
    neighbor->hold_time_config = (uint16_t)seconds;
    bgp_neighbor_renegotiate(neighbor);
    return 0;
}

int bgp_neighbor_set_ttl_security(bgp_neighbor_t *neighbor, uint32_t hops) {
    if (!neighbor || !neighbor->active || !neighbor->router) {
        return -1;
    }
    if (hops > 254) {
        fprintf(stderr, "Error: ttl-security hops is 1-254\n");
        return -1;
    }
    if (neighbor->ttl_security_hops != hops) {
        neighbor->ttl_security_hops = (uint8_t)hops;
        bgp_neighbor_renegotiate(neighbor);
    }
    return 0;
}

int bgp_neighbor_set_password(bgp_neighbor_t *neighbor, const char *password) {
    if (!neighbor || !neighbor->active || !neighbor->router) {
        return -1;
    }
    if (!password) {
        password = "";
    }
    if (strlen(password) >= sizeof(neighbor->password)) {
        fprintf(stderr, "Error: a password is at most %zu octets\n", sizeof(neighbor->password) - 1);
        return -1;
    }
    if (strcmp(neighbor->password, password) != 0) {
        snprintf(neighbor->password, sizeof(neighbor->password), "%s", password);
        // A passive listener checks the key on the SYN, before there is a session to reset.
        bgpsim_runtime_neighbor_password_changed(neighbor);
        bgp_neighbor_renegotiate(neighbor);
    }
    return 0;
}

int bgp_neighbor_set_shutdown(bgp_neighbor_t *neighbor, int shutdown, const char *text) {
    if (!neighbor || !neighbor->active || !neighbor->router) {
        return -1;
    }
    if (text && strlen(text) >= sizeof(neighbor->shutdown_text)) {
        fprintf(stderr, "Error: a Shutdown Communication is at most 255 octets\n");
        return -1;
    }
    neighbor->admin_shutdown = shutdown != 0;
    snprintf(neighbor->shutdown_text, sizeof(neighbor->shutdown_text), "%s", shutdown && text ? text : "");
    bgpsim_runtime_shutdown_neighbor(neighbor);
    return 0;
}

int bgp_neighbor_apply_capabilities(bgp_neighbor_t *neighbor, const bgp_capabilities_t *caps) {
    const bgp_capabilities_t *old;
    int                       changed;

    if (!neighbor || !neighbor->active || !neighbor->router || !caps) {
        return -1;
    }
    if (caps->restart_time > 4095) {
        fprintf(stderr, "Error: graceful-restart restart-time must be between 0 and 4095\n");
        return -1;
    }
    if (!caps->four_byte_asn &&
        (neighbor->router->local_as > UINT16_MAX || neighbor->remote_as > UINT16_MAX)) {
        fprintf(stderr, "Error: four-byte ASN capability cannot be disabled when local-as "
                        "or remote-as exceeds 65535\n");
        return -1;
    }

    old = &neighbor->capabilities;
    changed = old->route_refresh != caps->route_refresh ||
              old->extended_message != caps->extended_message ||
              old->four_byte_asn != caps->four_byte_asn ||
              old->graceful_restart != caps->graceful_restart ||
              old->restart_time != caps->restart_time ||
              old->gr_family_mask != caps->gr_family_mask ||
              old->gr_forwarding_mask != caps->gr_forwarding_mask;
    // Compare fields, not struct padding. The family table owns the per-family layout.
    for (int i = 0; i < BGP_NUM_FAMILIES; i++) {
        const bgp_family_t *family = &bgp_families[i];

        changed |= *(const int *)((const char *)old + family->mp_offset) !=
                   *(const int *)((const char *)caps + family->mp_offset);
        changed |= bgp_caps_get_add_path(old, family->afi, family->safi) !=
                   bgp_caps_get_add_path(caps, family->afi, family->safi);
        changed |= bgp_caps_has_ext_nh(old, family->afi, family->safi, AFI_IPV6) !=
                   bgp_caps_has_ext_nh(caps, family->afi, family->safi, AFI_IPV6);
    }
    // Always store the candidate; the comparison only decides whether the peer must renegotiate its OPEN.
    neighbor->capabilities = *caps;
    if (changed) {
        bgp_neighbor_renegotiate(neighbor);
    }
    return 1;
}

/*
 * Error codes and subcodes from the IANA "BGP Error (Notification) Codes" registry.
 */
static const struct {
    uint8_t     code;
    uint8_t     subcode;  /* 0 names the code itself */
    const char *name;
} bgp_notification_names[] = {
    {1,  0, "Message Header Error"},                  /* RFC 4271 */
    {1,  1, "Connection Not Synchronized"},
    {1,  2, "Bad Message Length"},
    {1,  3, "Bad Message Type"},
    {2,  0, "OPEN Message Error"},
    {2,  1, "Unsupported Version Number"},
    {2,  2, "Bad Peer AS"},
    {2,  3, "Bad BGP Identifier"},
    {2,  4, "Unsupported Optional Parameter"},
    {2,  5, "Authentication Failure"},
    {2,  6, "Unacceptable Hold Time"},
    {2,  7, "Unsupported Capability"},                /* RFC 5492 */
    {2, 11, "Role Mismatch"},                         /* RFC 9234 */
    {3,  0, "UPDATE Message Error"},
    {3,  1, "Malformed Attribute List"},
    {3,  2, "Unrecognized Well-known Attribute"},
    {3,  3, "Missing Well-known Attribute"},
    {3,  4, "Attribute Flags Error"},
    {3,  5, "Attribute Length Error"},
    {3,  6, "Invalid ORIGIN Attribute"},
    {3,  7, "AS Routing Loop"},
    {3,  8, "Invalid NEXT_HOP Attribute"},
    {3,  9, "Optional Attribute Error"},
    {3, 10, "Invalid Network Field"},
    {3, 11, "Malformed AS_PATH"},
    {4,  0, "Hold Timer Expired"},
    {5,  0, "Finite State Machine Error"},
    {5,  1, "Unexpected Message in OpenSent State"},  /* RFC 6608 */
    {5,  2, "Unexpected Message in OpenConfirm State"},
    {5,  3, "Unexpected Message in Established State"},
    {6,  0, "Cease"},
    {6,  1, "Maximum Number of Prefixes Reached"},    /* RFC 4486 */
    {6,  2, "Administrative Shutdown"},
    {6,  3, "Peer De-configured"},
    {6,  4, "Administrative Reset"},
    {6,  5, "Connection Rejected"},
    {6,  6, "Other Configuration Change"},
    {6,  7, "Connection Collision Resolution"},
    {6,  8, "Out of Resources"},
    {6,  9, "Hard Reset"},                            /* RFC 8538 */
    {6, 10, "BFD Down"},                              /* RFC 9384 */
    {7,  0, "ROUTE-REFRESH Message Error"},           /* RFC 7313 */
    {7,  1, "Invalid Message Length"},
    {8,  0, "Send Hold Timer Expired"},               /* RFC 9687 */
};

static const char *bgp_notification_name(uint8_t code, uint8_t subcode) {
    for (size_t i = 0; i < sizeof(bgp_notification_names) / sizeof(bgp_notification_names[0]); i++) {
        if (bgp_notification_names[i].code == code && bgp_notification_names[i].subcode == subcode) {
            return bgp_notification_names[i].name;
        }
    }
    return NULL;
}

const char *bgp_notification_code_name(uint8_t code) {
    const char *name = bgp_notification_name(code, 0);

    return name ? name : "Unknown Error Code";
}

/*
 * Subcode 0 is "Unspecific" for every code (RFC 4271 section 4.5).
 */
const char *bgp_notification_subcode_name(uint8_t code, uint8_t subcode) {
    const char *name = subcode ? bgp_notification_name(code, subcode) : "Unspecific";

    return name ? name : "Unknown Subcode";
}

/*
 * Keep a NOTIFICATION's body: error code, subcode and data. The data of a Cease with subcode Administrative Shutdown or
 * Administrative Reset may be a Shutdown Communication (RFC 9003): a length octet and that many octets of UTF-8. It is
 * kept with control characters replaced by '?'; a length past the data makes it malformed, and it is then ignored.
 */
void bgp_notification_record(bgp_notification_record_t *record, const uint8_t *body, size_t body_len) {
    const uint8_t *data = body + 2;
    size_t         data_len = body_len > 2 ? body_len - 2 : 0;

    memset(record, 0, sizeof(*record));
    record->time = time(NULL);
    record->code = body_len > 0 ? body[0] : 0;
    record->subcode = body_len > 1 ? body[1] : 0;
    record->data_len = data_len > UINT16_MAX ? UINT16_MAX : (uint16_t)data_len;
    if (record->code == 6 && (record->subcode == 2 || record->subcode == 4) && data_len > 0 &&
        (size_t)data[0] <= data_len - 1) {
        for (size_t i = 0; i < data[0]; i++) {
            uint8_t octet = data[1 + i];

            record->shutdown[i] = (octet < 0x20 || octet == 0x7f) ? '?' : (char)octet;
        }
    }
}

/*
 * "6/2 (Cease/Administrative Shutdown), shutdown communication "text"", or ", data length N" for other data.
 */
void bgp_notification_describe(const bgp_notification_record_t *record, char *buffer, size_t size) {
    int len = snprintf(buffer, size, "%u/%u (%s/%s)", record->code, record->subcode,
                       bgp_notification_code_name(record->code),
                       bgp_notification_subcode_name(record->code, record->subcode));

    if (len < 0 || (size_t)len >= size) {
        return;
    }
    if (record->shutdown[0] != '\0') {
        snprintf(buffer + len, size - (size_t)len, ", shutdown communication \"%s\"", record->shutdown);
    } else if (record->data_len > 0) {
        snprintf(buffer + len, size - (size_t)len, ", data length %u", record->data_len);
    }
}
