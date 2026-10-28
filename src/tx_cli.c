#define OUTPUT_STDIO_REMAP

#include <stdlib.h>
#include <inttypes.h>
#include "util.h"
#include "output.h"
#include "tx_exec.h"
#include "commands.h"

static int tx_keyword(const match_result_t *result, const char *keyword) {
    for (int i = 0; i < result->token_count; i++) {
        if (result->tokens[i].type == TOKEN_KEYWORD && strcmp(result->tokens[i].value, keyword) == 0) return 1;
    }
    return 0;
}

/*
 * "<ip|all> [router <AS>]": peer canonicalized; router 0 when omitted. A dangling "router" is invalid.
 */
static int tx_parse_peer(match_result_t *result, char *peer, size_t peer_len, uint32_t *router) {
    char raw[MAX_TOKEN_LEN];
    int  has_router;

    *router = 0;
    has_router = match_get_uint32(result, "router", router);
    if (!match_get_string(result, "peer", raw, sizeof(raw)) || (tx_keyword(result, "router") && !has_router) ||
        (has_router && *router == 0)) {
        fprintf(stderr, "Error: expected peer <ip|all> [router <AS>]\n");
        return -1;
    }
    if (strcmp(raw, "all") == 0) {
        snprintf(peer, peer_len, "all");
        return 0;
    }
    if (canonical_ip_address(raw, peer, peer_len) < 0) {
        fprintf(stderr, "Error: invalid peer address %s\n", raw);
        return -1;
    }
    return 0;
}

/*
 * One line per peer. The command fails when a peer rejected the operation or a named peer was not sent to; a
 * withheld advertisement is reported but is not an error.
 */
static int tx_report(const char *what, const tx_request_t *request, const tx_peer_result_t *results, size_t count) {
    int failed = 0;
    int named = strcmp(request->peer, "all") != 0;

    if (count == 0) {
        printf("%s: no neighbors\n", what);
    }
    for (size_t i = 0; i < count; i++) {
        const tx_peer_result_t *r = &results[i];

        switch (r->status) {
            case TX_PEER_QUEUED:
                printf("%s: queued to %s (router %u): %zu UPDATEs, %" PRIu64 " bytes\n", what, r->peer, r->router_as,
                       r->msgs, r->bytes);
                break;
            case TX_PEER_WITHHELD:
                printf("%s: withheld from %s: %s\n", what, r->peer, r->reason);
                break;
            case TX_PEER_SKIPPED:
                if (named) {
                    fprintf(stderr, "Error: %s: %s: %s\n", what, r->peer, r->reason);
                    failed = 1;
                } else {
                    printf("%s: skipped %s: %s\n", what, r->peer, r->reason);
                }
                break;
            case TX_PEER_REJECTED:
                fprintf(stderr, "Error: %s: rejected by %s: %s\n", what, r->peer, r->reason);
                failed = 1;
                break;
        }
    }
    return failed ? -1 : 0;
}

static int tx_run(cmd_ctx_t *command, const tx_request_t *request, const char *what) {
    size_t            capacity = tx_result_capacity(command->sim);
    tx_peer_result_t *results = calloc(capacity, sizeof(*results));
    char              error[160];
    size_t            count = 0;
    int               rc;

    if (!results) {
        fprintf(stderr, "Error: no memory\n");
        return -1;
    }
    if (tx_admit(command->sim, request, results, capacity, &count, error, sizeof(error)) < 0) {
        fprintf(stderr, "Error: %s: %s\n", what, error);
        free(results);
        return -1;
    }
    rc = tx_report(what, request, results, count);
    free(results);
    return rc;
}

/*
 * advertise|withdraw|replay ribout <name> peer <ip|all> [router <AS>]
 */
int cmd_handle_tx_ribout(void *ctx, match_result_t *result) {
    tx_request_t request = {0};
    char ribout[MAX_TOKEN_LEN], peer[INET6_ADDRSTRLEN], what[MAX_TOKEN_LEN + 32];
    const char *verb = tx_keyword(result, "advertise") ? "advertise" :
                       tx_keyword(result, "withdraw") ? "withdraw" : "replay";

    if (!match_get_string(result, "ribout", ribout, sizeof(ribout)) || !bgp_ribout_name_valid(ribout)) {
        fprintf(stderr, "Error: invalid ribout name\n");
        return -1;
    }
    if (tx_parse_peer(result, peer, sizeof(peer), &request.router_as) < 0) {
        return -1;
    }
    request.op = strcmp(verb, "advertise") == 0 ? BGP_TX_OP_ADVERTISE :
                 strcmp(verb, "withdraw") == 0 ? BGP_TX_OP_WITHDRAW : BGP_TX_OP_REPLAY;
    request.ribout = ribout;
    request.peer = peer;
    snprintf(what, sizeof(what), "%s ribout %s", verb, ribout);
    return tx_run(ctx, &request, what);
}

/*
 * withdraw all peer <ip|all> [router <AS>]
 */
int cmd_handle_tx_withdraw_all(void *ctx, match_result_t *result) {
    tx_request_t request = {.op = BGP_TX_OP_WITHDRAW_ALL};
    char         peer[INET6_ADDRSTRLEN];

    if (tx_parse_peer(result, peer, sizeof(peer), &request.router_as) < 0) {
        return -1;
    }
    request.peer = peer;
    return tx_run(ctx, &request, "withdraw all");
}
