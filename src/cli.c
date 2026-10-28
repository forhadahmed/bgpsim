#define OUTPUT_STDIO_REMAP

#include <time.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include "bgp.h"
#include "log.h"
#include "util.h"
#include "output.h"
#include "commands.h"
#include "bgp_peer_tx.h"
#include "bgp_ribout_snapshot.h"

/*
 * The generator owns the path-count formula; the CLI only displays it.
 */
static uint64_t cli_ribout_total_paths(const bgp_ribout_config_t *block) {
    return bgp_ribout_total_paths(block);
}

/*
 * Distinct NLRIs of a block: total paths without the path-ID multiplier (none with path-id rotate).
 */
static uint64_t cli_ribout_base_nlri_count(const bgp_ribout_config_t *block) {
    return bgp_ribout_total_paths(block) / bgp_ribout_effective_count(block->path_id_rotate ? 0 : block->path_id_count);
}

static int cli_ribout_u32_values_are_sequential(const uint32_t *values, uint32_t count, uint32_t step) {
    if (!values || count == 0) {
        return 0;
    }

    if (step) return step == 1;
    for (uint32_t i = 1; i < count; i++) {
        if (values[i] != (values[i - 1] + 1)) {
            return 0;
        }
    }

    return 1;
}

/*
 * Print the color values in config syntax: "<base> x <count> [co <bits>]" for a sequence with one CO type, else each
 * value with "co <bits>" when its CO type is not 00.
 */
static void cli_print_ribout_colors(const bgp_ribout_config_t *block) {
    int same_co = 1;

    for (uint32_t i = 1; i < (block->colors_step ? 1 : block->color_count); i++) {
        same_co &= (bgp_ribout_color_co_at(block, i) == bgp_ribout_color_co_at(block, 0));
    }
    if (block->color_count > 1 && same_co &&
        cli_ribout_u32_values_are_sequential(block->colors, block->color_count, block->colors_step)) {
        printf("%u x %u", bgp_ribout_colors_at(block, 0), block->color_count);
        if (bgp_ribout_color_co_at(block, 0) != BGP_COLOR_CO_SPECIFIC) {
            printf(" co %s", bgp_ribout_co_bits_text(bgp_ribout_color_co_at(block, 0)));
        }
        return;
    }
    for (uint32_t i = 0; i < block->color_count; i++) {
        printf("%s%u", i == 0 ? "" : " ", bgp_ribout_colors_at(block, i));
        if (bgp_ribout_color_co_at(block, i) != BGP_COLOR_CO_SPECIFIC) {
            printf(" co %s", bgp_ribout_co_bits_text(bgp_ribout_color_co_at(block, i)));
        }
    }
}

static void cli_print_ribout_u32_values(const char *keyword, const uint32_t *values, uint32_t count, uint32_t step) {
    if (!keyword || !values || count == 0) {
        return;
    }

    if (count > 1 && cli_ribout_u32_values_are_sequential(values, count, step)) {
        printf("  %s %u x %u\n", keyword, values[0], count);
        return;
    }

    printf("  %s", keyword);
    for (uint32_t i = 0; i < count; i++) {
        printf(" %u", values[i]);
    }
    printf("\n");
}

static void cli_rd_to_string(const route_distinguisher_t *rd, char *buffer, size_t buffer_len) {
    uint16_t type;

    if (!rd || !buffer || buffer_len == 0) {
        return;
    }

    type = rd->type;
    if (type == 0) {
        uint16_t admin;
        uint32_t assigned;

        memcpy(&admin, rd->value, sizeof(admin));
        memcpy(&assigned, rd->value + 2, sizeof(assigned));
        snprintf(buffer, buffer_len, "%u:%u", (unsigned)ntohs(admin), (unsigned)ntohl(assigned));
        return;
    }

    if (type == 1) {
        struct in_addr ipv4_addr;
        uint16_t       assigned;
        char           ip_str[INET_ADDRSTRLEN];

        memcpy(&ipv4_addr, rd->value, sizeof(ipv4_addr));
        memcpy(&assigned, rd->value + 4, sizeof(assigned));
        inet_ntop(AF_INET, &ipv4_addr, ip_str, sizeof(ip_str));
        snprintf(buffer, buffer_len, "%s:%u", ip_str, (unsigned)ntohs(assigned));
        return;
    }

    if (type == 2) {
        uint32_t admin;
        uint16_t assigned;

        memcpy(&admin, rd->value, sizeof(admin));
        memcpy(&assigned, rd->value + 4, sizeof(assigned));
        snprintf(buffer, buffer_len, "%u:%u", (unsigned)ntohl(admin), (unsigned)ntohs(assigned));
        return;
    }

    snprintf(buffer, buffer_len, "type%u", (unsigned)type);
}

/*
 * Color Extended Community (type 0x03, sub-type 0x0b).
 */
static int cli_ext_comm_is_color(const bgp_ext_comm_t *ext_comm) {
    return ext_comm != NULL &&
           ext_comm->bytes[0] == 0x03 &&
           ext_comm->bytes[1] == 0x0b;
}

/*
 * Text of one extended community for show and preview: RT and SoO as admin:assigned, Color as "<c>[ co <bits>]", the
 * encapsulation type by name, Router's MAC as a MAC address, and any other community as 8 hex octets.
 */
static void cli_ext_comm_to_string(const bgp_ext_comm_t *ext_comm, char *buffer, size_t buffer_len) {
    uint16_t tunnel_type;

    if (!ext_comm || !buffer || buffer_len == 0) {
        return;
    }

    if ((ext_comm->bytes[0] == 0x00 ||
         ext_comm->bytes[0] == 0x01 ||
         ext_comm->bytes[0] == 0x02) &&
        (ext_comm->bytes[1] == 0x02 || ext_comm->bytes[1] == 0x03)) {
        if (ext_comm->bytes[0] == 0x00) {
            uint16_t admin;
            uint32_t assigned;

            memcpy(&admin, ext_comm->bytes + 2, sizeof(admin));
            memcpy(&assigned, ext_comm->bytes + 4, sizeof(assigned));
            snprintf(buffer, buffer_len, "%u:%u", (unsigned)ntohs(admin), (unsigned)ntohl(assigned));
            return;
        }

        if (ext_comm->bytes[0] == 0x01) {
            struct in_addr ipv4_addr;
            uint16_t       assigned;
            char           ip_str[INET_ADDRSTRLEN];

            memcpy(&ipv4_addr, ext_comm->bytes + 2, sizeof(ipv4_addr));
            memcpy(&assigned, ext_comm->bytes + 6, sizeof(assigned));
            inet_ntop(AF_INET, &ipv4_addr, ip_str, sizeof(ip_str));
            snprintf(buffer, buffer_len, "%s:%u", ip_str, (unsigned)ntohs(assigned));
            return;
        }

        if (ext_comm->bytes[0] == 0x02) {
            uint32_t admin;
            uint16_t assigned;

            memcpy(&admin, ext_comm->bytes + 2, sizeof(admin));
            memcpy(&assigned, ext_comm->bytes + 6, sizeof(assigned));
            snprintf(buffer, buffer_len, "%u:%u", (unsigned)ntohl(admin), (unsigned)ntohs(assigned));
            return;
        }
    }

    if (cli_ext_comm_is_color(ext_comm)) {
        uint32_t color;
        uint8_t  co_type = (uint8_t)(ext_comm->bytes[2] >> 6);

        memcpy(&color, ext_comm->bytes + 4, sizeof(color));
        snprintf(buffer, buffer_len, "%u%s%s", (unsigned)ntohl(color),
                 co_type != BGP_COLOR_CO_SPECIFIC ? " co " : "",
                 co_type != BGP_COLOR_CO_SPECIFIC ? bgp_ribout_co_bits_text(co_type) : "");
        return;
    }

    if (ext_comm->bytes[0] == 0x03 && ext_comm->bytes[1] == 0x0c) {
        memcpy(&tunnel_type, ext_comm->bytes + 6, sizeof(tunnel_type));
        tunnel_type = ntohs(tunnel_type);
        switch (tunnel_type) {
            case 1:
                snprintf(buffer, buffer_len, "l2tpv3");
                return;
            case 2:
                snprintf(buffer, buffer_len, "gre");
                return;
            case 8:
                snprintf(buffer, buffer_len, "vxlan");
                return;
            case 9:
                snprintf(buffer, buffer_len, "nvgre");
                return;
            case 11:
                snprintf(buffer, buffer_len, "mpls-in-gre");
                return;
            default:
                snprintf(buffer, buffer_len, "%u", (unsigned)tunnel_type);
                return;
        }
    }

    if (ext_comm->bytes[0] == 0x06 && ext_comm->bytes[1] == 0x03) {
        snprintf(buffer, buffer_len,
                 "%02x:%02x:%02x:%02x:%02x:%02x",
                 ext_comm->bytes[2], ext_comm->bytes[3], ext_comm->bytes[4],
                 ext_comm->bytes[5], ext_comm->bytes[6], ext_comm->bytes[7]);
        return;
    }

    snprintf(buffer, buffer_len,
             "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
             ext_comm->bytes[0], ext_comm->bytes[1], ext_comm->bytes[2],
             ext_comm->bytes[3], ext_comm->bytes[4], ext_comm->bytes[5],
             ext_comm->bytes[6], ext_comm->bytes[7]);
}

static int cli_ext_comm_is_rt(const bgp_ext_comm_t *ext_comm) {
    return ext_comm != NULL &&
           (ext_comm->bytes[0] == 0x00 || ext_comm->bytes[0] == 0x01 || ext_comm->bytes[0] == 0x02) &&
           ext_comm->bytes[1] == 0x02;
}

static int cli_ext_comm_is_soo(const bgp_ext_comm_t *ext_comm) {
    return ext_comm != NULL &&
           (ext_comm->bytes[0] == 0x00 || ext_comm->bytes[0] == 0x01 || ext_comm->bytes[0] == 0x02) &&
           ext_comm->bytes[1] == 0x03;
}

static int cli_ext_comm_is_encap(const bgp_ext_comm_t *ext_comm) {
    return ext_comm != NULL &&
           ext_comm->bytes[0] == 0x03 &&
           ext_comm->bytes[1] == 0x0c;
}

static int cli_ext_comm_is_router_mac(const bgp_ext_comm_t *ext_comm) {
    return ext_comm != NULL &&
           ext_comm->bytes[0] == 0x06 &&
           ext_comm->bytes[1] == 0x03;
}

static void cli_esi_to_string(const evpn_esi_t *esi, char *buffer, size_t buffer_len) {
    if (!esi || !buffer || buffer_len == 0) {
        return;
    }

    snprintf(buffer, buffer_len,
             "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
             esi->type,
             esi->value[0], esi->value[1], esi->value[2],
             esi->value[3], esi->value[4], esi->value[5],
             esi->value[6], esi->value[7], esi->value[8]);
}

static void cli_mac_to_string(const uint8_t mac[6], char *buffer, size_t buffer_len) {
    if (!mac || !buffer || buffer_len == 0) {
        return;
    }

    snprintf(buffer, buffer_len, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void cli_append_formatted_value(char *buffer, size_t buffer_len, const char *value, const char *separator) {
    size_t      used;
    size_t      remaining;
    const char *prefix;
    size_t      prefix_len;
    size_t      value_len;

    if (!buffer || !value || buffer_len == 0) {
        return;
    }

    used = strlen(buffer);
    if (used >= buffer_len - 1) {
        return;
    }

    remaining = buffer_len - used - 1;
    prefix = (used > 0 && separator) ? separator : "";
    prefix_len = strlen(prefix);
    if (prefix_len > remaining) {
        prefix_len = remaining;
    }
    memcpy(buffer + used, prefix, prefix_len);
    used += prefix_len;
    remaining -= prefix_len;

    value_len = strlen(value);
    if (value_len > remaining) {
        value_len = remaining;
    }
    memcpy(buffer + used, value, value_len);
    used += value_len;
    buffer[used] = '\0';
}

/*
 * Sort the extended communities of a generated path into the preview columns: RT, SoO, encap, router-MAC and Color,
 * each a comma-separated list.
 */
static void cli_format_path_ext_comms(const bgp_gen_path_t *path,
                                      char *rt_buffer,
                                      size_t rt_buffer_len,
                                      char *soo_buffer,
                                      size_t soo_buffer_len,
                                      char *encap_buffer,
                                      size_t encap_buffer_len,
                                      char *router_mac_buffer,
                                      size_t router_mac_buffer_len,
                                      char *color_buffer,
                                      size_t color_buffer_len) {
    uint16_t offset = 0;

    if (!rt_buffer || !soo_buffer || !encap_buffer || !router_mac_buffer || !color_buffer ||
        !path) {
        return;
    }

    rt_buffer[0] = '\0';
    soo_buffer[0] = '\0';
    encap_buffer[0] = '\0';
    router_mac_buffer[0] = '\0';
    color_buffer[0] = '\0';

    while ((offset + 8) <= path->ext_comm_len) {
        bgp_ext_comm_t ext_comm;
        char           value[64];

        memcpy(ext_comm.bytes, path->ext_comm_data + offset, 8);
        cli_ext_comm_to_string(&ext_comm, value, sizeof(value));

        if (cli_ext_comm_is_rt(&ext_comm)) {
            cli_append_formatted_value(rt_buffer, rt_buffer_len, value, ",");
        } else if (cli_ext_comm_is_soo(&ext_comm)) {
            cli_append_formatted_value(soo_buffer, soo_buffer_len, value, ",");
        } else if (cli_ext_comm_is_encap(&ext_comm)) {
            cli_append_formatted_value(encap_buffer, encap_buffer_len, value, ",");
        } else if (cli_ext_comm_is_router_mac(&ext_comm)) {
            cli_append_formatted_value(router_mac_buffer, router_mac_buffer_len, value, ",");
        } else if (cli_ext_comm_is_color(&ext_comm)) {
            cli_append_formatted_value(color_buffer, color_buffer_len, value, ",");
        }

        offset += 8;
    }
}

static int cli_ribout_labels_are_sequential(const bgp_ribout_config_t *block) {
    return cli_ribout_u32_values_are_sequential(block->labels, block->label_count, block->labels_step);
}

static void cli_print_ribout_labels(const bgp_ribout_config_t *block) {
    if (block->label_count == 0) {
        return;
    }

    if (block->label_count > 1 && cli_ribout_labels_are_sequential(block)) {
        printf("  label%s %u x %u\n", block->label_rotate ? " rotate" : "", bgp_ribout_labels_at(block, 0), block->label_count);
        return;
    }

    printf("  label%s", block->label_rotate ? " rotate" : "");
    for (uint32_t i = 0; i < block->label_count; i++) {
        printf(" %u", bgp_ribout_labels_at(block, i));
    }
    printf("\n");
}

static void cli_print_ribout_label2s(const bgp_ribout_config_t *block) {
    if (!block || block->label2_count == 0) {
        return;
    }

    cli_print_ribout_u32_values("label2", block->label2s, block->label2_count, block->label2s_step);
}

static int cli_ribout_ethernet_tags_are_sequential(const bgp_ribout_config_t *block) {
    return cli_ribout_u32_values_are_sequential(block->ethernet_tags, block->ethernet_tag_count, block->ethernet_tags_step);
}

/*
 * True when the RDs run base, base + 1, ...: the same type and administrator, assigned numbers counting up.
 */
static int cli_rds_sequential(const bgp_ribout_config_t *block) {
    if (block->rds_step) return 1;
    for (uint32_t i = 1; i < block->rd_count; i++) {
        const route_distinguisher_t *first = &block->rds[0], *rd = &block->rds[i];
        int                          admin_len = (first->type == 0) ? 2 : 4;
        uint32_t                     base = 0, value = 0;

        if (rd->type != first->type || memcmp(rd->value, first->value, (size_t)admin_len) != 0) {
            return 0;
        }
        for (int b = admin_len; b < 6; b++) {
            base = (base << 8) | first->value[b];
            value = (value << 8) | rd->value[b];
        }
        if (value != base + i) {
            return 0;
        }
    }
    return 1;
}

static void cli_print_ribout_rds(const bgp_ribout_config_t *block) {
    if (block->rd_count == 0) {
        return;
    }

    printf("  rd%s", block->rd_rotate ? " rotate" : "");
    if (block->rd_count > 1 && cli_rds_sequential(block)) {
        char rd_str[64];

        route_distinguisher_t rd = bgp_ribout_rds_at(block, 0);
        cli_rd_to_string(&rd, rd_str, sizeof(rd_str));
        printf(" %s x %u\n", rd_str, block->rd_count);
        return;
    }
    for (uint32_t i = 0; i < block->rd_count; i++) {
        char rd_str[64];

        route_distinguisher_t rd = bgp_ribout_rds_at(block, i);
        cli_rd_to_string(&rd, rd_str, sizeof(rd_str));
        printf(" %s", rd_str);
    }
    printf("\n");
}

static void cli_print_ribout_ethernet_tags(const bgp_ribout_config_t *block) {
    if (block->ethernet_tag_count == 0) {
        return;
    }

    if (block->ethernet_tag_count > 1 &&
        cli_ribout_ethernet_tags_are_sequential(block)) {
        printf("  ethernet-tag%s %u x %u\n", block->ethernet_tag_rotate ? " rotate" : "", bgp_ribout_ethernet_tags_at(block, 0),
               block->ethernet_tag_count);
        return;
    }

    printf("  ethernet-tag%s", block->ethernet_tag_rotate ? " rotate" : "");
    for (uint32_t i = 0; i < block->ethernet_tag_count; i++) {
        printf(" %u", bgp_ribout_ethernet_tags_at(block, i));
    }
    printf("\n");
}

static void cli_print_ribout_next_hop_spec(const char *keyword, const bgp_next_hop_spec_t *spec) {
    char next_hop_str[INET6_ADDRSTRLEN];
    char link_local_str[INET6_ADDRSTRLEN];

    if (!keyword || !spec || spec->count == 0) {
        return;
    }

    if (spec->af == AF_INET) {
        inet_ntop(AF_INET, &spec->base_addr.ipv4, next_hop_str, sizeof(next_hop_str));
    } else {
        inet_ntop(AF_INET6, &spec->base_addr.ipv6, next_hop_str, sizeof(next_hop_str));
        if (spec->has_link_local) {
            inet_ntop(AF_INET6, &spec->link_local, link_local_str, sizeof(link_local_str));
        }
    }

    if (spec->count > 1) {
        printf("  %s %s x %u", keyword, next_hop_str, spec->count);
    } else {
        printf("  %s %s", keyword, next_hop_str);
    }

    if (spec->af == AF_INET6 && spec->has_link_local) {
        printf(" link-local %s", link_local_str);
    }
    printf("\n");
}

static int cli_print_ribout_scalar_spec(const char *keyword, const bgp_u32_spec_t *spec) {
    if (!keyword || !spec) {
        return 0;
    }

    switch (spec->mode) {
        case BGP_U32_MODE_FIXED:
            printf("  %s %u\n", keyword, spec->value);
            return 1;
        case BGP_U32_MODE_RANDOM:
            printf("  %s rand(%u)\n", keyword, spec->value);
            return 1;
        case BGP_U32_MODE_RANGE:
            printf("  %s range(%u,%u)\n", keyword, spec->range_start, spec->range_end);
            return 1;
        case BGP_U32_MODE_RANDOM_RANGE:
            printf("  %s randrange(%u,%u)\n", keyword, spec->range_start, spec->range_end);
            return 1;
        default:
            return 0;
    }
}

static int cli_print_ribout_optional_scalar_spec(const char *keyword, const bgp_u32_optional_spec_t *spec) {
    bgp_u32_spec_t base;

    if (!spec || !spec->enabled) {
        return 0;
    }

    base.mode = spec->mode;
    base.value = spec->value;
    base.range_start = spec->range_start;
    base.range_end = spec->range_end;
    return cli_print_ribout_scalar_spec(keyword, &base);
}

static void cli_print_ribout_enlps(const bgp_ribout_config_t *block) {
    if (!block) {
        return;
    }

    if (block->enlp_spec.enabled) {
        cli_print_ribout_optional_scalar_spec("enlp", &block->enlp_spec);
        return;
    }

    cli_print_ribout_u32_values("enlp", block->enlps, block->enlp_count, block->enlps_step);
}

static void cli_print_ribout_priorities(const bgp_ribout_config_t *block) {
    if (!block) {
        return;
    }

    if (block->priority_spec.enabled) {
        cli_print_ribout_optional_scalar_spec("priority", &block->priority_spec);
        return;
    }

    cli_print_ribout_u32_values("priority", block->priorities, block->priority_count, block->priorities_step);
}

static void cli_print_ribout_binding_sids(const bgp_ribout_config_t *block) {
    if (!block) {
        return;
    }

    if (block->binding_sid_kind == BGP_RIBOUT_SR_BINDING_SID_SRV6 &&
        block->binding_sid_srv6_spec.count > 0) {
        char sid_str[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET6, &block->binding_sid_srv6_spec.base_addr.ipv6, sid_str, sizeof(sid_str));
        if (block->binding_sid_srv6_spec.count > 1) {
            printf("  binding-sid srv6 %s x %u\n", sid_str, block->binding_sid_srv6_spec.count);
        } else {
            printf("  binding-sid srv6 %s\n", sid_str);
        }
        return;
    }

    if (block->binding_sid_spec.enabled) {
        if (block->binding_sid_spec.mode == BGP_U32_MODE_FIXED) {
            printf("  binding-sid mpls %u\n", block->binding_sid_spec.value);
        } else if (block->binding_sid_spec.mode == BGP_U32_MODE_RANDOM) {
            printf("  binding-sid mpls rand(%u)\n", block->binding_sid_spec.value);
        } else if (block->binding_sid_spec.mode == BGP_U32_MODE_RANGE) {
            printf("  binding-sid mpls range(%u,%u)\n",
                   block->binding_sid_spec.range_start,
                   block->binding_sid_spec.range_end);
        } else {
            printf("  binding-sid mpls randrange(%u,%u)\n",
                   block->binding_sid_spec.range_start,
                   block->binding_sid_spec.range_end);
        }
        return;
    }

    if (block->binding_sid_count == 0) {
        return;
    }

    if (block->binding_sid_count > 1 &&
        cli_ribout_u32_values_are_sequential(block->binding_sids, block->binding_sid_count, block->binding_sids_step)) {
        printf("  binding-sid mpls %u x %u\n", bgp_ribout_binding_sids_at(block, 0), block->binding_sid_count);
        return;
    }

    printf("  binding-sid mpls");
    for (uint32_t i = 0; i < block->binding_sid_count; i++) {
        printf(" %u", bgp_ribout_binding_sids_at(block, i));
    }
    printf("\n");
}

static void cli_print_ribout_preferences(const bgp_ribout_config_t *block) {
    if (!block) {
        return;
    }

    if (block->preference_spec.enabled) {
        cli_print_ribout_optional_scalar_spec("preference", &block->preference_spec);
        return;
    }

    cli_print_ribout_u32_values("preference", block->preferences, block->preference_count, block->preferences_step);
}

/*
 * FlowSpec match lines after the prefix: src-prefix and the operator components in type order.
 */
static void cli_print_ribout_flowspec_match(const bgp_ribout_config_t *block) {
    char text[MAX_FLOWSPEC_LINE_TEXT];

    for (uint8_t type = FLOWSPEC_SRC_PREFIX; type <= FLOWSPEC_FLOW_LABEL; type++) {
        if (bgp_ribout_flowspec_component_to_string(block, type, text, sizeof(text))) {
            printf("  %s\n", text);
        }
    }
}

static void cli_print_ribout_segment_lists(const bgp_ribout_config_t *block) {
    if (!block) {
        return;
    }

    for (uint32_t i = 0; i < block->segment_list_count; i++) {
        const bgp_ribout_sr_segment_list_t *list = &block->segment_lists[i];

        printf("  segment-list %u weight %u", list->id, list->weight);

        if (list->segment_count > 0 &&
            list->segments[0].type == SR_SEGMENT_TYPE_MPLS) {
            printf(" mpls");
            for (uint32_t j = 0; j < list->segment_count; j++) {
                uint32_t label_net;
                uint32_t label;

                memcpy(&label_net, list->segments[j].sid, sizeof(label_net));
                label = ntohl(label_net);
                printf(" %u", label);
            }
        } else {
            printf(" srv6");
            for (uint32_t j = 0; j < list->segment_count; j++) {
                char sid_str[INET6_ADDRSTRLEN];

                inet_ntop(AF_INET6, list->segments[j].sid, sid_str, sizeof(sid_str));
                printf(" %s", sid_str);
                if (list->segments[j].has_srv6_behavior) {
                    printf(" behavior %u", list->segments[j].srv6_behavior.endpoint_behavior);
                    if (list->segments[j].srv6_behavior.locator_block_len > 0 ||
                        list->segments[j].srv6_behavior.locator_node_len > 0 ||
                        list->segments[j].srv6_behavior.function_len > 0 ||
                        list->segments[j].srv6_behavior.argument_len > 0) {
                        printf(" structure %u %u %u %u",
                               list->segments[j].srv6_behavior.locator_block_len,
                               list->segments[j].srv6_behavior.locator_node_len,
                               list->segments[j].srv6_behavior.function_len,
                               list->segments[j].srv6_behavior.argument_len);
                    }
                }
            }
        }

        printf("\n");
    }
}

static void cli_print_ribout_mac_spec(const bgp_ribout_config_t *block) {
    char mac_str[32];

    if (!block || block->mac_spec.count == 0) {
        return;
    }

    cli_mac_to_string(block->mac_spec.base_addr, mac_str, sizeof(mac_str));
    if (block->mac_spec.count > 1) {
        printf("  mac %s x %u\n", mac_str, block->mac_spec.count);
    } else {
        printf("  mac %s\n", mac_str);
    }
}

static void cli_print_ribout_esis(const bgp_ribout_config_t *block) {
    if (block->esi_count == 0) {
        return;
    }

    printf("  esi");
    for (uint32_t i = 0; i < block->esi_count; i++) {
        char esi_str[64];

        cli_esi_to_string(&block->esis[i], esi_str, sizeof(esi_str));
        printf(" %s", esi_str);
    }
    printf("\n");
}

/*
 * rt, soo, encap and router-mac lines append, so a long list goes on in further lines, each within the command limits
 * (MAX_TOKENS tokens, BGPSIM_COMMAND_SIZE bytes) and so loadable again.
 */
static void cli_print_ribout_ext_comms(const char *keyword, const bgp_ext_comm_t *values, uint32_t count) {
    char   line[BGPSIM_COMMAND_SIZE];
    size_t len = 0;
    int    tokens = 0;

    if (!keyword || !values || count == 0) {
        return;
    }

    for (uint32_t i = 0; i < count; i++) {
        char value_str[64];

        cli_ext_comm_to_string(&values[i], value_str, sizeof(value_str));
        if (tokens > 0 && (tokens + 1 > MAX_TOKENS || len + 1 + strlen(value_str) >= BGPSIM_COMMAND_SIZE - 1)) {
            printf("%s\n", line);
            tokens = 0;
        }
        if (tokens == 0) {
            len = (size_t)snprintf(line, sizeof(line), "  %s", keyword);
            tokens = 1;
        }
        len += (size_t)snprintf(line + len, sizeof(line) - len, " %s", value_str);
        tokens++;
    }
    printf("%s\n", line);
}

/*
 * True when set i is set 0 with every route target's local administrator larger by i: "rt-set <set> x <count>".
 */
static int cli_rt_sets_sequential(const bgp_ribout_config_t *block) {
    for (uint32_t i = 1; i < block->rt_set_group_count; i++) {
        if (block->rt_sets[i].count != block->rt_sets[0].count) {
            return 0;
        }
        for (uint32_t j = 0; j < block->rt_sets[0].count; j++) {
            bgp_ext_comm_t step = block->rt_sets[0].values[j];

            if (bgp_ext_comm_local_admin_add(&step, block->rt_sets[i].first) < 0 ||
                memcmp(step.bytes, block->rt_sets[i].values[j].bytes, sizeof(step.bytes)) != 0) {
                return 0;
            }
        }
    }
    return 1;
}

/*
 * rt-set lines append, so a long list prints as one sequence ("rt-set <set> x <count>") or as several lines, each
 * within the command limits (MAX_TOKENS tokens, BGPSIM_COMMAND_SIZE bytes) and so loadable again.
 */
static void cli_print_ribout_rt_sets(const bgp_ribout_config_t *block) {
    char   line[BGPSIM_COMMAND_SIZE];
    size_t len = 0;
    int    tokens = 0;

    if (block->rt_set_count > 1 && cli_rt_sets_sequential(block)) {
        printf("  rt-set [");
        for (uint32_t j = 0; j < block->rt_sets[0].count; j++) {
            char value_str[64];

            cli_ext_comm_to_string(&block->rt_sets[0].values[j], value_str, sizeof(value_str));
            printf("%s%s", (j > 0) ? "," : "", value_str);
        }
        printf("] x %u\n", block->rt_set_count);
        return;
    }

    for (uint32_t i = 0; i < block->rt_set_group_count; i++) {
        char   set[BGPSIM_COMMAND_SIZE];
        size_t set_len = (size_t)snprintf(set, sizeof(set), " [");

        for (uint32_t j = 0; j < block->rt_sets[i].count; j++) {
            char value_str[64];

            cli_ext_comm_to_string(&block->rt_sets[i].values[j], value_str, sizeof(value_str));
            set_len += (size_t)snprintf(set + set_len, sizeof(set) - set_len, "%s%s", (j > 0) ? "," : "", value_str);
        }
        set_len += (size_t)snprintf(set + set_len, sizeof(set) - set_len, "]");
        int set_tokens = block->rt_sets[i].repeat > 1 ? 3 : 1;
        if (set_tokens == 3) {
            set_len += (size_t)snprintf(set + set_len, sizeof(set) - set_len, " x %u", block->rt_sets[i].repeat);
        }
        if (tokens > 0 && (tokens + set_tokens > MAX_TOKENS || len + set_len >= BGPSIM_COMMAND_SIZE - 1)) {
            printf("%s\n", line);
            tokens = 0;
        }
        if (tokens == 0) {
            len = (size_t)snprintf(line, sizeof(line), "  rt-set");
            tokens = 1;
        }
        len += (size_t)snprintf(line + len, sizeof(line) - len, "%s", set);
        tokens += set_tokens;
    }
    if (tokens > 0) {
        printf("%s\n", line);
    }
}

/*
 * Text of one community: its well-known name, else aa:nn.
 */
static void cli_community_to_string(uint32_t value, char *out, size_t len) {
    const char *name = bgp_community_well_known_name(value);

    if (name) {
        snprintf(out, len, "%s", name);
    } else {
        snprintf(out, len, "%u:%u", value >> 16, value & 0xFFFF);
    }
}

/*
 * One community (large: large-community) group as written: "[v,v,...]" or one value, then " x <count>" for a
 * sequence. Returns its token count on a command line.
 */
static int cli_community_group_text(const bgp_ribout_config_t *block, int large, uint32_t index, char *out,
                                    size_t len) {
    uint32_t count = large ? block->large_community_groups[index].count : block->community_groups[index].count;
    uint32_t repeat = large ? block->large_community_groups[index].repeat : block->community_groups[index].repeat;
    size_t   used = 0;

    used += (size_t)snprintf(out + used, len - used, "%s", count > 1 ? "[" : "");
    for (uint32_t j = 0; j < count; j++) {
        char value[48];

        if (large) {
            const uint32_t *v = block->large_community_groups[index].values[j];

            snprintf(value, sizeof(value), "%u:%u:%u", v[0], v[1], v[2]);
        } else {
            cli_community_to_string(block->community_groups[index].values[j], value, sizeof(value));
        }
        used += (size_t)snprintf(out + used, len - used, "%s%s", j > 0 ? "," : "", value);
    }
    used += (size_t)snprintf(out + used, len - used, "%s", count > 1 ? "]" : "");
    if (repeat > 1) {
        snprintf(out + used, len - used, " x %u", repeat);
        return 3;
    }
    return 1;
}

/*
 * community and large-community lines append, so each group prints as written, and a long list goes on in further
 * lines, each within the command limits (MAX_TOKENS tokens, BGPSIM_COMMAND_SIZE bytes) and so loadable again.
 */
static void cli_print_ribout_community_lines(const bgp_ribout_config_t *block, int large) {
    const char *keyword = large ? "large-community" : "community";
    uint32_t    groups = large ? block->large_community_group_count : block->community_group_count;
    char        line[BGPSIM_COMMAND_SIZE];
    size_t      len = 0;
    int         tokens = 0;

    for (uint32_t i = 0; i < groups; i++) {
        char text[BGPSIM_COMMAND_SIZE];
        int  group_tokens = cli_community_group_text(block, large, i, text, sizeof(text));

        if (tokens > 0 && (tokens + group_tokens > MAX_TOKENS || len + 1 + strlen(text) >= BGPSIM_COMMAND_SIZE - 1)) {
            printf("%s\n", line);
            tokens = 0;
        }
        if (tokens == 0) {
            len = (size_t)snprintf(line, sizeof(line), "  %s", keyword);
            tokens = 1;
        }
        len += (size_t)snprintf(line + len, sizeof(line) - len, " %s", text);
        tokens += group_tokens;
    }
    if (tokens > 0) {
        printf("%s\n", line);
    }
}

/*
 * Show all BGP routers
 */
void cli_show_routers(bgp_sim_t *sim) {
    stdout_lock();

    if (sim->router_count == 0) {
        printf("\nNo BGP routers configured.\n\n");
        stdout_unlock();
        return;
    }

    // Display summary for each router instance
    for (int i = 0; i < sim->router_count; i++) {
        bgp_router_t *router = sim->routers[i];

        if (!router->active) continue;

        char router_id_str[INET_ADDRSTRLEN];
        router_id_to_str(router->router_id, router_id_str, sizeof(router_id_str));

        printf("\n");
        printf("BGP router identifier %s, local AS number %u\n", router_id_str, router->local_as);
        printf("BGP table version is 0, main routing table version 0\n");
        if (router->listener_error != 0) {
            // Passive mode: the listening socket did not open; the runtime keeps retrying it.
            printf("Listener on port %u is not open (%s), retrying\n", router->listen_port,
                   uv_strerror(router->listener_error));
        }
        printf("\n");

        printf("Neighbor        V    AS MsgRcvd MsgSent   TblVer" "  InQ OutQ Up/Down  State/PfxRcd\n");

        for (int j = 0; j < router->neighbor_count; j++) {
            bgp_neighbor_t *neighbor = router->neighbors[j];

            if (!neighbor->active) continue;

            // Calculate total messages
            uint64_t msg_rcvd = neighbor->rx_open + neighbor->rx_update +
                                neighbor->rx_keepalive + neighbor->rx_notification;
            uint64_t msg_sent = neighbor->tx_open + neighbor->tx_update +
                                neighbor->tx_keepalive + neighbor->tx_notification;

            // Format uptime or state
            char uptime[12] = "";
            if (neighbor->state == BGP_STATE_ESTABLISHED && neighbor->uptime > 0) {
                format_uptime(neighbor->uptime, uptime, sizeof(uptime));
            } else {
                snprintf(uptime, sizeof(uptime), "%s", bgp_state_to_string(neighbor->state));
            }

            // For established neighbors, show prefix count (0 for now)
            char state_pfx[16] = "";
            if (neighbor->state == BGP_STATE_ESTABLISHED) {
                snprintf(state_pfx, sizeof(state_pfx), "0");
            } else {
                snprintf(state_pfx, sizeof(state_pfx), "%s", bgp_state_to_string(neighbor->state));
            }

            printf("%-15s 4 %5u %7"PRIu64" %7"PRIu64" %8u %4u %4"PRIu64" %-8s %s\n",
                   neighbor->ip,
                   neighbor->remote_as,
                   msg_rcvd,
                   msg_sent,
                   0,                                                  /* TblVer               */
                   0,                                                  /* InQ                  */
                   neighbor->tx ? bgp_peer_tx_outq(neighbor->tx) : 0,  /* OutQ: queued UPDATEs */
                   uptime,
                   state_pfx);
        }
    }

    printf("\n");
    stdout_unlock();
}

/*
 * "snapshot 7 (ipv4-unicast)"
 */
static void cli_snapshot_text(const bgp_ribout_snapshot_t *snapshot, char *buf, size_t len) {
    snprintf(buf, len, "snapshot %" PRIu64 " (%s)", snapshot->id,
             bgp_ribout_family_info((bgp_ribout_family_t)snapshot->profile.family)->name);
}

/*
 * What the peer does with a bound ribout: advertised, or the pending job that will get it there.
 */
static void cli_binding_state(const bgp_peer_tx_t *tx, const char *name, char *buf, size_t len) {
    const bgp_tx_job_t *job = bgp_peer_tx_pending(tx, name);
    const bgp_tx_job_t *head = bgp_peer_tx_head(tx);

    if (!job) {
        snprintf(buf, len, "advertised");
    } else if (job == head && job->sent_msgs > 0) {
        snprintf(buf, len, "%s %zu/%zu UPDATEs", job->replay ? "replaying" : "sending", job->sent_msgs,
                 job->stream->count);
    } else {
        snprintf(buf, len, "%s queued (%zu UPDATEs)", job->replay ? "replay" : "advertisement", job->stream->count);
    }
}

/*
 * Outbound UPDATE state of a neighbor: bound ribouts, withheld ones, pending withdrawals and End-of-RIB. Lines are
 * indented so that no line starts with "BGP neighbor is".
 */
static void cli_show_neighbor_tx(const bgp_neighbor_t *neighbor) {
    const bgp_peer_tx_t *tx = neighbor->tx;
    char snapshot[96], state[64];

    if (!tx || (tx->binding_count == 0 && tx->withheld_count == 0 && tx->job_count == 0 &&
                tx->eor_sent_count == 0)) {
        return;
    }
    printf("  Outbound ribouts: OutQ %" PRIu64 " UPDATEs\n", bgp_peer_tx_outq(tx));
    for (size_t i = 0; i < tx->binding_count; i++) {
        cli_snapshot_text(tx->bindings[i].snapshot, snapshot, sizeof(snapshot));
        cli_binding_state(tx, tx->bindings[i].name, state, sizeof(state));
        printf("    %s: %s, %s\n", tx->bindings[i].name, snapshot, state);
    }
    for (size_t i = 0; i < tx->job_count; i++) {
        const bgp_tx_job_t *job = bgp_peer_tx_job(tx, i);

        if (job->kind == BGP_TX_JOB_WITHDRAW) {
            cli_snapshot_text(job->snapshot, snapshot, sizeof(snapshot));
            printf("    %s: withdrawing %s, %zu/%zu UPDATEs\n", job->name, snapshot, job->sent_msgs,
                   job->stream->count);
        }
    }
    for (size_t i = 0; i < tx->withheld_count; i++) {
        printf("    %s: withheld: %s\n", tx->withheld[i].name, tx->withheld[i].reason);
    }
    if (tx->eor_sent_count > 0) {
        printf("  End-of-RIB sent:");
        for (size_t i = 0; i < tx->eor_sent_count; i++) {
            const bgp_family_t *family = bgp_family_lookup(tx->eor_sent[i].afi, tx->eor_sent[i].safi);

            printf("%s %s", i ? "," : "", family ? family->display_name : "unknown");
        }
        printf("\n");
    }
}

/*
 * "Last notification sent: 6/4 (Cease/Administrative Reset), 00:12 ago", when there was one.
 */
static void cli_print_last_notification(const char *direction, const bgp_notification_record_t *record) {
    char reason[400];
    char ago[12];

    if (record->time == 0) {
        return;
    }
    bgp_notification_describe(record, reason, sizeof(reason));
    format_uptime(record->time, ago, sizeof(ago));
    printf("  Last notification %s: %s, %s ago\n", direction, reason, ago);
}

/*
 * Show neighbors for a specific router or all routers
 */
void cli_show_neighbors(bgp_sim_t *sim, uint32_t as_number) {
    stdout_lock();

    printf("\n");

    int found = 0;
    for (int i = 0; i < sim->router_count; i++) {
        bgp_router_t *router = sim->routers[i];

        if (!router->active) continue;
        if (as_number != 0 && router->local_as != as_number) continue;

        found = 1;

        if (router->neighbor_count == 0) {
            printf("No neighbors configured for AS %u.\n\n", router->local_as);
            continue;
        }

        for (int j = 0; j < router->neighbor_count; j++) {
            bgp_neighbor_t *neighbor = router->neighbors[j];

            if (!neighbor->active) continue;

            // Display detailed neighbor information
            printf("BGP neighbor is %s, remote AS %u, local AS %u\n",
                   neighbor->ip, neighbor->remote_as, router->local_as);

            // Convert remote BGP ID to dotted decimal if available
            if (neighbor->remote_id != 0) {
                char remote_id_str[INET_ADDRSTRLEN];
                router_id_to_str(neighbor->remote_id, remote_id_str, sizeof(remote_id_str));
                printf("  BGP version 4, remote router ID %s\n", remote_id_str);
            } else {
                printf("  BGP version 4, " "remote router ID not available\n");
            }

            // BGP state
            printf("  BGP state = %s", bgp_state_to_string(neighbor->state));
            if (neighbor->state == BGP_STATE_ESTABLISHED && neighbor->uptime > 0) {
                char up_str[12];
                format_uptime(neighbor->uptime, up_str, sizeof(up_str));
                printf(", up for %s", up_str);
            }
            printf("\n");

            // Last read/write
            if (neighbor->last_msg_time > 0) {
                char last_str[12];
                format_uptime(neighbor->last_msg_time, last_str, sizeof(last_str));
                printf("  Last read %s", last_str);
            }
            printf("\n");

            // Hold time
            if (neighbor->hold_time > 0) {
                printf("  Hold time is %u, keepalive interval is %u seconds\n",
                       neighbor->hold_time, neighbor->hold_time / 3);
            }

            // Message statistics
            printf("  Message statistics:    Sent       Rcvd\n");
            printf("    Opens:            %7"PRIu64"    %7"PRIu64"\n", neighbor->tx_open, neighbor->rx_open);
            printf("    Notifications:    %7"PRIu64"    %7"PRIu64"\n",
                   neighbor->tx_notification,
                   neighbor->rx_notification);
            printf("    Updates:          %7"PRIu64"    %7"PRIu64"\n", neighbor->tx_update, neighbor->rx_update);
            printf("    Keepalives:       %7"PRIu64"    %7"PRIu64"\n", neighbor->tx_keepalive, neighbor->rx_keepalive);

            // Session reset counter if applicable
            if (neighbor->session_resets > 0) {
                printf("  Session resets: %"PRIu64"\n", neighbor->session_resets);
            }
            cli_print_last_notification("sent", &neighbor->last_notification_tx);
            cli_print_last_notification("received", &neighbor->last_notification_rx);

            // Neighbor Capabilities
            if (neighbor->peer_capabilities_received) {
                printf("  Neighbor Capabilities:\n");

                // Helper macros to determine capability status
                #define CAP_STATUS(local, peer)                       \
                    ((local) && (peer)) ? "advertised and received" : \
                    ((local) ? "advertised" : "received")

                // Multiprotocol BGP capabilities
                for (int i = 0; i < BGP_NUM_FAMILIES; i++) {
                    const bgp_family_t *fam = &bgp_families[i];
                    int                 local_mp = *(const int *)((const char *)&neighbor->capabilities + fam->mp_offset);
                    int                 peer_mp  = *(const int *)((const char *)&neighbor->peer_capabilities + fam->mp_offset);
                    if (local_mp || peer_mp) {
                        printf("    Multiprotocol %s: %s\n", fam->display_name, CAP_STATUS(local_mp, peer_mp));
                    }
                }

                // Route Refresh
                if (neighbor->capabilities.route_refresh ||
                    neighbor->peer_capabilities.route_refresh) {
                    printf("    Route refresh: %s\n",
                           CAP_STATUS(neighbor->capabilities.route_refresh,
                                      neighbor->peer_capabilities.route_refresh));
                }

                if (neighbor->capabilities.four_byte_asn ||
                    neighbor->peer_capabilities.four_byte_asn) {
                    printf("    4-byte ASN: %s\n",
                           CAP_STATUS(neighbor->capabilities.four_byte_asn,
                                      neighbor->peer_capabilities.four_byte_asn));
                }

                // Graceful Restart
                if (neighbor->capabilities.graceful_restart ||
                    neighbor->peer_capabilities.graceful_restart) {
                    printf("    Graceful Restart: %s\n",
                           CAP_STATUS(neighbor->capabilities.graceful_restart,
                                      neighbor->peer_capabilities.graceful_restart));
                    if (neighbor->peer_capabilities.graceful_restart &&
                        neighbor->peer_capabilities.restart_time > 0) {
                        printf("      Restart time: %u seconds\n", neighbor->peer_capabilities.restart_time);
                    }
                }

                // ADD-PATH per family
                for (int i = 0; i < BGP_NUM_FAMILIES; i++) {
                    const bgp_family_t *fam = &bgp_families[i];
                    int                 local_mp = *(const int *)((const char *)&neighbor->capabilities + fam->mp_offset);
                    uint8_t             local_ap = *(const uint8_t *)((const char *)&neighbor->capabilities + fam->add_path_offset);
                    uint8_t peer_ap  =
                        *(const uint8_t *)((const char *)&neighbor->peer_capabilities + fam->add_path_offset);
                    int local_active = local_mp && local_ap;
                    if (local_active || peer_ap) {
                        printf("    ADD-PATH %s: %s\n", fam->display_name, CAP_STATUS(local_active, peer_ap));
                    }
                }

                // Extended next-hop (only families with ext_nh_offset)
                for (int i = 0; i < BGP_NUM_FAMILIES; i++) {
                    const bgp_family_t *fam = &bgp_families[i];
                    if (fam->ext_nh_offset == NO_CAP_OFFSET) {
                        continue;
                    }
                    int local_mp = *(const int *)((const char *)&neighbor->capabilities + fam->mp_offset);
                    int local_nh = *(const int *)((const char *)&neighbor->capabilities + fam->ext_nh_offset);
                    int peer_nh  = *(const int *)((const char *)&neighbor->peer_capabilities + fam->ext_nh_offset);
                    int local_active = local_mp && local_nh;
                    if (local_active || peer_nh) {
                        printf("    Extended next-hop %s over IPv6: %s\n",
                               fam->display_name, CAP_STATUS(local_active, peer_nh));
                    }
                }

                #undef CAP_STATUS
            }

            cli_show_neighbor_tx(neighbor);

            // Connection state
            printf("  Connection state is %s\n", neighbor->sock_fd >= 0 ? "ESTAB" : "CLOSED");

            printf("\n");
        }
    }

    if (!found && as_number != 0) {
        printf("BGP router AS %u not found.\n\n", as_number);
    }

    stdout_unlock();
}

/*
 * Show current configuration
 */
void cli_show_config(bgp_sim_t *sim) {
    stdout_lock();

    printf("\n");
    printf("!\n");
    printf("! BGP Simulator Configuration\n");
    printf("!\n");

    // Output ribout blocks first
    for (int i = 0; i < sim->ribout_count; i++) {
        bgp_ribout_config_t *block = sim->ribouts[i];

        printf("ribout %s\n", block->name);
        if (*block->nlri_template.text) printf("  %s\n", block->nlri_template.text);
        if (*block->family_attr_text) printf("  %s\n", block->family_attr_text);
        if (*block->l2_info_text) printf("  %s\n", block->l2_info_text);

        if (block->address_family_afi != 0) {
            const bgp_family_t *family = bgp_family_lookup(block->address_family_afi, block->address_family_safi);

            if (family) {
                printf("  address-family %s\n", family->cli_name);
            }
        }

        // Prefix
        if (block->prefix_spec.count > 0) {
            char prefix_str[INET6_ADDRSTRLEN];
            if (block->prefix_spec.af == AF_INET) {
                inet_ntop(AF_INET, &block->prefix_spec.base_addr.ipv4, prefix_str, sizeof(prefix_str));
            } else {
                inet_ntop(AF_INET6, &block->prefix_spec.base_addr.ipv6, prefix_str, sizeof(prefix_str));
            }
            printf("  prefix %s/", prefix_str);
            if (block->prefix_offset > 0) {
                printf("%u-", block->prefix_offset);
            }
            printf("%u", block->prefix_spec.prefix_len);
            if (block->prefix_spec.count > 1) {
                printf(" x %u", block->prefix_spec.count);
            }
            printf("\n");
        }
        cli_print_ribout_flowspec_match(block);

        // SR Policy endpoint
        cli_print_ribout_next_hop_spec(block->endpoint_rotate ? "endpoint rotate" : "endpoint", &block->endpoint_spec);

        // Route distinguishers
        cli_print_ribout_rds(block);
        cli_print_ribout_u32_values(block->distinguisher_rotate ? "distinguisher rotate" : "distinguisher",
                                    block->distinguishers, block->distinguisher_count, block->distinguishers_step);
        if (block->color_count > 0) {
            printf("  color %s", block->color_set ? "set " : block->color_rotate ? "rotate " : "");
            cli_print_ribout_colors(block);
            printf("\n");
        }

        // Labels
        cli_print_ribout_labels(block);
        cli_print_ribout_label2s(block);

        // Ethernet tags
        cli_print_ribout_ethernet_tags(block);
        cli_print_ribout_mac_spec(block);
        cli_print_ribout_next_hop_spec(block->ip_rotate ? "ip rotate" : "ip", &block->ip_spec);
        cli_print_ribout_next_hop_spec(block->ip2_rotate ? "ip rotate" : "ip", &block->ip2_spec);

        // Path-IDs
        cli_print_ribout_u32_values(block->path_id_rotate ? "path-id rotate" : "path-id", block->path_ids, block->path_id_count, block->path_ids_step);

        // Next-hop
        cli_print_ribout_next_hop_spec("next-hop", &block->next_hop_spec);

        // EVPN gateway IP
        cli_print_ribout_next_hop_spec("gateway-ip", &block->gateway_ip_spec);

        // EVPN ESI
        cli_print_ribout_esis(block);

        // AS-path
        if (block->aspath_segment_count > 0) {
            printf("  as-path");
            for (uint32_t j = 0; j < block->aspath_segment_count; j++) {
                bgp_aspath_segment_t *seg = &block->aspath_segments[j];

                if (seg->type == ASPATH_SEQUENCE) {
                    // AS sequence: 100 200 300
                    for (uint32_t k = 0; k < seg->value_count; k++) {
                        printf(" %u", seg->as_values[k]);
                    }
                } else if (seg->type == ASPATH_SET) {
                    // AS set: { 100 200 300 }
                    printf(" {");
                    for (uint32_t k = 0; k < seg->value_count; k++) {
                        printf(" %u", seg->as_values[k]);
                    }
                    printf(" }");
                } else if (seg->type == ASPATH_RANDOM) {
                    // Random: [rand(500) x 10] or [rand(500)] if count is 1
                    if (seg->rand_count == 1) {
                        printf(" rand(%u)", seg->rand_max);
                    } else {
                        printf(" [rand(%u) x %u]", seg->rand_max, seg->rand_count);
                    }
                }
            }
            printf("\n");
        }

        // Local preference
        cli_print_ribout_scalar_spec("localpref", &block->localpref_spec);

        // MED
        if (block->med_spec.enabled) {
            cli_print_ribout_optional_scalar_spec("med", &block->med_spec);
        }

        // Route-targets and SoO
        cli_print_ribout_ext_comms("rt", block->rt_values, block->rt_count);
        cli_print_ribout_rt_sets(block);
        cli_print_ribout_community_lines(block, 0);
        cli_print_ribout_community_lines(block, 1);
        if (block->rotate_every > 0) {
            printf("  rotate-every %u\n", block->rotate_every);
        }
        if (block->rotate_period > 0) {
            printf("  rotate-period %u\n", block->rotate_period);
        }
        cli_print_ribout_ext_comms("soo", block->soo_values, block->soo_count);
        cli_print_ribout_ext_comms("encap", block->encap_values, block->encap_count);
        cli_print_ribout_ext_comms("router-mac", block->router_mac_values, block->router_mac_count);
        cli_print_ribout_enlps(block);
        cli_print_ribout_priorities(block);
        cli_print_ribout_preferences(block);
        cli_print_ribout_binding_sids(block);
        cli_print_ribout_segment_lists(block);

        // Origin
        printf("  origin %s\n", bgp_origin_to_string(block->origin));

        // FlowSpec action lines
        for (uint32_t i = 0; block->flowspec && i < block->flowspec->actions.line_count; i++) {
            printf("  %s\n", block->flowspec->actions.lines[i].text);
        }

        printf("!\n");
    }

    // Output BGP routers
    for (int i = 0; i < sim->router_count; i++) {
        bgp_router_t *router = sim->routers[i];

        if (!router->active) continue;

        printf("router bgp %u\n", router->local_as);

        // Router ID if manually configured
        if (router->router_id_configured) {
            char router_id_str[INET_ADDRSTRLEN];
            router_id_to_str(router->router_id, router_id_str, sizeof(router_id_str));
            printf("  router-id %s\n", router_id_str);
        }

        // Source IP if configured
        if (router->source_ip[0] != '\0') {
            printf("  update-source %s\n", router->source_ip);
        }

        // Neighbors
        for (int j = 0; j < router->neighbor_count; j++) {
            bgp_neighbor_t *neighbor = router->neighbors[j];

            if (!neighbor->active) continue;

            printf("  neighbor %s remote-as %u\n", neighbor->ip, neighbor->remote_as);

            if (neighbor->source_ip[0] != '\0') {
                printf("    update-source %s\n", neighbor->source_ip);
            }

            for (int a = 0; a < neighbor->advertise_count; a++) {
                printf("    advertise %s\n", neighbor->advertise[a]);
            }

            // Neighbor capabilities - shown as if in neighbor config mode
            // These are indented to show they would be entered in neighbor mode

            /*
             * Address-family capabilities (ipv4/ipv6 unicast are
             * defaults and are not shown in running-config).
             */
            for (int i = 2; i < BGP_NUM_FAMILIES; i++) {
                int enabled = *(const int *)((const char *)&neighbor->capabilities + bgp_families[i].mp_offset);
                if (enabled) {
                    printf("    address-family %s\n", bgp_families[i].cli_name);
                }
            }

            // Non-address-family capabilities
            if (neighbor->capabilities.route_refresh) {
                printf("    capability route-refresh\n");
            }
            if (!neighbor->capabilities.four_byte_asn) {
                printf("    no capability four-byte-asn\n");
            }
            if (neighbor->capabilities.graceful_restart) {
                if (neighbor->capabilities.restart_time != 120) {
                    printf("    capability graceful-restart restart-time %u\n", neighbor->capabilities.restart_time);
                } else {
                    printf("    capability graceful-restart\n");
                }
            }

            /*
             * ADD-PATH: emit bare "capability add-path" if ALL families
             * are enabled, otherwise list each individually.
             */
            {
                int all_ap = 1;
                for (int i = 0; i < BGP_NUM_FAMILIES; i++) {
                    uint8_t ap = *(const uint8_t *)((const char *)&neighbor->capabilities +
                                                    bgp_families[i].add_path_offset);
                    if (!ap) { all_ap = 0; break; }
                }
                if (all_ap) {
                    printf("    capability add-path\n");
                } else {
                    for (int i = 0; i < BGP_NUM_FAMILIES; i++) {
                        uint8_t ap = *(const uint8_t *)((const char *)&neighbor->capabilities +
                                                        bgp_families[i].add_path_offset);
                        if (ap) {
                            printf("    capability add-path %s\n", bgp_families[i].cli_name);
                        }
                    }
                }
            }

            /*
             * Extended next-hop: emit bare "capability ext-nh" if all
             * ext-nh-capable families are enabled.
             */
            {
                int all_nh = 1, any_nh = 0;
                for (int i = 0; i < BGP_NUM_FAMILIES; i++) {
                    if (bgp_families[i].ext_nh_offset == NO_CAP_OFFSET)
                        continue;
                    int val = *(const int *)((const char *)&neighbor->capabilities + bgp_families[i].ext_nh_offset);
                    if (val) { any_nh = 1; } else { all_nh = 0; }
                }
                if (any_nh && all_nh) {
                    printf("    capability ext-nh\n");
                } else {
                    for (int i = 0; i < BGP_NUM_FAMILIES; i++) {
                        if (bgp_families[i].ext_nh_offset == NO_CAP_OFFSET)
                            continue;
                        int val = *(const int *)((const char *)&neighbor->capabilities + bgp_families[i].ext_nh_offset);
                        if (val) {
                            printf("    capability ext-nh %s\n", bgp_families[i].cli_name);
                        }
                    }
                }
            }
        }

        printf("!\n");
    }

    script_print_config(&sim->scripts);
    printf("!\n");

    stdout_unlock();
}

/*
 * Show all ribout blocks
 */
void cli_show_ribout(bgp_sim_t *sim) {
    stdout_lock();
    printf("\n%-20s %-18s %-12s %-10s %-15s\n", "Name", "Family", "Base NLRIs", "Path-IDs", "Total Paths");
    printf("--------------------------------------------------------------------------\n");

    if (sim->ribout_count == 0) {
        printf("No ribouts configured.\n");
    } else {
        for (int i = 0; i < sim->ribout_count; i++) {
            bgp_ribout_config_t *block = sim->ribouts[i];
            printf("%-20s %-18s %-12llu %-10u %-15llu\n",
                   block->name,
                   bgp_ribout_family_info(bgp_ribout_resolve_family(block))->name,
                   (unsigned long long)cli_ribout_base_nlri_count(block),
                   block->path_id_count,
                   (unsigned long long)cli_ribout_total_paths(block));
        }
    }

    printf("\n");
    stdout_unlock();
}

/*
 * Show details of a specific ribout block
 */
void cli_show_ribout_detail(bgp_sim_t *sim, const char *name) {
    stdout_lock();

    bgp_ribout_config_t *block = bgp_sim_find_ribout(sim, name);

    if (!block) {
        printf("\nribout '%s' not found.\n\n", name);
        stdout_unlock();
        return;
    }

    printf("\nribout block: %s\n", block->name);
    printf("===============================================\n");
    bgp_ribout_family_t family = bgp_ribout_resolve_family(block);

    /*
     * Label column width: widest label is "AS-Path Segments:" / "Local
     * Preference:" at 17 chars across all families, plus 2 chars of buffer.
     */
    const int w = 19;

    // Header
    printf("%-*s%s\n", w, "Family:", bgp_ribout_family_info(family)->name);
    printf("%-*s%"PRIu64"\n", w, "Base NLRIs:", cli_ribout_base_nlri_count(block));
    printf("%-*s%"PRIu64"\n", w, "Total Paths:", cli_ribout_total_paths(block));
    if (*block->nlri_template.text) {
        printf("%-*s%s\n", w, "NLRI template:", block->nlri_template.text + 5);
    }
    if (*block->family_attr_text) {
        printf("%-*s%s\n", w, "Family attribute:", block->family_attr_text);
    }

    // Basic fields (classic BGP rows everyone recognizes)

    // Prefixes: BASE/LEN [x COUNT]
    if (block->prefix_spec.count > 0) {
        char prefix_str[INET6_ADDRSTRLEN];
        if (block->prefix_spec.af == AF_INET) {
            inet_ntop(AF_INET, &block->prefix_spec.base_addr.ipv4, prefix_str, sizeof(prefix_str));
        } else {
            inet_ntop(AF_INET6, &block->prefix_spec.base_addr.ipv6, prefix_str, sizeof(prefix_str));
        }
        printf("%-*s%s/", w, "Prefixes:", prefix_str);
        if (block->prefix_offset > 0) {
            printf("%u-", block->prefix_offset);
        }
        printf("%u", block->prefix_spec.prefix_len);
        if (block->prefix_spec.count > 1) {
            printf(" x %u", block->prefix_spec.count);
        }
        printf("\n");
    }

    // Path-IDs (ADD-PATH discriminator)
    printf("%-*s%s", w, "Path-IDs:", block->path_id_rotate ? "rotate " : "");
    if (block->path_id_count == 0) {
        printf("unset\n");
    } else if (block->path_id_count > 1 &&
               cli_ribout_u32_values_are_sequential(block->path_ids, block->path_id_count, block->path_ids_step)) {
        printf("%u x %u\n", bgp_ribout_path_ids_at(block, 0), block->path_id_count);
    } else {
        for (uint32_t i = 0; i < block->path_id_count; i++) {
            printf("%s%u", i == 0 ? "" : " ", bgp_ribout_path_ids_at(block, i));
        }
        printf("\n");
    }

    // Next-hops
    printf("%-*s", w, "Next-hops:");
    if (block->next_hop_spec.count == 0) {
        printf("unset\n");
    } else {
        char nh_str[INET6_ADDRSTRLEN];
        if (block->next_hop_spec.af == AF_INET) {
            inet_ntop(AF_INET, &block->next_hop_spec.base_addr.ipv4, nh_str, sizeof(nh_str));
        } else {
            inet_ntop(AF_INET6, &block->next_hop_spec.base_addr.ipv6, nh_str, sizeof(nh_str));
        }
        if (block->next_hop_spec.count > 1) {
            printf("%s x %u", nh_str, block->next_hop_spec.count);
        } else {
            printf("%s", nh_str);
        }
        if (block->next_hop_spec.af == AF_INET6 && block->next_hop_spec.has_link_local) {
            char ll_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &block->next_hop_spec.link_local, ll_str, sizeof(ll_str));
            printf(" link-local %s", ll_str);
        }
        printf("\n");
    }

    // AS-Path (show the actual segments, not a count)
    printf("%-*s", w, "AS-Path:");
    if (block->aspath_segment_count == 0) {
        printf("unset\n");
    } else {
        char aspath_str[MAX_ASPATH_STRING_LEN];
        bgp_aspath_to_string(block->aspath_segments, block->aspath_segment_count, aspath_str, sizeof(aspath_str));
        printf("%s\n", aspath_str);
    }

    // Local Preference
    printf("%-*s", w, "Local Preference:");
    if (block->localpref_spec.mode == BGP_U32_MODE_FIXED) {
        printf("%u\n", block->localpref_spec.value);
    } else if (block->localpref_spec.mode == BGP_U32_MODE_RANDOM) {
        printf("rand(%u)\n", block->localpref_spec.value);
    } else if (block->localpref_spec.mode == BGP_U32_MODE_RANGE) {
        printf("range(%u,%u)\n", block->localpref_spec.range_start, block->localpref_spec.range_end);
    } else {
        printf("randrange(%u,%u)\n", block->localpref_spec.range_start, block->localpref_spec.range_end);
    }

    // MED
    printf("%-*s", w, "MED:");
    if (!block->med_spec.enabled) {
        printf("unset\n");
    } else if (block->med_spec.mode == BGP_U32_MODE_FIXED) {
        printf("%u\n", block->med_spec.value);
    } else if (block->med_spec.mode == BGP_U32_MODE_RANDOM) {
        printf("rand(%u)\n", block->med_spec.value);
    } else if (block->med_spec.mode == BGP_U32_MODE_RANGE) {
        printf("range(%u,%u)\n", block->med_spec.range_start, block->med_spec.range_end);
    } else {
        printf("randrange(%u,%u)\n", block->med_spec.range_start, block->med_spec.range_end);
    }

    // Origin
    printf("%-*s%s\n", w, "Origin:", bgp_origin_to_string(block->origin));

    // Advanced NLRI-side family-specific tokens (config-syntax form)

    // RDs: space-separated stringified values
    if (block->rd_count > 0) {
        printf("%-*s%s", w, "RDs:", block->rd_rotate ? "rotate " : "");
        for (uint32_t i = 0; i < block->rd_count; i++) {
            char                  rd_str[64];
            route_distinguisher_t rd = bgp_ribout_rds_at(block, i);
            cli_rd_to_string(&rd, rd_str, sizeof(rd_str));
            printf("%s%s", i == 0 ? "" : " ", rd_str);
        }
        printf("\n");
    }

    // Labels: list of values (or "base x count" if sequential)
    if (block->label_count > 0) {
        printf("%-*s%s", w, "Labels:", block->label_rotate ? "rotate " : "");
        if (block->label_count > 1 && cli_ribout_labels_are_sequential(block)) {
            printf("%u x %u\n", bgp_ribout_labels_at(block, 0), block->label_count);
        } else {
            for (uint32_t i = 0; i < block->label_count; i++) {
                printf("%s%u", i == 0 ? "" : " ", bgp_ribout_labels_at(block, i));
            }
            printf("\n");
        }
    }

    // Label2s: list (or "base x count" if sequential)
    if (block->label2_count > 0) {
        printf("%-*s", w, "Label2s:");
        if (block->label2_count > 1 &&
            cli_ribout_u32_values_are_sequential(block->label2s, block->label2_count, block->label2s_step)) {
            printf("%u x %u\n", bgp_ribout_label2s_at(block, 0), block->label2_count);
        } else {
            for (uint32_t i = 0; i < block->label2_count; i++) {
                printf("%s%u", i == 0 ? "" : " ", bgp_ribout_label2s_at(block, i));
            }
            printf("\n");
        }
    }

    // Ethernet Tags: list (or "base x count" if sequential)
    if (block->ethernet_tag_count > 0) {
        printf("%-*s%s", w, "Ethernet Tags:", block->ethernet_tag_rotate ? "rotate " : "");
        if (block->ethernet_tag_count > 1 && cli_ribout_ethernet_tags_are_sequential(block)) {
            printf("%u x %u\n", bgp_ribout_ethernet_tags_at(block, 0), block->ethernet_tag_count);
        } else {
            for (uint32_t i = 0; i < block->ethernet_tag_count; i++) {
                printf("%s%u", i == 0 ? "" : " ", bgp_ribout_ethernet_tags_at(block, i));
            }
            printf("\n");
        }
    }

    // MACs: BASE [x COUNT]
    if (block->mac_spec.count > 0) {
        char mac_str[32];
        cli_mac_to_string(block->mac_spec.base_addr, mac_str, sizeof(mac_str));
        printf("%-*s%s", w, "MACs:", mac_str);
        if (block->mac_spec.count > 1) {
            printf(" x %u", block->mac_spec.count);
        }
        printf("\n");
    }

    // IPs (EVPN Type 2): BASE [x COUNT], per address family
    for (int slot = 0; slot < 2; slot++) {
        const bgp_next_hop_spec_t *spec = slot ? &block->ip2_spec : &block->ip_spec;
        char                       ip_str[INET6_ADDRSTRLEN];

        if (spec->count == 0) {
            continue;
        }
        if (spec->af == AF_INET) {
            inet_ntop(AF_INET, &spec->base_addr.ipv4, ip_str, sizeof(ip_str));
        } else {
            inet_ntop(AF_INET6, &spec->base_addr.ipv6, ip_str, sizeof(ip_str));
        }
        printf("%-*s%s%s", w, "IPs:", (slot ? block->ip2_rotate : block->ip_rotate) ? "rotate " : "", ip_str);
        if (spec->count > 1) {
            printf(" x %u", spec->count);
        }
        printf("\n");
    }
    if (block->rotate_every > 0) {
        printf("%-*s%u paths\n", w, "Rotate every:", block->rotate_every);
    }
    if (block->rotate_period > 0) {
        printf("%-*s%u values\n", w, "Rotate period:", block->rotate_period);
    }

    // ESIs: space-separated stringified values
    if (block->esi_count > 0) {
        printf("%-*s", w, "ESIs:");
        for (uint32_t i = 0; i < block->esi_count; i++) {
            char esi_str[64];
            cli_esi_to_string(&block->esis[i], esi_str, sizeof(esi_str));
            printf("%s%s", i == 0 ? "" : " ", esi_str);
        }
        printf("\n");
    }

    // Gateway-IPs: BASE [x COUNT]
    if (block->gateway_ip_spec.count > 0) {
        char gw_str[INET6_ADDRSTRLEN];
        if (block->gateway_ip_spec.af == AF_INET) {
            inet_ntop(AF_INET, &block->gateway_ip_spec.base_addr.ipv4, gw_str, sizeof(gw_str));
        } else {
            inet_ntop(AF_INET6, &block->gateway_ip_spec.base_addr.ipv6, gw_str, sizeof(gw_str));
        }
        printf("%-*s%s", w, "Gateway-IPs:", gw_str);
        if (block->gateway_ip_spec.count > 1) {
            printf(" x %u", block->gateway_ip_spec.count);
        }
        printf("\n");
    }

    // Distinguishers: list
    if (block->distinguisher_count > 0) {
        printf("%-*s%s", w, "Distinguishers:", block->distinguisher_rotate ? "rotate " : "");
        if (block->distinguisher_count > 1 &&
            cli_ribout_u32_values_are_sequential(block->distinguishers, block->distinguisher_count, block->distinguishers_step)) {
            printf("%u x %u\n", bgp_ribout_distinguishers_at(block, 0), block->distinguisher_count);
        } else {
            for (uint32_t i = 0; i < block->distinguisher_count; i++) {
                printf("%s%u", i == 0 ? "" : " ", bgp_ribout_distinguishers_at(block, i));
            }
            printf("\n");
        }
    }

    // Colors: SR Policy NLRI values, or a rotating/fixed set of Color communities.
    if (block->color_count > 0) {
        printf("%-*s%s", w, bgp_ribout_family_info(family)->kind == BGP_RIBOUT_KIND_SR_POLICY ?
                          "Colors:" : "Color communities:", block->color_set ? "set " : block->color_rotate ? "rotate " : "");
        cli_print_ribout_colors(block);
        printf("\n");
    }

    // Endpoints (SR Policy): BASE [x COUNT]
    if (block->endpoint_spec.count > 0) {
        char ep_str[INET6_ADDRSTRLEN];
        if (block->endpoint_spec.af == AF_INET) {
            inet_ntop(AF_INET, &block->endpoint_spec.base_addr.ipv4, ep_str, sizeof(ep_str));
        } else {
            inet_ntop(AF_INET6, &block->endpoint_spec.base_addr.ipv6, ep_str, sizeof(ep_str));
        }
        printf("%-*s%s%s", w, "Endpoints:", block->endpoint_rotate ? "rotate " : "", ep_str);
        if (block->endpoint_spec.count > 1) {
            printf(" x %u", block->endpoint_spec.count);
        }
        printf("\n");
    }

    // SR Policy candidate-path attributes
    if (block->enlp_spec.enabled) {
        if (block->enlp_spec.mode == BGP_U32_MODE_RANDOM) {
            printf("%-*srand(%u)\n", w, "ENLP:", block->enlp_spec.value);
        } else if (block->enlp_spec.mode == BGP_U32_MODE_RANGE) {
            printf("%-*srange(%u,%u)\n", w, "ENLP:", block->enlp_spec.range_start, block->enlp_spec.range_end);
        } else if (block->enlp_spec.mode == BGP_U32_MODE_RANDOM_RANGE) {
            printf("%-*srandrange(%u,%u)\n", w, "ENLP:", block->enlp_spec.range_start, block->enlp_spec.range_end);
        } else {
            printf("%-*s%u\n", w, "ENLP:", block->enlp_spec.value);
        }
    } else if (block->enlp_count > 0) {
        printf("%-*s", w, "ENLPs:");
        for (uint32_t i = 0; i < block->enlp_count; i++) {
            printf("%s%u", i == 0 ? "" : " ", bgp_ribout_enlps_at(block, i));
        }
        printf("\n");
    }
    if (block->priority_spec.enabled) {
        if (block->priority_spec.mode == BGP_U32_MODE_RANDOM) {
            printf("%-*srand(%u)\n", w, "Priority:", block->priority_spec.value);
        } else if (block->priority_spec.mode == BGP_U32_MODE_RANGE) {
            printf("%-*srange(%u,%u)\n", w, "Priority:",
                   block->priority_spec.range_start, block->priority_spec.range_end);
        } else if (block->priority_spec.mode == BGP_U32_MODE_RANDOM_RANGE) {
            printf("%-*srandrange(%u,%u)\n", w, "Priority:",
                   block->priority_spec.range_start, block->priority_spec.range_end);
        } else {
            printf("%-*s%u\n", w, "Priority:", block->priority_spec.value);
        }
    } else if (block->priority_count > 0) {
        printf("%-*s", w, "Priorities:");
        for (uint32_t i = 0; i < block->priority_count; i++) {
            printf("%s%u", i == 0 ? "" : " ", bgp_ribout_priorities_at(block, i));
        }
        printf("\n");
    }
    if (block->preference_spec.enabled) {
        if (block->preference_spec.mode == BGP_U32_MODE_RANDOM) {
            printf("%-*srand(%u)\n", w, "Preference:", block->preference_spec.value);
        } else if (block->preference_spec.mode == BGP_U32_MODE_RANGE) {
            printf("%-*srange(%u,%u)\n", w, "Preference:",
                   block->preference_spec.range_start, block->preference_spec.range_end);
        } else if (block->preference_spec.mode == BGP_U32_MODE_RANDOM_RANGE) {
            printf("%-*srandrange(%u,%u)\n", w, "Preference:",
                   block->preference_spec.range_start, block->preference_spec.range_end);
        } else {
            printf("%-*s%u\n", w, "Preference:", block->preference_spec.value);
        }
    } else if (block->preference_count > 0) {
        printf("%-*s", w, "Preferences:");
        for (uint32_t i = 0; i < block->preference_count; i++) {
            printf("%s%u", i == 0 ? "" : " ", bgp_ribout_preferences_at(block, i));
        }
        printf("\n");
    }
    if (block->binding_sid_spec.enabled) {
        if (block->binding_sid_spec.mode == BGP_U32_MODE_RANDOM) {
            printf("%-*smpls rand(%u)\n", w, "Binding SIDs:", block->binding_sid_spec.value);
        } else if (block->binding_sid_spec.mode == BGP_U32_MODE_RANGE) {
            printf("%-*smpls range(%u,%u)\n", w, "Binding SIDs:",
                   block->binding_sid_spec.range_start, block->binding_sid_spec.range_end);
        } else if (block->binding_sid_spec.mode == BGP_U32_MODE_RANDOM_RANGE) {
            printf("%-*smpls randrange(%u,%u)\n", w, "Binding SIDs:",
                   block->binding_sid_spec.range_start, block->binding_sid_spec.range_end);
        } else {
            printf("%-*smpls %u\n", w, "Binding SIDs:", block->binding_sid_spec.value);
        }
    } else if (block->binding_sid_count > 0) {
        printf("%-*smpls", w, "Binding SIDs:");
        for (uint32_t i = 0; i < block->binding_sid_count; i++) {
            printf(" %u", bgp_ribout_binding_sids_at(block, i));
        }
        printf("\n");
    } else if (block->binding_sid_kind == BGP_RIBOUT_SR_BINDING_SID_SRV6 && block->binding_sid_srv6_spec.count > 0) {
        char sid_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &block->binding_sid_srv6_spec.base_addr.ipv6, sid_str, sizeof(sid_str));
        printf("%-*ssrv6 %s", w, "Binding SIDs:", sid_str);
        if (block->binding_sid_srv6_spec.count > 1) {
            printf(" x %u", block->binding_sid_srv6_spec.count);
        }
        printf("\n");
    }

    // Segment Lists: id=N (weight W)
    if (block->segment_list_count > 0) {
        printf("%-*s", w, "Segment Lists:");
        for (uint32_t i = 0; i < block->segment_list_count; i++) {
            printf("%sid=%u", i == 0 ? "" : " ", block->segment_lists[i].id);
        }
        printf("\n");
    }

    // Extended community surface
    if (block->rt_count > 0) {
        printf("%-*s", w, "RTs:");
        for (uint32_t i = 0; i < block->rt_count; i++) {
            char rt_str[64];
            cli_ext_comm_to_string(&block->rt_values[i], rt_str, sizeof(rt_str));
            printf("%s%s", i == 0 ? "" : " ", rt_str);
        }
        printf("\n");
    }
    for (int large = 0; large <= 1; large++) {
        uint32_t groups = large ? block->large_community_group_count : block->community_group_count;

        if (groups > 0) {
            uint64_t sets = large ? bgp_ribout_large_community_sets(block) : bgp_ribout_community_sets(block);

            printf("%-*s", w, large ? "Large Communities:" : "Communities:");
            for (uint32_t i = 0; i < groups; i++) {
                char text[BGPSIM_COMMAND_SIZE];

                cli_community_group_text(block, large, i, text, sizeof(text));
                printf("%s%s", i == 0 ? "" : " ", text);
            }
            printf(" (%" PRIu64 " set%s, rotating)\n", sets, sets == 1 ? "" : "s");
        }
    }
    if (block->rt_set_count > 0) {
        printf("%-*s", w, "RT Sets:");
        for (uint32_t i = 0; i < block->rt_set_group_count; i++) {
            printf("%s[", i == 0 ? "" : " ");
            for (uint32_t j = 0; j < block->rt_sets[i].count; j++) {
                char rt_str[64];
                cli_ext_comm_to_string(&block->rt_sets[i].values[j], rt_str, sizeof(rt_str));
                printf("%s%s", j == 0 ? "" : ",", rt_str);
            }
            printf("]");
            if (block->rt_sets[i].repeat > 1) printf(" x %u", block->rt_sets[i].repeat);
        }
        printf("\n");
    }
    if (block->soo_count > 0) {
        printf("%-*s", w, "SoOs:");
        for (uint32_t i = 0; i < block->soo_count; i++) {
            char soo_str[64];
            cli_ext_comm_to_string(&block->soo_values[i], soo_str, sizeof(soo_str));
            printf("%s%s", i == 0 ? "" : " ", soo_str);
        }
        printf("\n");
    }
    if (block->encap_count > 0) {
        printf("%-*s", w, "Encaps:");
        for (uint32_t i = 0; i < block->encap_count; i++) {
            char enc_str[64];
            cli_ext_comm_to_string(&block->encap_values[i], enc_str, sizeof(enc_str));
            printf("%s%s", i == 0 ? "" : " ", enc_str);
        }
        printf("\n");
    }
    if (block->router_mac_count > 0) {
        printf("%-*s", w, "Router-MACs:");
        for (uint32_t i = 0; i < block->router_mac_count; i++) {
            char rm_str[64];
            cli_ext_comm_to_string(&block->router_mac_values[i], rm_str, sizeof(rm_str));
            printf("%s%s", i == 0 ? "" : " ", rm_str);
        }
        printf("\n");
    }

    // FlowSpec: the match components after the prefix, then the action lines, in config syntax
    if (block->flowspec) {
        char text[MAX_FLOWSPEC_LINE_TEXT];
        int  first = 1;

        for (uint8_t type = FLOWSPEC_SRC_PREFIX; type <= FLOWSPEC_FLOW_LABEL; type++) {
            if (bgp_ribout_flowspec_component_to_string(block, type, text, sizeof(text))) {
                printf("%-*s%s\n", w, first ? "Match:" : "", text);
                first = 0;
            }
        }
        for (uint32_t i = 0; i < block->flowspec->actions.line_count; i++) {
            printf("%-*s%s\n", w, (i == 0) ? "Actions:" : "",
                   block->flowspec->actions.lines[i].text + strlen("action "));
        }
    }

    // Show the published UPDATE snapshot
    if (block->snapshot) {
        const bgp_ribout_snapshot_t *snapshot = block->snapshot;
        size_t                       total_bytes = (size_t)snapshot->adv->bytes;
        char                         profile[96];

        printf("\nBGP UPDATE Messages:\n");
        printf("  Message Count:     %zu\n", snapshot->adv->count);
        printf("  Total Size:        ");
        if (total_bytes < 1024) {
            printf("%zu bytes\n", total_bytes);
        } else if (total_bytes < 1024 * 1024) {
            printf("%.2f KB\n", total_bytes / 1024.0);
        } else {
            printf("%.2f MB\n", total_bytes / (1024.0 * 1024.0));
        }

        if (snapshot->adv->count > 0) {
            printf("  Avg Message Size:  %.1f bytes\n", (double)total_bytes / snapshot->adv->count);
        }

        if (block->map_time_ms > 0.0) {
            printf("  Map Time:          %.3f ms\n", block->map_time_ms);
        }
        if (block->message_time_ms > 0.0) {
            printf("  Message Time:      %.3f ms\n", block->message_time_ms);
        }

        // Show generation time: elapsed, then the CPU time of the generating thread
        if (block->generation_time_ms < 1.0) {
            printf("  Generation Time:   %.3f ms\n", block->generation_time_ms);
        } else if (block->generation_time_ms < 1000.0) {
            printf("  Generation Time:   %.2f ms\n", block->generation_time_ms);
        } else {
            printf("  Generation Time:   %.3f sec\n", block->generation_time_ms / 1000.0);
        }
        if (block->generation_cpu_ms < 1000.0) {
            printf("  Generation CPU:    %.3f ms\n", block->generation_cpu_ms);
        } else {
            printf("  Generation CPU:    %.3f sec\n", block->generation_cpu_ms / 1000.0);
        }

        bgp_tx_profile_to_string(&snapshot->profile, profile, sizeof(profile));
        printf("  Snapshot:          %" PRIu64 " (%s)\n", snapshot->id, profile);
        // A failed or skipped generation keeps the last snapshot and leaves the block dirty.
        printf("  Status:            %s\n",
               block->dirty ? "stale (configuration changed since this snapshot)" : "current");
    } else {
        printf("\nNo messages generated (run 'update generate')\n");
    }

    // Peers that hold or were refused this ribout
    int peers_header = 0;
    for (int r = 0; r < sim->router_count; r++) {
        const bgp_router_t *router = sim->routers[r];

        for (int n = 0; router->active && n < router->neighbor_count; n++) {
            const bgp_neighbor_t   *neighbor = router->neighbors[n];
            const bgp_tx_binding_t *binding;
            char snapshot[96], state[64];

            if (!neighbor->active || !neighbor->tx) {
                continue;
            }
            binding = bgp_peer_tx_binding(neighbor->tx, name);
            for (size_t w = 0; !binding && w < neighbor->tx->withheld_count; w++) {
                if (strcmp(neighbor->tx->withheld[w].name, name) == 0) {
                    if (!peers_header++) {
                        printf("\nPeers:\n");
                    }
                    printf("  %s (router %u): withheld: %s\n", neighbor->ip, router->local_as,
                           neighbor->tx->withheld[w].reason);
                }
            }
            if (binding) {
                if (!peers_header++) {
                    printf("\nPeers:\n");
                }
                cli_snapshot_text(binding->snapshot, snapshot, sizeof(snapshot));
                cli_binding_state(neighbor->tx, name, state, sizeof(state));
                printf("  %s (router %u): %s, %s\n", neighbor->ip, router->local_as, snapshot, state);
            }
        }
    }

    printf("\n");

    stdout_unlock();
}

typedef struct {
    int index;
    int nlri;
    int rd;
    int label;
    int label2;
    int ethernet_tag;
    int path_id;
    int gateway_ip;
    int esi;
    int next_hop;
    int ll_nh;
    int enlp;
    int priority;
    int preference;
    int binding_sid;
    int segment_lists;
    int actions;
    int local_pref;
    int med;
    int origin;
    int rt;
    int soo;
    int encap;
    int router_mac;
    int color;
    int comm;
    int lcomm;
} cli_ribout_preview_widths_t;

typedef struct {
    char        nlri[256];
    char        rd[64];
    char        gateway_ip[INET6_ADDRSTRLEN];
    char        esi[64];
    char        next_hop[INET6_ADDRSTRLEN];
    char        ll_nh[INET6_ADDRSTRLEN];
    char        binding_sid[INET6_ADDRSTRLEN];
    char        segment_lists[128];
    char        rt[256];
    char        soo[128];
    char        encap[64];
    char        router_mac[64];
    char        color[MAX_EXT_COMMS_PER_ROUTE * 18 + 1];  /* u32 + optional CO bits + separator, for every Color */
    char        comm[512];
    char        lcomm[512];
    char        actions[512];
    char        aspath[MAX_ASPATH_STRING_LEN];
    const char *origin;
} cli_ribout_preview_row_t;

static int cli_max_int(int a, int b) {
    return (a > b) ? a : b;
}

static int cli_decimal_width_u64(uint64_t value) {
    int digits = 1;

    while (value >= 10) {
        value /= 10;
        digits++;
    }

    return digits;
}

static void cli_ribout_preview_render_segment_lists(const bgp_ribout_config_t *block, char *buffer, size_t buffer_len) {
    if (!buffer || buffer_len == 0) {
        return;
    }

    buffer[0] = '\0';
    if (!block) {
        return;
    }

    for (uint32_t i = 0; i < block->segment_list_count; i++) {
        char id_buf[16];

        snprintf(id_buf, sizeof(id_buf), "%u", block->segment_lists[i].id);
        cli_append_formatted_value(buffer, buffer_len, id_buf, ",");
    }
}

/*
 * Render generated path number path_index into the text cells of a preview row (NLRI, next hop, attributes,
 * actions).
 */
static void cli_ribout_preview_render_row(const bgp_gen_path_t *path,
                                          uint64_t path_index,
                                          const bgp_ribout_config_t *block,
                                          cli_ribout_preview_row_t *row) {
    char    addr_str[INET6_ADDRSTRLEN];
    uint8_t kind;

    if (!path || !row) {
        return;
    }

    memset(row, 0, sizeof(*row));
    kind = bgp_ribout_family_info(path->family)->kind;

    if (kind == BGP_RIBOUT_KIND_TEMPLATE && block) {
        bgp_ribout_template_describe(&block->nlri_template, path->template_instance, row->nlri, sizeof(row->nlri));
    } else if (kind == BGP_RIBOUT_KIND_SR_POLICY) {
        if (path->endpoint_af == AF_INET) {
            inet_ntop(AF_INET, &path->endpoint_addr.ipv4, addr_str, sizeof(addr_str));
        } else {
            inet_ntop(AF_INET6, &path->endpoint_addr.ipv6, addr_str, sizeof(addr_str));
        }

        snprintf(row->nlri, sizeof(row->nlri),
                 "<dist=%u,color=%u,endpoint=%s>",
                 path->distinguisher, path->color, addr_str);
        cli_ribout_preview_render_segment_lists(block, row->segment_lists, sizeof(row->segment_lists));
    } else if (path->has_flowspec && block) {
        bgp_ribout_flowspec_nlri_to_string(block, path->flowspec_instance, row->nlri, sizeof(row->nlri));
        bgp_ribout_flowspec_actions_to_string(block, path_index, row->actions, sizeof(row->actions));
    } else if (kind == BGP_RIBOUT_KIND_EVPN_TYPE2) {
        char mac_str[32];

        cli_mac_to_string(path->mac_addr, mac_str, sizeof(mac_str));
        if (path->has_ip) {
            if (path->ip_af == AF_INET) {
                inet_ntop(AF_INET, &path->ip_addr.ipv4, addr_str, sizeof(addr_str));
            } else {
                inet_ntop(AF_INET6, &path->ip_addr.ipv6, addr_str, sizeof(addr_str));
            }
            snprintf(row->nlri, sizeof(row->nlri), "<etag=%u,mac=%s,ip=%s>", path->ethernet_tag_id, mac_str, addr_str);
        } else {
            snprintf(row->nlri, sizeof(row->nlri), "<etag=%u,mac=%s>", path->ethernet_tag_id, mac_str);
        }
    } else {
        if (path->prefix_af == AF_INET) {
            inet_ntop(AF_INET, &path->prefix_addr.ipv4, addr_str, sizeof(addr_str));
        } else {
            inet_ntop(AF_INET6, &path->prefix_addr.ipv6, addr_str, sizeof(addr_str));
        }
        /*
         * Preview renders the generated route identity column as protocol-neutral
         * NLRI text even though the currently supported families still format that
         * identity as an IP prefix here.
         */
        snprintf(row->nlri, sizeof(row->nlri), "%s/%u", addr_str, path->prefix_len);
    }

    if (path->next_hop_af == 0) {
        // FlowSpec: zero-length next hop.
        snprintf(row->next_hop, sizeof(row->next_hop), "-");
    } else if (path->next_hop_af == AF_INET) {
        inet_ntop(AF_INET, &path->next_hop_addr.ipv4, row->next_hop, sizeof(row->next_hop));
    } else {
        inet_ntop(AF_INET6, &path->next_hop_addr.ipv6, row->next_hop, sizeof(row->next_hop));
        if (path->next_hop_has_link_local) {
            inet_ntop(AF_INET6, &path->next_hop_link_local, row->ll_nh, sizeof(row->ll_nh));
        }
    }

    if (path->has_binding_sid) {
        if (path->binding_sid.type == SRPOLICY_BINDING_SID_MPLS) {
            snprintf(row->binding_sid, sizeof(row->binding_sid), "%u", path->binding_sid.mpls_label);
        } else if (path->binding_sid.type == SRPOLICY_BINDING_SID_SRV6) {
            inet_ntop(AF_INET6, path->binding_sid.srv6_sid, row->binding_sid, sizeof(row->binding_sid));
        }
    }

    if (path->has_rd) {
        cli_rd_to_string(&path->rd, row->rd, sizeof(row->rd));
    }

    if (path->has_gateway_ip) {
        if (path->gateway_ip_af == AF_INET) {
            inet_ntop(AF_INET, &path->gateway_ip_addr.ipv4, row->gateway_ip, sizeof(row->gateway_ip));
        } else {
            inet_ntop(AF_INET6, &path->gateway_ip_addr.ipv6, row->gateway_ip, sizeof(row->gateway_ip));
        }
    }

    if (path->has_esi) {
        cli_esi_to_string(&path->esi, row->esi, sizeof(row->esi));
    }

    cli_format_path_ext_comms(path,
                              row->rt, sizeof(row->rt),
                              row->soo, sizeof(row->soo),
                              row->encap, sizeof(row->encap),
                              row->router_mac, sizeof(row->router_mac),
                              row->color, sizeof(row->color));
    row->comm[0] = row->lcomm[0] = '\0';
    for (uint16_t i = 0; i + 4 <= path->community_len; i += 4) {
        const uint8_t *v = path->community_data + i;
        char           value[32];

        cli_community_to_string((uint32_t)v[0] << 24 | (uint32_t)v[1] << 16 | (uint32_t)v[2] << 8 | v[3], value,
                                sizeof(value));
        cli_append_formatted_value(row->comm, sizeof(row->comm), value, ",");
    }
    for (uint16_t i = 0; i + 12 <= path->large_community_len; i += 12) {
        const uint8_t *v = path->large_community_data + i;
        char           value[48];

        snprintf(value, sizeof(value), "%u:%u:%u", (uint32_t)v[0] << 24 | (uint32_t)v[1] << 16 | (uint32_t)v[2] << 8 | v[3],
                 (uint32_t)v[4] << 24 | (uint32_t)v[5] << 16 | (uint32_t)v[6] << 8 | v[7],
                 (uint32_t)v[8] << 24 | (uint32_t)v[9] << 16 | (uint32_t)v[10] << 8 | v[11]);
        cli_append_formatted_value(row->lcomm, sizeof(row->lcomm), value, ",");
    }
    bgp_aspath_to_string(path->aspath_segments, path->aspath_segment_count, row->aspath, sizeof(row->aspath));
    row->origin = bgp_origin_to_string(path->origin);
}

/*
 * Start the preview column widths at the header widths, for count rows of total_paths.
 */
static void cli_ribout_preview_init_widths(cli_ribout_preview_widths_t *widths, uint64_t total_paths, int count) {
    uint64_t preview_rows = 0;

    if (!widths) {
        return;
    }

    memset(widths, 0, sizeof(*widths));

    if (count > 0) {
        preview_rows = (uint64_t)count;
    }
    if (total_paths > 0 && (preview_rows == 0 || total_paths < preview_rows)) {
        preview_rows = total_paths;
    }

    widths->index = cli_max_int(4, cli_decimal_width_u64((preview_rows > 0) ? preview_rows : 1));
    widths->nlri = (int)strlen("nlri");
    widths->rd = (int)strlen("rd");
    widths->label = (int)strlen("label");
    widths->label2 = (int)strlen("label2");
    widths->ethernet_tag = (int)strlen("eth-tag");
    widths->path_id = (int)strlen("path-id");
    widths->gateway_ip = (int)strlen("gateway-ip");
    widths->esi = (int)strlen("esi");
    widths->next_hop = (int)strlen("next-hop");
    widths->ll_nh = (int)strlen("ll-nh");
    widths->enlp = (int)strlen("enlp");
    widths->priority = (int)strlen("prio");
    widths->preference = (int)strlen("pref");
    widths->binding_sid = (int)strlen("bsid");
    widths->segment_lists = (int)strlen("seg-lists");
    widths->actions = (int)strlen("actions");
    widths->local_pref = (int)strlen("lp");
    widths->med = (int)strlen("med");
    widths->origin = (int)strlen("origin");
    widths->rt = (int)strlen("rt");
    widths->soo = (int)strlen("soo");
    widths->encap = (int)strlen("encap");
    widths->router_mac = (int)strlen("router-mac");
    widths->color = (int)strlen("color");
    widths->comm = (int)strlen("comm");
    widths->lcomm = (int)strlen("lcomm");
}

/*
 * Grow the preview column widths to fit one rendered row.
 */
static void cli_ribout_preview_update_widths(cli_ribout_preview_widths_t *widths,
                                             const cli_ribout_preview_row_t *row,
                                             const bgp_gen_path_t *path,
                                             int show_rd,
                                             int show_label,
                                             int show_label2,
                                             int show_ethernet_tag,
                                             int show_pathid,
                                             int show_gateway_ip,
                                             int show_esi,
                                             int show_ll_nh,
                                             int show_preference,
                                             int show_binding_sid,
                                             int show_segment_lists,
                                             int show_actions,
                                             int show_med,
                                             int show_rt,
                                             int show_soo,
                                             int show_encap,
                                             int show_router_mac,
                                             int show_color,
                                             int show_comm,
                                             int show_lcomm) {
    if (!widths || !row || !path) {
        return;
    }
    if (show_comm) {
        widths->comm = cli_max_int(widths->comm, row->comm[0] ? (int)strlen(row->comm) : 1);
    }
    if (show_lcomm) {
        widths->lcomm = cli_max_int(widths->lcomm, row->lcomm[0] ? (int)strlen(row->lcomm) : 1);
    }

    widths->nlri = cli_max_int(widths->nlri, (int)strlen(row->nlri));
    if (show_rd) {
        widths->rd = cli_max_int(widths->rd, path->has_rd ? (int)strlen(row->rd) : 1);
    }
    if (show_label) {
        widths->label = cli_max_int(widths->label, cli_decimal_width_u64(path->label));
    }
    if (show_label2) {
        widths->label2 = cli_max_int(widths->label2, path->has_label2 ? cli_decimal_width_u64(path->label2) : 1);
    }
    if (show_ethernet_tag) {
        widths->ethernet_tag = cli_max_int(widths->ethernet_tag, cli_decimal_width_u64(path->ethernet_tag_id));
    }
    if (show_pathid) {
        widths->path_id = cli_max_int(widths->path_id, cli_decimal_width_u64(path->path_id));
    }
    if (show_gateway_ip) {
        widths->gateway_ip = cli_max_int(widths->gateway_ip, path->has_gateway_ip ? (int)strlen(row->gateway_ip) : 1);
    }
    if (show_esi) {
        widths->esi = cli_max_int(widths->esi, path->has_esi ? (int)strlen(row->esi) : 1);
    }
    widths->next_hop = cli_max_int(widths->next_hop, (int)strlen(row->next_hop));
    if (show_ll_nh) {
        widths->ll_nh = cli_max_int(widths->ll_nh, path->next_hop_has_link_local ? (int)strlen(row->ll_nh) : 1);
    }
    if (show_preference) {
        widths->enlp = cli_max_int(widths->enlp, path->has_enlp ? cli_decimal_width_u64(path->enlp) : 1);
        widths->priority = cli_max_int(widths->priority,
                                       path->has_priority ?
                                       cli_decimal_width_u64(path->priority) : 1);
    }
    if (show_preference) {
        widths->preference = cli_max_int(widths->preference, cli_decimal_width_u64(path->preference));
    }
    if (show_binding_sid) {
        widths->binding_sid = cli_max_int(widths->binding_sid,
                                          path->has_binding_sid ?
                                          (int)strlen(row->binding_sid) : 1);
    }
    if (show_actions) {
        widths->actions = cli_max_int(widths->actions, row->actions[0] ? (int)strlen(row->actions) : 1);
    }
    if (show_segment_lists) {
        widths->segment_lists = cli_max_int(widths->segment_lists,
                                            row->segment_lists[0] ?
                                            (int)strlen(row->segment_lists) : 1);
    }
    widths->local_pref = cli_max_int(widths->local_pref, cli_decimal_width_u64(path->local_pref));
    if (show_med) {
        widths->med = cli_max_int(widths->med, path->has_med ? cli_decimal_width_u64(path->med) : 1);
    }
    widths->origin = cli_max_int(widths->origin, (int)strlen(row->origin));
    if (show_rt) {
        widths->rt = cli_max_int(widths->rt, row->rt[0] ? (int)strlen(row->rt) : 1);
    }
    if (show_soo) {
        widths->soo = cli_max_int(widths->soo, row->soo[0] ? (int)strlen(row->soo) : 1);
    }
    if (show_encap) {
        widths->encap = cli_max_int(widths->encap, row->encap[0] ? (int)strlen(row->encap) : 1);
    }
    if (show_color) {
        widths->color = cli_max_int(widths->color, row->color[0] ? (int)strlen(row->color) : 1);
    }
    if (show_router_mac) {
        widths->router_mac = cli_max_int(widths->router_mac, row->router_mac[0] ? (int)strlen(row->router_mac) : 1);
    }
}

static void cli_print_dashes(int width) {
    for (int i = 0; i < width; i++) {
        putchar('-');
    }
}

/*
 * Preview generated paths from a ribout block
 */
void cli_show_ribout_preview(bgp_sim_t *sim, const char *name, int count) {
    stdout_lock();

    bgp_ribout_config_t *block = bgp_sim_find_ribout(sim, name);

    if (!block) {
        printf("\nribout '%s' not found.\n\n", name);
        stdout_unlock();
        return;
    }

    // Initialize generator
    bgp_ribout_gen_t gen;
    if (bgp_ribout_generator_init(&gen, block) < 0) {
        printf("\nFailed to initialize generator for '%s'.\n\n", name);
        stdout_unlock();
        return;
    }

    bgp_ribout_family_t         family = bgp_ribout_resolve_family(block);
    cli_ribout_preview_widths_t widths;

    printf("\nribout preview: %s (showing first %d paths)\n", block->name, count);
    printf("===============================================\n");
    printf("family: %s\n\n", bgp_ribout_family_info(family)->name);

    // Determine which optional columns to show
    int                             show_rd = (block->rd_count > 0);
    int                             show_label  = (block->label_count > 0);
    int                             show_label2 = (block->label2_count > 0);
    const bgp_ribout_family_info_t *info = bgp_ribout_family_info(family);
    // EVPN Type 5 is the prefix kind with AFI 25.
    int                             evpn_type5 = (info->kind == BGP_RIBOUT_KIND_PREFIX && info->afi == AFI_L2VPN);
    int show_ethernet_tag = (info->kind != BGP_RIBOUT_KIND_EVPN_TYPE2) &&
        ((block->ethernet_tag_count > 0) || evpn_type5);
    int show_pathid = (block->path_id_count > 0);
    int show_gateway_ip = (block->gateway_ip_spec.count > 0);
    int show_esi = (block->esi_count > 0);
    int show_preference = (info->kind == BGP_RIBOUT_KIND_SR_POLICY);
    int show_binding_sid = show_preference;
    int show_segment_lists = show_preference;
    int show_actions = bgp_ribout_family_is_flowspec(family);
    int show_med = block->med_spec.enabled;
    int show_rt = (block->rt_count > 0 || block->rt_set_count > 0);
    int show_soo = (block->soo_count > 0);
    int show_encap = (block->encap_count > 0);
    int show_router_mac = (block->router_mac_count > 0);
    int show_color = (block->color_count > 0 && info->kind != BGP_RIBOUT_KIND_SR_POLICY);
    int show_comm = (block->community_group_count > 0);
    int show_lcomm = (block->large_community_group_count > 0);
    int show_ll_nh = (block->next_hop_spec.af == AF_INET6 && block->next_hop_spec.has_link_local);

    /*
     * Two-pass render: first measure the preview rows we will actually show,
     * then re-run the generator and print with those measured widths.
     */
    cli_ribout_preview_init_widths(&widths, gen.total_paths, count);

    int paths_measured = 0;
    while (bgp_ribout_generator_has_next(&gen) && paths_measured < count) {
        bgp_gen_path_t path;

        if (bgp_ribout_generator_next(&gen, &path) != 0) {
            continue;
        }

        cli_ribout_preview_row_t row;
        cli_ribout_preview_render_row(&path, gen.paths_generated - 1, block, &row);
        cli_ribout_preview_update_widths(&widths, &row, &path,
                                         show_rd, show_label, show_label2,
                                         show_ethernet_tag,
                                         show_pathid, show_gateway_ip, show_esi,
                                         show_ll_nh, show_preference,
                                         show_binding_sid, show_segment_lists,
                                         show_actions,
                                         show_med, show_rt, show_soo,
                                         show_encap, show_router_mac, show_color, show_comm, show_lcomm);
        paths_measured++;
    }

    // Rewind the generator for the second pass, which emits the formatted table.
    if (bgp_ribout_generator_init(&gen, block) < 0) {
        printf("Failed to reinitialize generator for '%s'.\n\n", name);
        stdout_unlock();
        return;
    }

    // Print table header
    printf("%-*s  %-*s", widths.index, "#", widths.nlri, "nlri");
    if (show_rd)     printf("  %-*s", widths.rd, "rd");
    if (show_label)  printf("  %-*s", widths.label, "label");
    if (show_label2) printf("  %-*s", widths.label2, "label2");
    if (show_ethernet_tag) printf("  %-*s", widths.ethernet_tag, "eth-tag");
    if (show_pathid) printf("  %-*s", widths.path_id, "path-id");
    if (show_gateway_ip) printf("  %-*s", widths.gateway_ip, "gateway-ip");
    if (show_esi)    printf("  %-*s", widths.esi, "esi");
    printf("  %-*s", widths.next_hop, "next-hop");
    if (show_ll_nh)  printf("  %-*s", widths.ll_nh, "ll-nh");
    if (show_preference) printf("  %-*s", widths.enlp, "enlp");
    if (show_preference) printf("  %-*s", widths.priority, "prio");
    if (show_preference) printf("  %-*s", widths.preference, "pref");
    if (show_binding_sid) printf("  %-*s", widths.binding_sid, "bsid");
    if (show_segment_lists) printf("  %-*s", widths.segment_lists, "seg-lists");
    if (show_actions) printf("  %-*s", widths.actions, "actions");
    printf("  %-*s", widths.local_pref, "lp");
    if (show_med)    printf("  %-*s", widths.med, "med");
    printf("  %-*s", widths.origin, "origin");
    if (show_rt)     printf("  %-*s", widths.rt, "rt");
    if (show_soo)    printf("  %-*s", widths.soo, "soo");
    if (show_encap)  printf("  %-*s", widths.encap, "encap");
    if (show_router_mac) printf("  %-*s", widths.router_mac, "router-mac");
    if (show_color)  printf("  %-*s", widths.color, "color");
    if (show_comm)   printf("  %-*s", widths.comm, "comm");
    if (show_lcomm)  printf("  %-*s", widths.lcomm, "lcomm");
    printf("  %s\n", "as-path");

    cli_print_dashes(widths.index);
    printf("  ");
    cli_print_dashes(widths.nlri);
    if (show_rd) {
        printf("  ");
        cli_print_dashes(widths.rd);
    }
    if (show_label) {
        printf("  ");
        cli_print_dashes(widths.label);
    }
    if (show_label2) {
        printf("  ");
        cli_print_dashes(widths.label2);
    }
    if (show_ethernet_tag) {
        printf("  ");
        cli_print_dashes(widths.ethernet_tag);
    }
    if (show_pathid) {
        printf("  ");
        cli_print_dashes(widths.path_id);
    }
    if (show_gateway_ip) {
        printf("  ");
        cli_print_dashes(widths.gateway_ip);
    }
    if (show_esi) {
        printf("  ");
        cli_print_dashes(widths.esi);
    }
    printf("  ");
    cli_print_dashes(widths.next_hop);
    if (show_ll_nh) {
        printf("  ");
        cli_print_dashes(widths.ll_nh);
    }
    if (show_preference) {
        printf("  ");
        cli_print_dashes(widths.enlp);
    }
    if (show_preference) {
        printf("  ");
        cli_print_dashes(widths.priority);
    }
    if (show_preference) {
        printf("  ");
        cli_print_dashes(widths.preference);
    }
    if (show_binding_sid) {
        printf("  ");
        cli_print_dashes(widths.binding_sid);
    }
    if (show_segment_lists) {
        printf("  ");
        cli_print_dashes(widths.segment_lists);
    }
    if (show_actions) {
        printf("  ");
        cli_print_dashes(widths.actions);
    }
    printf("  ");
    cli_print_dashes(widths.local_pref);
    if (show_med) {
        printf("  ");
        cli_print_dashes(widths.med);
    }
    printf("  ");
    cli_print_dashes(widths.origin);
    if (show_rt) {
        printf("  ");
        cli_print_dashes(widths.rt);
    }
    if (show_soo) {
        printf("  ");
        cli_print_dashes(widths.soo);
    }
    if (show_encap) {
        printf("  ");
        cli_print_dashes(widths.encap);
    }
    if (show_router_mac) {
        printf("  ");
        cli_print_dashes(widths.router_mac);
    }
    if (show_color) {
        printf("  ");
        cli_print_dashes(widths.color);
    }
    if (show_comm) {
        printf("  ");
        cli_print_dashes(widths.comm);
    }
    if (show_lcomm) {
        printf("  ");
        cli_print_dashes(widths.lcomm);
    }
    printf("  -------\n");

    int paths_shown = 0;
    while (bgp_ribout_generator_has_next(&gen) && paths_shown < count) {
        bgp_gen_path_t path;
        if (bgp_ribout_generator_next(&gen, &path) == 0) {
            cli_ribout_preview_row_t row;
            cli_ribout_preview_render_row(&path, gen.paths_generated - 1, block, &row);

            // Print row with optional columns
            printf("%-*d  %-*s", widths.index, paths_shown + 1, widths.nlri, row.nlri);
            if (show_rd)     printf("  %-*s", widths.rd, path.has_rd ? row.rd : "-");
            if (show_label)  printf("  %-*u", widths.label, path.label);
            if (show_label2) {
                if (path.has_label2) {
                    printf("  %-*u", widths.label2, path.label2);
                } else {
                    printf("  %-*s", widths.label2, "-");
                }
            }
            if (show_ethernet_tag) {
                printf("  %-*u", widths.ethernet_tag, path.ethernet_tag_id);
            }
            if (show_pathid) printf("  %-*u", widths.path_id, path.path_id);
            if (show_gateway_ip) {
                printf("  %-*s", widths.gateway_ip, path.has_gateway_ip ? row.gateway_ip : "-");
            }
            if (show_esi) {
                printf("  %-*s", widths.esi, path.has_esi ? row.esi : "-");
            }
            printf("  %-*s", widths.next_hop, row.next_hop);
            if (show_ll_nh) {
                printf("  %-*s", widths.ll_nh, path.next_hop_has_link_local ? row.ll_nh : "-");
            }
            if (show_preference) {
                if (path.has_enlp) {
                    printf("  %-*u", widths.enlp, path.enlp);
                } else {
                    printf("  %-*s", widths.enlp, "-");
                }
            }
            if (show_preference) {
                if (path.has_priority) {
                    printf("  %-*u", widths.priority, path.priority);
                } else {
                    printf("  %-*s", widths.priority, "-");
                }
            }
            if (show_preference) {
                printf("  %-*u", widths.preference, path.preference);
            }
            if (show_binding_sid) {
                if (path.has_binding_sid) {
                    printf("  %-*s", widths.binding_sid, row.binding_sid);
                } else {
                    printf("  %-*s", widths.binding_sid, "-");
                }
            }
            if (show_segment_lists) {
                printf("  %-*s", widths.segment_lists, row.segment_lists[0] ? row.segment_lists : "-");
            }
            if (show_actions) {
                printf("  %-*s", widths.actions, row.actions[0] ? row.actions : "-");
            }
            printf("  %-*u", widths.local_pref, path.local_pref);
            if (show_med) {
                if (path.has_med) {
                    printf("  %-*u", widths.med, path.med);
                } else {
                    printf("  %-*s", widths.med, "-");
                }
            }
            printf("  %-*s", widths.origin, row.origin);
            if (show_rt) {
                printf("  %-*s", widths.rt, row.rt[0] ? row.rt : "-");
            }
            if (show_soo) {
                printf("  %-*s", widths.soo, row.soo[0] ? row.soo : "-");
            }
            if (show_encap) {
                printf("  %-*s", widths.encap, row.encap[0] ? row.encap : "-");
            }
            if (show_router_mac) {
                printf("  %-*s", widths.router_mac, row.router_mac[0] ? row.router_mac : "-");
            }
            if (show_color) {
                printf("  %-*s", widths.color, row.color[0] ? row.color : "-");
            }
            if (show_comm) {
                printf("  %-*s", widths.comm, row.comm[0] ? row.comm : "-");
            }
            if (show_lcomm) {
                printf("  %-*s", widths.lcomm, row.lcomm[0] ? row.lcomm : "-");
            }
            printf("  %s\n", row.aspath);
            paths_shown++;
        }
    }

    printf("\ntotal paths in block: %"PRIu64"\n\n", gen.total_paths);

    stdout_unlock();
}

/*
 * Show all ribout maps
 */
void cli_show_ribout_map_summary(bgp_sim_t *sim) {
    stdout_lock();

    printf("\nribout maps summary\n");
    printf("===============================================\n\n");

    if (sim->ribout_count == 0) {
        printf("No ribouts configured.\n\n");
    } else {
        for (int i = 0; i < sim->ribout_count; i++) {
            bgp_ribout_config_t *block = sim->ribouts[i];
            printf("ribout: %s\n", block->name);

            if (block->ribout) {
                size_t entries, nlris, buckets;
                bgp_ribout_map_get_stats(block->ribout, &entries, &nlris, &buckets);
                printf("  Path Attribute Entries: %zu\n", entries);
                printf("  Total NLRIs: %zu\n", nlris);
                printf("  Memory Usage: %zu bytes\n", bgp_ribout_map_get_memory_usage(block->ribout));
            } else {
                printf("  (no ribout map generated)\n");
            }
            printf("\n");
        }
    }

    stdout_unlock();
}

/*
 * Show ribout map detail for specific ribout config
 */
void cli_show_ribout_map_detail(bgp_sim_t *sim, const char *ribout_name) {
    stdout_lock();

    bgp_ribout_config_t *config = bgp_sim_find_ribout(sim, ribout_name);

    if (!config) {
        printf("\nError: ribout '%s' not found\n\n", ribout_name);
    } else if (!config->ribout) {
        printf("\nribout '%s' has no generated map.\n", ribout_name);
        printf("Map will be generated automatically when ribout config is complete.\n\n");
    } else {
        printf("\nribout map detail for '%s'\n", ribout_name);
        printf("===============================================\n\n");
        bgp_ribout_map_print(config->ribout);
    }

    stdout_unlock();
}

void cli_session_init(cli_session_t *session) {
    if (!session) {
        return;
    }

    memset(session, 0, sizeof(*session));
    session->config_mode = CONFIG_MODE_GLOBAL;
}

void cli_session_reset_exec_context(cli_session_t *session) {
    int terminal_monitor;

    if (!session) {
        return;
    }

    terminal_monitor = session->terminal_monitor;
    cli_session_init(session);
    session->terminal_monitor = terminal_monitor;
}

static bgp_router_t *cli_session_resolve_router(bgp_sim_t *sim, const cli_session_t *session) {
    if (!sim || !session || !session->has_router) {
        return NULL;
    }

    return bgp_find_router(sim, session->current_router_as);
}

static bgp_neighbor_t *cli_session_resolve_neighbor(bgp_router_t *router, const cli_session_t *session) {
    if (!router || !session || !session->has_neighbor) {
        return NULL;
    }

    return bgp_find_neighbor(router, session->current_neighbor_ip);
}

static bgp_ribout_config_t *cli_session_resolve_ribout(bgp_sim_t *sim, const cli_session_t *session) {
    if (!sim || !session || !session->has_ribout) {
        return NULL;
    }

    return bgp_sim_find_ribout(sim, session->current_ribout_name);
}

static void cli_session_store_router(cli_session_t *session, const bgp_router_t *router) {
    if (!session) {
        return;
    }

    if (!router) {
        session->has_router = 0;
        session->current_router_as = 0;
        session->has_neighbor = 0;
        session->current_neighbor_ip[0] = '\0';
        return;
    }

    session->has_router = 1;
    session->current_router_as = router->local_as;
}

static void cli_session_store_neighbor(cli_session_t *session, const bgp_neighbor_t *neighbor) {
    if (!session) {
        return;
    }

    if (!neighbor) {
        session->has_neighbor = 0;
        session->current_neighbor_ip[0] = '\0';
        return;
    }

    session->has_neighbor = 1;
    strncpy(session->current_neighbor_ip, neighbor->ip, sizeof(session->current_neighbor_ip) - 1);
    session->current_neighbor_ip[sizeof(session->current_neighbor_ip) - 1] = '\0';
}

static void cli_session_store_ribout(cli_session_t *session, const bgp_ribout_config_t *ribout) {
    if (!session) {
        return;
    }

    if (!ribout) {
        session->has_ribout = 0;
        session->current_ribout_name[0] = '\0';
        return;
    }

    session->has_ribout = 1;
    strncpy(session->current_ribout_name, ribout->name, sizeof(session->current_ribout_name) - 1);
    session->current_ribout_name[sizeof(session->current_ribout_name) - 1] = '\0';
}

/*
 * Copy the mode, the object names and the mode stack of a finished command back into the session.
 */
static void cli_session_store_command_state(cli_session_t *session, const cmd_ctx_t *cmd_ctx) {
    if (!session || !cmd_ctx) {
        return;
    }

    session->config_mode = cmd_ctx->config_mode;
    cli_session_store_router(session, cmd_ctx->current_router);
    cli_session_store_neighbor(session, cmd_ctx->current_neighbor);
    cli_session_store_ribout(session, cmd_ctx->current_ribout);
    memcpy(session->current_script_name, cmd_ctx->current_script_name, sizeof(session->current_script_name));

    session->mode_stack_depth = cmd_ctx->mode_stack_depth;
    for (int i = 0; i < session->mode_stack_depth; i++) {
        session->mode_stack[i] = cmd_ctx->mode_stack[i];
    }
}

/*
 * Build the prompt for a mode and session, for example "bgpsim(config-ribout-fs-rule-web)#", with ANSI colors when
 * use_color is set.
 */
void cli_build_prompt(cli_mode_t mode, const cli_session_t *session, char *prompt, size_t prompt_size, int use_color) {
    config_mode_t cfg_mode = CONFIG_MODE_GLOBAL;
    uint32_t      router_as = 0;
    const char   *neighbor_ip = NULL;
    const char   *ribout_name = NULL;

    // Color pointers — empty strings when color is off
    const char *c_name  = use_color ? CLR_BLUE           : "";
    const char *c_sub   = use_color ? CLR_YELLOW         : "";
    const char *c_delim = use_color ? CLR_YELLOW         : "";
    const char *c_reset = use_color ? CLR_RESET          : "";

    if (prompt_size == 0) {
        return;
    }

    if (mode == CLI_MODE_EXEC) {
        snprintf(prompt, prompt_size, "%s" BGPSIM ">%s ", c_name, c_reset);
        return;
    }

    if (session) {
        cfg_mode = session->config_mode;
        if (session->has_router) {
            router_as = session->current_router_as;
        }
        if (session->has_neighbor) {
            neighbor_ip = session->current_neighbor_ip;
        }
        if (session->has_ribout) {
            ribout_name = session->current_ribout_name;
        }
    }

    // Helper macro: name(submode)# with color wrapping
    #define CONFIG_PROMPT(sub)                        \
        snprintf(prompt, prompt_size,                 \
                 "%s" BGPSIM "%s%s(" sub ")%s%s#%s ", \
                 c_name, c_reset, c_sub, c_reset, c_delim, c_reset)

    switch (cfg_mode) {
        case CONFIG_MODE_GLOBAL:
            CONFIG_PROMPT("config");
            break;
        case CONFIG_MODE_ROUTER_BGP:
            if (router_as != 0) {
                snprintf(prompt, prompt_size,
                         "%s" BGPSIM "%s%s(config-router-bgp-%u)%s%s#%s ",
                         c_name, c_reset, c_sub, router_as, c_reset,
                         c_delim, c_reset);
            } else {
                CONFIG_PROMPT("config-router");
            }
            break;
        case CONFIG_MODE_NEIGHBOR:
            if (router_as != 0 && neighbor_ip) {
                snprintf(prompt, prompt_size,
                         "%s" BGPSIM "%s%s(config-router-bgp-%u-neighbor-%s)%s%s#%s ",
                         c_name, c_reset, c_sub, router_as, neighbor_ip,
                         c_reset, c_delim, c_reset);
            } else if (router_as != 0) {
                snprintf(prompt, prompt_size,
                         "%s" BGPSIM "%s%s(config-router-bgp-%u-neighbor)%s%s#%s ",
                         c_name, c_reset, c_sub, router_as, c_reset,
                         c_delim, c_reset);
            } else {
                CONFIG_PROMPT("config-neighbor");
            }
            break;
        case CONFIG_MODE_RIBOUT:
            if (ribout_name) {
                snprintf(prompt, prompt_size,
                         "%s" BGPSIM "%s%s(config-ribout-%s)%s%s#%s ",
                         c_name, c_reset, c_sub, ribout_name, c_reset,
                         c_delim, c_reset);
            } else {
                CONFIG_PROMPT("config-ribout");
            }
            break;
        case CONFIG_MODE_SCRIPT:
            snprintf(prompt, prompt_size,
                     "%s" BGPSIM "%s%s(config-script-%s)%s%s#%s ",
                     c_name, c_reset, c_sub, session ? session->current_script_name : "",
                     c_reset, c_delim, c_reset);
            break;
        default:
            CONFIG_PROMPT("config");
            break;
    }

    #undef CONFIG_PROMPT
}

static void cli_show_command_table_help(cmd_def_t *commands, int command_count) {
    parser_ctx_t parser;

    parser_init(&parser, commands, command_count, NULL);
    parser_show_help_with_output(&parser, output_current());
}

static void cli_show_help(cli_mode_t mode, const cli_session_t *session) {
    stdout_lock();

    if (mode == CLI_MODE_EXEC) {
        cli_show_command_table_help(cli_exec_commands, cli_exec_commands_count);
    } else {
        /*
         * 'help' in config mode is intentionally a compact current-mode
         * reference. Reachability and cross-mode discovery belong to bare '?'.
         */
        config_mode_t cfg_mode = session ? session->config_mode : CONFIG_MODE_GLOBAL;
        cli_show_command_table_help(config_tables[cfg_mode].commands, config_tables[cfg_mode].count);
    }

    stdout_unlock();
}

static void cli_report_parse_error(const char *cmd, int is_no_command, int result) {
    switch (result) {
        case PARSER_NO_MATCH:
            fprintf(stderr, "Unknown Command: %s\n", cmd);
            break;
        case PARSER_INCOMPLETE:
            fprintf(stderr, "Incomplete Command: %s\n", cmd);
            break;
        case PARSER_AMBIGUOUS:
            fprintf(stderr, "Ambiguous Command: %s\n", cmd);
            break;
        case PARSER_UNSUPPORTED_NEGATION:
            if (is_no_command) {
                fprintf(stderr, "'no %s' is not supported\n", cmd);
            }
            break;
        default:
            break;
    }
}

static int cli_split_help_query(char *cmd, const char **completion_input) {
    size_t len;

    if (!cmd || !completion_input) {
        return 0;
    }

    len = strlen(cmd);
    if (len == 0 || cmd[len - 1] != '?') {
        return 0;
    }

    cmd[len - 1] = '\0';
    *completion_input = cmd;
    return 1;
}

/*
 * Process a CLI command using explicit caller-owned mode/session state.
 */
int cli_process_command_with_output(cli_session_t *session, bgp_sim_t *sim,
                                    cli_mode_t *mode, const char *line,
                                    const output_t *output) {
    char                 buf[MAX_LINE_LENGTH];
    bgp_router_t        *router = NULL;
    bgp_neighbor_t      *neighbor = NULL;
    bgp_ribout_config_t *ribout = NULL;
    const output_t      *previous_output = output_push(output);
    int                  final_result = 0;

    if (!sim || !line || !mode || !session) {
        output_pop(previous_output);
        return -1;
    }

    if (!command_input_valid(line, strlen(line))) {
        fprintf(stderr, "Error: command is too long (maximum %d bytes)\n", BGPSIM_COMMAND_SIZE - 1);
        output_pop(previous_output);
        return -1;
    }
    memcpy(buf, line, strlen(line) + 1);

    char *cmd = str_trim(buf);

    // Empty command
    if (cmd[0] == '\0') {
        output_pop(previous_output);
        return 0;
    }

    /*
     * Keep 'help' and full-line '?' distinct:
     * - help: explicit reference view
     * - ?: flat discoverability view shared with interactive completion
     */
    if (strcmp(cmd, "help") == 0) {
        cli_show_help(*mode, session);
        output_pop(previous_output);
        return 0;
    }

    const char *completion_input = NULL;
    if (cli_split_help_query(cmd, &completion_input)) {
        completion_show_help_with_output(*mode, session ? session->config_mode : CONFIG_MODE_GLOBAL,
                                         completion_input, output_current());
        output_pop(previous_output);
        return 0;
    }

    // EXEC mode never carries hierarchical config context.
    if (*mode == CLI_MODE_EXEC) {
        cli_session_reset_exec_context(session);
    }

    router = cli_session_resolve_router(sim, session);
    neighbor = cli_session_resolve_neighbor(router, session);
    ribout = cli_session_resolve_ribout(sim, session);

    // Set up context for handlers from this session's state.
    cmd_ctx_t cmd_ctx = {
        .sim = sim,
        .mode = mode,
        .session = session,
        .config_mode = session->config_mode,
        .is_no_command = 0,
        .raw_line = cmd,
        .current_ribout = ribout,
        .current_router = router,
        .current_neighbor = neighbor,
        .mode_stack_depth = session->mode_stack_depth
    };
    memcpy(cmd_ctx.current_script_name, session->current_script_name, sizeof(cmd_ctx.current_script_name));
    for (int i = 0; i < session->mode_stack_depth; i++) {
        cmd_ctx.mode_stack[i] = session->mode_stack[i];
    }

    parser_ctx_t parser;
    int          result = -1;

    // Exec mode commands
    if (*mode == CLI_MODE_EXEC) {
        parser_init(&parser, cli_exec_commands, cli_exec_commands_count, &cmd_ctx);
        result = parser_execute(&parser, cmd);
        cli_report_parse_error(cmd, 0, result);
        final_result = result;
    }
    // Config mode commands
    else if (*mode == CLI_MODE_CONFIG) {
        // Check for "no" prefix
        if (strncmp(cmd, "no ", 3) == 0) {
            cmd_ctx.is_no_command = 1;
            cmd += 3;
            while (isspace(*cmd)) cmd++;
            cmd_ctx.raw_line = cmd;
        }

        // Execute command with mode stack unwinding and exec fallback
        cmd_exec_options_t opts;
        command_init_exec_options(&opts);

        result = command_execute(cmd, &cmd_ctx, &opts);
        cli_report_parse_error(cmd, cmd_ctx.is_no_command, result);
        final_result = result;

        // Persist updated state back to the caller's session.
        cli_session_store_command_state(session, &cmd_ctx);

        if (*mode == CLI_MODE_EXEC) {
            cli_session_reset_exec_context(session);
        }

        // Update tab completion config mode
        tab_completion_set_config_mode(cmd_ctx.config_mode);
    }

    output_pop(previous_output);
    return final_result;
}

int cli_process_command(cli_session_t *session, bgp_sim_t *sim, cli_mode_t *mode, const char *line) {
    return cli_process_command_with_output(session, sim, mode, line, NULL);
}
