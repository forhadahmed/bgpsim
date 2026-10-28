#define OUTPUT_STDIO_REMAP

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "output.h"
#include "bgp_ribout_config.h"

typedef struct {
    const char *keyword;
    int (*parse)(bgp_ribout_config_t *block, const char *line);
    void (*clear)(bgp_ribout_config_t *block);
} ribout_edit_spec_t;

/*
 * Clear functions for each ribout attribute
 */
static void ribout_clear_prefix(bgp_ribout_config_t *r) {
    memset(&r->prefix_spec, 0, sizeof(r->prefix_spec));
    r->prefix_offset = 0;
}
static void ribout_clear_rd(bgp_ribout_config_t *r) {
    r->rd_count = 0;
    r->rd_rotate = 0;
    free(r->rds);
    r->rds = NULL;
    r->rds_capacity = 0;
    r->rds_step = 0;
}
static void ribout_clear_rotate_every(bgp_ribout_config_t *r) {
    r->rotate_every = 0;
}
static void ribout_clear_rotate_period(bgp_ribout_config_t *r) {
    r->rotate_period = 0;
}
static void ribout_clear_label(bgp_ribout_config_t *r) {
    r->label_count = 0;
    r->label_rotate = 0;
    free(r->labels);
    r->labels = NULL;
    r->labels_capacity = 0;
    r->labels_step = 0;
}
static void ribout_clear_label2(bgp_ribout_config_t *r) {
    r->label2_count = 0;
    free(r->label2s);
    r->label2s = NULL;
    r->label2s_capacity = 0;
    r->label2s_step = 0;
}
static void ribout_clear_ethernet_tag(bgp_ribout_config_t *r) {
    r->ethernet_tag_count = 0;
    r->ethernet_tag_rotate = 0;
    free(r->ethernet_tags);
    r->ethernet_tags = NULL;
    r->ethernet_tags_capacity = 0;
    r->ethernet_tags_step = 0;
}
static void ribout_clear_mac(bgp_ribout_config_t *r) {
    memset(&r->mac_spec, 0, sizeof(r->mac_spec));
}
static void ribout_clear_ip(bgp_ribout_config_t *r) {
    memset(&r->ip_spec, 0, sizeof(r->ip_spec));
    memset(&r->ip2_spec, 0, sizeof(r->ip2_spec));
    r->ip_rotate = 0;
    r->ip2_rotate = 0;
}
static void ribout_clear_path_id(bgp_ribout_config_t *r) {
    r->path_id_count = 0;
    r->path_id_rotate = 0;
    free(r->path_ids);
    r->path_ids = NULL;
    r->path_ids_capacity = 0;
    r->path_ids_step = 0;
}
static void ribout_clear_next_hop(bgp_ribout_config_t *r) {
    memset(&r->next_hop_spec, 0, sizeof(r->next_hop_spec));
}
static void ribout_clear_gateway_ip(bgp_ribout_config_t *r) {
    memset(&r->gateway_ip_spec, 0, sizeof(r->gateway_ip_spec));
}
static void ribout_clear_esi(bgp_ribout_config_t *r) {
    r->esi_count = 0;
    memset(r->esis, 0, sizeof(r->esis));
}
static void ribout_clear_aspath(bgp_ribout_config_t *r) {
    r->aspath_segment_count = 0;
    free(r->aspath_segments);
    r->aspath_segments = NULL;
    r->aspath_segments_capacity = 0;
}
static void ribout_clear_localpref(bgp_ribout_config_t *r) {
    r->localpref_spec.mode = BGP_U32_MODE_FIXED;
    r->localpref_spec.value = 100;
    r->localpref_spec.range_start = 0;
    r->localpref_spec.range_end = 0;
}
static void ribout_clear_med(bgp_ribout_config_t *r) {
    r->med_spec.enabled = 0;
    r->med_spec.mode = BGP_U32_MODE_FIXED;
    r->med_spec.value = 0;
    r->med_spec.range_start = 0;
    r->med_spec.range_end = 0;
}
static void ribout_clear_rt(bgp_ribout_config_t *r) {
    r->rt_count = 0;
    memset(r->rt_values, 0, sizeof(r->rt_values));
}
static void ribout_clear_community(bgp_ribout_config_t *r) {
    r->community_group_count = 0;
    free(r->community_groups);
    r->community_groups = NULL;
    r->community_groups_capacity = 0;
}
static void ribout_clear_large_community(bgp_ribout_config_t *r) {
    r->large_community_group_count = 0;
    free(r->large_community_groups);
    r->large_community_groups = NULL;
    r->large_community_groups_capacity = 0;
}
static void ribout_clear_rt_set(bgp_ribout_config_t *r) {
    r->rt_set_count = 0;
    r->rt_set_group_count = 0;
    free(r->rt_sets);
    r->rt_sets = NULL;
    r->rt_sets_capacity = 0;
}
static void ribout_clear_soo(bgp_ribout_config_t *r) {
    r->soo_count = 0;
    memset(r->soo_values, 0, sizeof(r->soo_values));
}
static void ribout_clear_encap(bgp_ribout_config_t *r) {
    r->encap_count = 0;
    memset(r->encap_values, 0, sizeof(r->encap_values));
}
static void ribout_clear_router_mac(bgp_ribout_config_t *r) {
    r->router_mac_count = 0;
    memset(r->router_mac_values, 0, sizeof(r->router_mac_values));
}
static void ribout_clear_origin(bgp_ribout_config_t *r) {
    r->origin = ORIGIN_IGP;
}
static void ribout_clear_distinguisher(bgp_ribout_config_t *r) {
    r->distinguisher_count = 0;
    r->distinguisher_rotate = 0;
    free(r->distinguishers);
    r->distinguishers = NULL;
    r->distinguishers_capacity = 0;
    r->distinguishers_step = 0;
}
static void ribout_clear_color(bgp_ribout_config_t *r) {
    r->color_count = 0;
    r->color_rotate = 0;
    r->color_set = 0;
    free(r->colors);
    r->colors = NULL;
    r->colors_capacity = 0;
    r->colors_step = 0;
    free(r->color_co);
    r->color_co = NULL;
    r->color_co_capacity = 0;
}
static void ribout_clear_endpoint(bgp_ribout_config_t *r) {
    memset(&r->endpoint_spec, 0, sizeof(r->endpoint_spec));
    r->endpoint_rotate = 0;
}
static void ribout_clear_enlp(bgp_ribout_config_t *r) {
    r->enlp_spec.enabled = 0;
    r->enlp_spec.mode = BGP_U32_MODE_FIXED;
    r->enlp_spec.value = 0;
    r->enlp_spec.range_start = 0;
    r->enlp_spec.range_end = 0;
    r->enlp_count = 0;
    free(r->enlps);
    r->enlps = NULL;
    r->enlps_capacity = 0;
    r->enlps_step = 0;
}
static void ribout_clear_priority(bgp_ribout_config_t *r) {
    r->priority_spec.enabled = 0;
    r->priority_spec.mode = BGP_U32_MODE_FIXED;
    r->priority_spec.value = 0;
    r->priority_spec.range_start = 0;
    r->priority_spec.range_end = 0;
    r->priority_count = 0;
    free(r->priorities);
    r->priorities = NULL;
    r->priorities_capacity = 0;
    r->priorities_step = 0;
}
static void ribout_clear_preference(bgp_ribout_config_t *r) {
    r->preference_spec.enabled = 0;
    r->preference_spec.mode = BGP_U32_MODE_FIXED;
    r->preference_spec.value = 0;
    r->preference_spec.range_start = 0;
    r->preference_spec.range_end = 0;
    r->preference_count = 0;
    free(r->preferences);
    r->preferences = NULL;
    r->preferences_capacity = 0;
    r->preferences_step = 0;
}
static void ribout_clear_binding_sid(bgp_ribout_config_t *r) {
    r->binding_sid_spec.enabled = 0;
    r->binding_sid_spec.mode = BGP_U32_MODE_FIXED;
    r->binding_sid_spec.value = 0;
    r->binding_sid_spec.range_start = 0;
    r->binding_sid_spec.range_end = 0;
    r->binding_sid_count = 0;
    free(r->binding_sids);
    r->binding_sids = NULL;
    r->binding_sids_capacity = 0;
    r->binding_sids_step = 0;
    memset(&r->binding_sid_srv6_spec, 0, sizeof(r->binding_sid_srv6_spec));
    r->binding_sid_kind = BGP_RIBOUT_SR_BINDING_SID_NONE;
}
static void ribout_clear_segment_list(bgp_ribout_config_t *r) {
    r->segment_list_count = 0;
    free(r->segment_lists);
    r->segment_lists = NULL;
    r->segment_lists_capacity = 0;
}

/*
 * "no address-family": infer the family from the tokens again.
 */
static void ribout_clear_address_family(bgp_ribout_config_t *r) {
    r->address_family_afi = 0;
    r->address_family_safi = 0;
}

static void ribout_clear_nlri(bgp_ribout_config_t *r) {
    memset(&r->nlri_template, 0, sizeof(r->nlri_template));
}

static void ribout_clear_family_attr(bgp_ribout_config_t *r) {
    r->family_attr_type = 0;
    r->family_attr_len = 0;
    r->family_attr_text[0] = '\0';
    memset(r->family_attr, 0, sizeof(r->family_attr));
}

static void ribout_clear_pmsi(bgp_ribout_config_t *r) {
    if (r->family_attr_type == BGP_ATTR_PMSI_TUNNEL) ribout_clear_family_attr(r);
}

static void ribout_clear_ls_attribute(bgp_ribout_config_t *r) {
    if (r->family_attr_type == BGP_ATTR_BGP_LS) ribout_clear_family_attr(r);
}

static void ribout_clear_l2_info(bgp_ribout_config_t *r) {
    memset(&r->l2_info, 0, sizeof(r->l2_info));
    r->l2_info_text[0] = '\0';
}

/*
 * Ribout command specifications
 */
static const ribout_edit_spec_t ribout_specs[] = {
    {"nlri", bgp_ribout_parse_nlri, ribout_clear_nlri},
    {"pmsi", bgp_ribout_parse_family_attr, ribout_clear_pmsi},
    {"ls-attribute", bgp_ribout_parse_family_attr, ribout_clear_ls_attribute},
    {"l2-info", bgp_ribout_parse_family_attr, ribout_clear_l2_info},
    {"prefix",
     bgp_ribout_parse_prefix, ribout_clear_prefix},
    {"rd",
     bgp_ribout_parse_rd, ribout_clear_rd},
    {"label",
     bgp_ribout_parse_label, ribout_clear_label},
    {"label2",
     bgp_ribout_parse_label2, ribout_clear_label2},
    {"ethernet-tag",
     bgp_ribout_parse_ethernet_tag, ribout_clear_ethernet_tag},
    {"mac",
     bgp_ribout_parse_mac, ribout_clear_mac},
    {"ip",
     bgp_ribout_parse_ip, ribout_clear_ip},
    {"path-id",
     bgp_ribout_parse_path_ids, ribout_clear_path_id},
    {"next-hop",
     bgp_ribout_parse_next_hop, ribout_clear_next_hop},
    {"gateway-ip",
     bgp_ribout_parse_gateway_ip, ribout_clear_gateway_ip},
    {"esi",
     bgp_ribout_parse_esi, ribout_clear_esi},
    {"as-path",
     bgp_ribout_parse_aspath, ribout_clear_aspath},
    {"localpref",
     bgp_ribout_parse_localpref, ribout_clear_localpref},
    {"med",
     bgp_ribout_parse_med, ribout_clear_med},
    {"rt",
     bgp_ribout_parse_rt, ribout_clear_rt},
    {"rt-set",
     bgp_ribout_parse_rt_set, ribout_clear_rt_set},
    {"community",
     bgp_ribout_parse_community, ribout_clear_community},
    {"large-community",
     bgp_ribout_parse_large_community, ribout_clear_large_community},
    {"rotate-every",
     bgp_ribout_parse_rotate_every, ribout_clear_rotate_every},
    {"rotate-period",
     bgp_ribout_parse_rotate_period, ribout_clear_rotate_period},
    {"soo",
     bgp_ribout_parse_soo, ribout_clear_soo},
    {"encap",
     bgp_ribout_parse_encap, ribout_clear_encap},
    {"router-mac",
     bgp_ribout_parse_router_mac, ribout_clear_router_mac},
    {"origin",
     bgp_ribout_parse_origin, ribout_clear_origin},
    {"distinguisher",
     bgp_ribout_parse_distinguisher, ribout_clear_distinguisher},
    {"color",
     bgp_ribout_parse_color, ribout_clear_color},
    {"endpoint",
     bgp_ribout_parse_endpoint, ribout_clear_endpoint},
    {"enlp",
     bgp_ribout_parse_enlp, ribout_clear_enlp},
    {"priority",
     bgp_ribout_parse_priority, ribout_clear_priority},
    {"preference",
     bgp_ribout_parse_preference, ribout_clear_preference},
    {"binding-sid",
     bgp_ribout_parse_binding_sid, ribout_clear_binding_sid},
    {"segment-list",
     bgp_ribout_parse_segment_list, ribout_clear_segment_list},
    {"address-family",
     bgp_ribout_parse_address_family, ribout_clear_address_family},
};

static int ribout_edit_candidate(bgp_ribout_config_t *candidate, const char *keyword, const char *value, int clear) {
    for (size_t i = 0; i < sizeof(ribout_specs) / sizeof(*ribout_specs); i++) {
        const ribout_edit_spec_t *spec = &ribout_specs[i];
        if (strcmp(keyword, spec->keyword) != 0) continue;
        if (clear) {
            spec->clear(candidate);
            return 0;
        }
        char line[BGPSIM_COMMAND_SIZE + 64];
        int  size = snprintf(line, sizeof(line), "%s %s", keyword, value);
        if (size < 0 || (size_t)size >= sizeof(line)) return -1;
        return spec->parse(candidate, line);
    }
    if (strcmp(keyword, "action") == 0) {
        if (clear) {
            bgp_ribout_flowspec_clear_actions(candidate);
            return 0;
        }
        return bgp_ribout_flowspec_parse_action(candidate, value);
    }
    return clear ? bgp_ribout_flowspec_clear_component(candidate, keyword) :
                   bgp_ribout_flowspec_parse_component(candidate, keyword, value);
}

int bgp_ribout_edit(bgp_ribout_config_t *block, const char *keyword, const char *value, int clear) {
    if (!block || !keyword || !value || !command_input_valid(value, strlen(value))) return -1;
    // Edit a clone of the configuration part; generated products stay with the live block.
    bgp_ribout_config_t *candidate = bgp_ribout_config_clone(block);
    if (!candidate) return -1;

    int rc = ribout_edit_candidate(candidate, keyword, value, clear);
    if (rc == 0) {
        bgp_ribout_config_take(block, candidate);
        block->dirty = 1;
    }
    bgp_ribout_config_clone_free(candidate);
    return rc;
}
