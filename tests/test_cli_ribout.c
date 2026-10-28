/*
 * BGP RIB-OUT CLI Interactive Configuration Tests
 * Tests dynamic ribout creation and management via CLI
 */

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "bgpsim.h"
#include "bgp_router.h"
#include "test_result.h"
#include "bgp_neighbor.h"
#include "test_helpers.h"

#define CLI_RUN(cmd) cli_process_command(&session, &sim, &mode, (cmd))
// The output of a command, in the `text` buffer of the test.
#define CLI_SHOW(cmd) test_capture_command(&sim, &session, &mode, (cmd), text, sizeof(text), NULL, 0)

/*
 * Test 1: Create ribout block via CLI
 */
void test_create_ribout() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};

    CLI_RUN("ribout test1");

    test_result(sim.ribout_count == 1, "Create ribout block via CLI");
    test_result(strcmp(sim.ribouts[0]->name, "test1") == 0, "RIB-OUT name is correct");
    bgp_shutdown_sim(&sim);
}

/*
 * A Router's MAC must be unicast (RFC 9136), as a single value and at every step of a sequence.
 */
void test_router_mac_rejects_multicast_and_broadcast() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};

    CLI_RUN("ribout macs");

    int accepted = CLI_RUN("router-mac 02:00:00:00:00:01");
    test_result(accepted >= 0 && sim.ribouts[0]->router_mac_count == 1, "A unicast router-mac is accepted");

    test_result(CLI_RUN("router-mac 01:00:5e:00:00:01") < 0 && sim.ribouts[0]->router_mac_count == 1,
                "A multicast router-mac is rejected");
    test_result(CLI_RUN("router-mac ff:ff:ff:ff:ff:ff") < 0 && sim.ribouts[0]->router_mac_count == 1,
                "A broadcast router-mac is rejected");
    test_result(CLI_RUN("router-mac 03:00:00:00:00:01 x 2") < 0 && sim.ribouts[0]->router_mac_count == 1,
                "A router-mac sequence starting at a multicast MAC is rejected");
    char output[256], error[256];
    int  stepped = test_capture_command(&sim, &session, &mode, "router-mac 02:ff:ff:ff:ff:ff x 2", output,
                                        sizeof(output), error, sizeof(error));
    test_result(stepped < 0 && strstr(error, "invalid unicast MAC at offset 1") != NULL,
                "A router-mac sequence that steps onto a multicast MAC is rejected and names the step");
    test_result(sim.ribouts[0]->router_mac_count == 1, "A rejected router-mac sequence leaves no values behind");
    test_result(CLI_RUN("router-mac 02:00:00:00:00:02 01:00:5e:00:00:01") < 0 &&
                sim.ribouts[0]->router_mac_count == 1,
                "A rejected router-mac list leaves no values behind");

    static const uint8_t next_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    test_result(CLI_RUN("router-mac 02:00:00:00:00:02 02:00:00:00:00:03") >= 0 &&
                sim.ribouts[0]->router_mac_count == 3 &&
                memcmp(sim.ribouts[0]->router_mac_values[1].bytes + 2, next_mac, sizeof(next_mac)) == 0,
                "A valid router-mac list still applies after a rejected one");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 2: Add prefix to ribout
 */
void test_add_prefix() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};

    CLI_RUN("ribout test1");
    CLI_RUN("prefix 10.0.0.0/24 x 10");

    test_result(sim.ribouts[0]->prefix_spec.count == 10, "Prefix count set to 10");
    test_result(sim.ribouts[0]->prefix_spec.prefix_len == 24, "Prefix length is 24");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 3: Add prefix without x count (should default to 1)
 */
void test_add_prefix_default_count() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};

    CLI_RUN("ribout test1");
    CLI_RUN("prefix 192.168.1.0/24");

    test_result(sim.ribouts[0]->prefix_spec.count == 1, "Prefix count defaults to 1");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 4: Add path-ids to ribout
 */
void test_add_path_ids() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};

    CLI_RUN("ribout test1");
    CLI_RUN("path-id 0 1 2 3");

    test_result(sim.ribouts[0]->path_id_count == 4, "Path-ID count is 4");
    test_result(bgp_ribout_path_ids_at(sim.ribouts[0], 0) == 0, "First path-id is 0");
    test_result(bgp_ribout_path_ids_at(sim.ribouts[0], 3) == 3, "Fourth path-id is 3");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 5: Add single path-id
 */
void test_add_single_path_id() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};

    CLI_RUN("ribout test1");
    CLI_RUN("path-id 0");

    test_result(sim.ribouts[0]->path_id_count == 1, "Single path-ID");
    test_result(bgp_ribout_path_ids_at(sim.ribouts[0], 0) == 0, "Path-ID value is 0");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 6: Add explicit labels
 */
void test_add_labels() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};

    CLI_RUN("ribout test1");
    CLI_RUN("label 16000 16010 24000");

    test_result(sim.ribouts[0]->label_count == 3, "Label count is 3");
    test_result(bgp_ribout_labels_at(sim.ribouts[0], 0) == 16000, "First label is 16000");
    test_result(bgp_ribout_labels_at(sim.ribouts[0], 2) == 24000, "Third label is 24000");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 7: Add sequential labels
 */
void test_add_label_sequence() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};

    CLI_RUN("ribout test1");
    CLI_RUN("label 16000 x 4");

    test_result(sim.ribouts[0]->label_count == 4, "Sequential label count is 4");
    test_result(bgp_ribout_labels_at(sim.ribouts[0], 0) == 16000, "Sequence starts at 16000");
    test_result(bgp_ribout_labels_at(sim.ribouts[0], 3) == 16003, "Sequence ends at 16003");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 8: Add next_hop IP address
 */
void test_add_next_hop_ip() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};

    CLI_RUN("ribout test1");
    CLI_RUN("next-hop 192.168.1.1");

    test_result(sim.ribouts[0]->next_hop_spec.count == 1, "Next-hop count is 1");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 9: Add next_hop prefix with count
 */
void test_add_next_hop_prefix() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};

    CLI_RUN("ribout test1");
    CLI_RUN("next-hop 10.10.1.0 x 4");

    test_result(sim.ribouts[0]->next_hop_spec.count == 4, "Next-hop count is 4");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 9a: Add IPv6 next_hop with link-local companion
 */
void test_add_next_hop_link_local() {
    bgp_sim_t       sim = {0};
    struct in6_addr expected_global;
    struct in6_addr expected_link_local;
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};

    CLI_RUN("ribout test1");
    CLI_RUN("next-hop 2001:db8::1 x 4 link-local fe80::1");

    inet_pton(AF_INET6, "2001:db8::1", &expected_global);
    inet_pton(AF_INET6, "fe80::1", &expected_link_local);

    test_result(sim.ribouts[0]->next_hop_spec.count == 4, "IPv6 next-hop count is 4");
    test_result(sim.ribouts[0]->next_hop_spec.af == AF_INET6, "IPv6 next-hop family is AF_INET6");
    test_result(sim.ribouts[0]->next_hop_spec.has_link_local == 1, "IPv6 next-hop link-local companion is set");
    test_result(memcmp(&sim.ribouts[0]->next_hop_spec.base_addr.ipv6,
                       &expected_global,
                       sizeof(expected_global)) == 0,
                "IPv6 next-hop global address is correct");
    test_result(memcmp(&sim.ribouts[0]->next_hop_spec.link_local,
                       &expected_link_local,
                       sizeof(expected_link_local)) == 0,
                "IPv6 next-hop link-local address is correct");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 10: Add AS-path sequence
 */
void test_add_aspath_sequence() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};

    CLI_RUN("ribout test1");
    CLI_RUN("as-path 100 200 300");

    test_result(sim.ribouts[0]->aspath_segment_count == 1, "One AS-path segment");
    test_result(sim.ribouts[0]->aspath_segments[0].type == ASPATH_SEQUENCE, "Segment is sequence type");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 11: Add AS-path with set
 */
void test_add_aspath_set() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};

    CLI_RUN("ribout test1");
    CLI_RUN("as-path 100 { 200 300 } 400");

    test_result(sim.ribouts[0]->aspath_segment_count == 3, "Three AS-path segments");
    test_result(sim.ribouts[0]->aspath_segments[1].type == ASPATH_SET, "Second segment is set type");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 12: Add AS-path with random
 */
void test_add_aspath_random() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};

    CLI_RUN("ribout test1");
    CLI_RUN("as-path 100 200 [rand(500) x 10]");

    test_result(sim.ribouts[0]->aspath_segment_count == 2, "Two AS-path segments");
    test_result(sim.ribouts[0]->aspath_segments[1].type == ASPATH_RANDOM, "Second segment is random");
    test_result(sim.ribouts[0]->aspath_segments[1].rand_max == 500, "Random max is 500");
    test_result(sim.ribouts[0]->aspath_segments[1].rand_count == 10, "Random count is 10");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 13: Add fixed local preference
 */
void test_add_localpref_fixed() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};

    CLI_RUN("ribout test1");
    CLI_RUN("localpref 150");

    test_result(sim.ribouts[0]->localpref_spec.mode == BGP_U32_MODE_FIXED, "Localpref is fixed type");
    test_result(sim.ribouts[0]->localpref_spec.value == 150, "Localpref value is 150");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 14: Add random local preference
 */
void test_add_localpref_random() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};

    CLI_RUN("ribout test1");
    CLI_RUN("localpref rand(200)");

    test_result(sim.ribouts[0]->localpref_spec.mode == BGP_U32_MODE_RANDOM, "Localpref is random type");
    test_result(sim.ribouts[0]->localpref_spec.value == 200, "Localpref max is 200");
    bgp_shutdown_sim(&sim);
}

void test_scalar_range_controls() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};

    CLI_RUN("ribout scalar-range");
    CLI_RUN("localpref range(150,152)");
    CLI_RUN("med randrange(10,25)");

    test_result(sim.ribouts[0]->localpref_spec.mode == BGP_U32_MODE_RANGE, "Localpref range mode set");
    test_result(sim.ribouts[0]->localpref_spec.range_start == 150 &&
                sim.ribouts[0]->localpref_spec.range_end == 152,
                "Localpref range bounds stored");
    test_result(sim.ribouts[0]->med_spec.enabled == 1 &&
                sim.ribouts[0]->med_spec.mode == BGP_U32_MODE_RANDOM_RANGE,
                "MED randrange mode set");
    test_result(sim.ribouts[0]->med_spec.range_start == 10 &&
                sim.ribouts[0]->med_spec.range_end == 25,
                "MED randrange bounds stored");

    CLI_RUN("no localpref");
    CLI_RUN("no med");

    test_result(sim.ribouts[0]->localpref_spec.mode == BGP_U32_MODE_FIXED &&
                sim.ribouts[0]->localpref_spec.value == 100,
                "Localpref range resets to default fixed value");
    test_result(sim.ribouts[0]->med_spec.enabled == 0, "MED randrange clears cleanly");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 15: Add origin IGP
 */
void test_add_origin_igp() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};

    CLI_RUN("ribout test1");
    CLI_RUN("origin igp");

    test_result(sim.ribouts[0]->origin == ORIGIN_IGP, "Origin is IGP");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 16: Add origin EGP
 */
void test_add_origin_egp() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};

    CLI_RUN("ribout test1");
    CLI_RUN("origin egp");

    test_result(sim.ribouts[0]->origin == ORIGIN_EGP, "Origin is EGP");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 17: Add origin incomplete
 */
void test_add_origin_incomplete() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};

    CLI_RUN("ribout test1");
    CLI_RUN("origin incomplete");

    test_result(sim.ribouts[0]->origin == ORIGIN_INCOMPLETE, "Origin is incomplete");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 18: Create complete ribout block
 */
void test_create_complete_ribout() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};

    CLI_RUN("ribout complete");
    CLI_RUN("prefix 10.0.0.0/24 x 100");
    CLI_RUN("label 16000 x 2");
    CLI_RUN("path-id 0 1");
    CLI_RUN("next-hop 192.168.1.1");
    CLI_RUN("as-path 100 200 300");
    CLI_RUN("localpref 100");
    CLI_RUN("origin igp");

    test_result(sim.ribout_count == 1, "RIB-OUT created");
    test_result(sim.ribouts[0]->prefix_spec.count == 100, "Prefix count correct");
    test_result(sim.ribouts[0]->label_count == 2, "Label count correct");
    test_result(sim.ribouts[0]->path_id_count == 2, "Path-ID count correct");
    test_result(sim.ribouts[0]->localpref_spec.value == 100, "Localpref correct");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 19: Create multiple ribout blocks
 */
void test_create_multiple_ribouts() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};

    CLI_RUN("ribout first");
    CLI_RUN("prefix 10.0.0.0/24");

    CLI_RUN("ribout second");
    CLI_RUN("prefix 172.16.0.0/16");

    CLI_RUN("ribout third");
    CLI_RUN("prefix 192.168.0.0/24");

    test_result(sim.ribout_count == 3, "Three ribouts created");
    test_result(strcmp(sim.ribouts[0]->name, "first") == 0, "First ribout name correct");
    test_result(strcmp(sim.ribouts[1]->name, "second") == 0, "Second ribout name correct");
    test_result(strcmp(sim.ribouts[2]->name, "third") == 0, "Third ribout name correct");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 20: Delete ribout block
 */
void test_delete_ribout() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};

    CLI_RUN("ribout test1");
    CLI_RUN("ribout test2");
    test_result(sim.ribout_count == 2, "Two ribouts created");

    CLI_RUN("no ribout test1");
    test_result(sim.ribout_count == 1, "RIB-OUT deleted");
    test_result(strcmp(sim.ribouts[0]->name, "test2") == 0, "Remaining ribout is test2");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 21: Delete non-existent ribout (error case)
 */
void test_delete_nonexistent_ribout() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};

    CLI_RUN("ribout test1");
    int result = test_exec_config(&sim, "no ribout nonexistent");

    test_result(result < 0, "Delete non-existent ribout returns error");
    test_result(sim.ribout_count == 1, "RIB-OUT count unchanged");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 22: Add attributes without ribout (error case)
 */
void test_attributes_without_ribout() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);

    int result = test_exec_config(&sim, "prefix 10.0.0.0/24");

    test_result(result < 0, "Adding prefix without ribout returns error");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 23: Attributes apply to most recent ribout
 */
void test_attributes_apply_to_recent() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};

    CLI_RUN("ribout first");
    CLI_RUN("prefix 10.0.0.0/24 x 10");

    CLI_RUN("ribout second");
    CLI_RUN("prefix 172.16.0.0/16 x 20");

    test_result(sim.ribouts[0]->prefix_spec.count == 10, "First ribout has count 10");
    test_result(sim.ribouts[1]->prefix_spec.count == 20, "Second ribout has count 20");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 24: IPv6 prefix support
 */
void test_ipv6_prefix() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};

    CLI_RUN("ribout ipv6test");
    CLI_RUN("prefix 2001:db8::/32 x 5");

    test_result(sim.ribouts[0]->prefix_spec.af == AF_INET6, "Prefix is IPv6");
    test_result(sim.ribouts[0]->prefix_spec.count == 5, "IPv6 prefix count is 5");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 25: Registry growth and stable identities
 */
void test_max_ribouts_limit() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};

    char cmd[64];
    for (int i = 0; i < 500; i++) {
        snprintf(cmd, sizeof(cmd), "ribout test%d", i);
        CLI_RUN(cmd);
    }

    test_result(sim.ribout_count == 500, "Created 10x the former ribout limit via CLI");

    bgp_ribout_config_t *first = bgp_sim_find_ribout(&sim, "test0");
    bgp_ribout_config_t *last = bgp_sim_find_ribout(&sim, "test499");
    int                  result = test_exec_config(&sim, "no ribout test100");
    test_result(result >= 0 && first && last && bgp_sim_find_ribout(&sim, "test0") == first &&
                bgp_sim_find_ribout(&sim, "test499") == last && sim.ribout_count == 499,
                "Removing a middle ribout preserves other object addresses");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 26: Show ribout command (exec mode)
 */
void test_show_ribout_exec() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};

    CLI_RUN("ribout test1");
    CLI_RUN("prefix 10.0.0.0/24 x 10");
    CLI_RUN("path-id 0 1");

    mode = CLI_MODE_EXEC;
    // This should not crash
    CLI_RUN("show ribout");

    test_result(mode == CLI_MODE_EXEC, "Show ribout command in EXEC mode");
    bgp_shutdown_sim(&sim);
}

void test_show_ribout_preview_formatting() {
    bgp_sim_t     sim = {0};
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};
    char          stdout_buf[8192];

    bgp_init_simulator(&sim);

    CLI_RUN("ribout previewfmt");
    CLI_RUN("prefix 2001:db8:40::/64 x 2");
    CLI_RUN("path-id 1001 1002");
    CLI_RUN("next-hop 2001:db8:400::1 x 2 link-local fe80::400");
    CLI_RUN("med 35");
    CLI_RUN("origin egp");

    mode = CLI_MODE_EXEC;
    test_capture_command(&sim, &session, &mode, "show ribout previewfmt preview 2", stdout_buf, sizeof(stdout_buf), NULL, 0);

    test_result(strstr(stdout_buf, "#     nlri") != NULL &&
                strstr(stdout_buf, "#     prefix") == NULL,
                "Preview uses AF-neutral 'nlri' as the first column");
    test_result(strstr(stdout_buf, "next-hop") != NULL &&
                strstr(stdout_buf, "ll-nh") != NULL &&
                strstr(stdout_buf, "path-id") != NULL,
                "Preview headers use lower-case field names");
    test_result(strstr(stdout_buf, "Gateway-IP") == NULL &&
                strstr(stdout_buf, "Next-hop") == NULL &&
                strstr(stdout_buf, "Path-ID") == NULL,
                "Preview headers avoid sentence-case labels");
    test_result(strstr(stdout_buf, "link-local") == NULL, "Preview link-local next-hop uses dedicated column");

    bgp_shutdown_sim(&sim);
}

void test_evpn_type2_ribout_tokens() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t       mode = CLI_MODE_CONFIG;
    cli_session_t    session = {0};
    bgp_ribout_gen_t gen;
    bgp_gen_path_t   path;

    CLI_RUN("ribout evpn2");
    CLI_RUN("rd 65000:320");
    CLI_RUN("ethernet-tag 0 100");
    CLI_RUN("mac 00:11:22:33:44:00 x 4");
    CLI_RUN("ip 192.0.2.1 x 2");
    CLI_RUN("label 30000 30001");
    CLI_RUN("label2 40000 40001");
    CLI_RUN("esi 00:00:00:00:00:00:00:00:00:00 00:00:00:00:00:00:00:00:00:01");
    CLI_RUN("rt-set [65000:320] [65000:321,65000:322]");
    CLI_RUN("encap vxlan nvgre");
    CLI_RUN("router-mac 02:00:00:00:00:01 02:00:00:00:00:02");
    CLI_RUN("next-hop 192.0.2.10 x 2");
    CLI_RUN("med rand(25)");

    test_result(sim.ribouts[0]->mac_spec.count == 4, "EVPN Type 2 ribout MAC count is 4");
    test_result(sim.ribouts[0]->ip_spec.count == 2, "EVPN Type 2 ribout IP count is 2");
    test_result(sim.ribouts[0]->label2_count == 2, "EVPN Type 2 ribout label2 count is 2");
    test_result(sim.ribouts[0]->esi_count == 2, "EVPN Type 2 ribout ESI count is 2");
    test_result(sim.ribouts[0]->rt_set_count == 2, "EVPN Type 2 ribout RT-set count is 2");
    test_result(sim.ribouts[0]->encap_count == 2, "EVPN Type 2 ribout encap count is 2");
    test_result(sim.ribouts[0]->router_mac_count == 2, "EVPN Type 2 ribout router-mac count is 2");
    test_result(sim.ribouts[0]->med_spec.mode == BGP_U32_MODE_RANDOM, "EVPN Type 2 ribout MED is random");
    test_result(
        bgp_ribout_resolve_family(sim.ribouts[0]) == BGP_RIBOUT_FAMILY_EVPN_TYPE2,
        "EVPN Type 2 ribout resolves from MAC token");

    test_result(bgp_ribout_generator_init(&gen, sim.ribouts[0]) == 0,
                "EVPN Type 2 ribout generator initialization succeeds");
    test_result(bgp_ribout_gen_total_paths(&gen) == 16,
                "EVPN Type 2 total paths scale with RD, Ethernet Tag, MAC, and IP");

    if (bgp_ribout_generator_has_next(&gen) &&
        bgp_ribout_generator_next(&gen, &path) == 0) {
        test_result(path.has_rd == 1, "EVPN Type 2 path includes RD");
        test_result(path.has_mac == 1, "EVPN Type 2 path includes MAC");
        test_result(path.has_ip == 1, "EVPN Type 2 path includes IP");
        test_result(path.has_label == 1 && path.label == 30000, "EVPN Type 2 path includes primary label");
        test_result(path.has_label2 == 1 && path.label2 == 40000, "EVPN Type 2 path includes optional label2");
        test_result(path.ext_comm_len == 24, "EVPN Type 2 path carries RT, encap, and router-mac ext comms");
        test_result(path.ext_comm_data[8] == 0x03 && path.ext_comm_data[9] == 0x0c,
                    "EVPN Type 2 path carries encap after RT");
        test_result(path.ext_comm_data[16] == 0x06 && path.ext_comm_data[17] == 0x03,
                    "EVPN Type 2 path carries router-mac after encap");
    }

    bgp_shutdown_sim(&sim);
}

void test_evpn_identifier_shorthand_forms() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};
    static const uint8_t expected_router_mac1[6] =
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    static const uint8_t expected_router_mac2[6] =
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x02};

    CLI_RUN("ribout evpn2short");
    CLI_RUN("rd 65000:330");
    CLI_RUN("ethernet-tag 10");
    CLI_RUN("mac 1 x 2");
    CLI_RUN("esi 00112233445566778899 x 2");
    CLI_RUN("router-mac 1 2");

    test_result(sim.ribouts[0]->mac_spec.count == 2 &&
                memcmp(sim.ribouts[0]->mac_spec.base_addr, (const uint8_t[]){0x00,0x00,0x00,0x00,0x00,0x01}, 6) == 0,
                "EVPN Type 2 ribout accepts decimal MAC shorthand");
    test_result(sim.ribouts[0]->esi_count == 2 &&
                sim.ribouts[0]->esis[0].type == 0x00 &&
                memcmp(sim.ribouts[0]->esis[0].value,
                       (const uint8_t[]){0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99},
                       9) == 0 &&
                sim.ribouts[0]->esis[1].type == 0x00 &&
                memcmp(sim.ribouts[0]->esis[1].value,
                       (const uint8_t[]){0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x9a},
                       9) == 0,
                "EVPN Type 2 ribout accepts compact-hex ESI shorthand with sequence count");
    test_result(sim.ribouts[0]->router_mac_count == 2 &&
                memcmp(sim.ribouts[0]->router_mac_values[0].bytes + 2, expected_router_mac1, 6) == 0 &&
                memcmp(sim.ribouts[0]->router_mac_values[1].bytes + 2, expected_router_mac2, 6) == 0,
                "EVPN Type 2 ribout accepts decimal router-mac shorthand");

    bgp_shutdown_sim(&sim);
}

/*
 * "<base> x <count>" and named shorthand give the same stored values as the long forms.
 */
void test_sequence_shorthand_forms() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t           mode = CLI_MODE_CONFIG;
    cli_session_t        session = {0};
    bgp_ribout_config_t *r;
    const uint8_t        rt3[] = {0x00, 0x02, 0xfd, 0xe8, 0, 0, 0, 3};
    const uint8_t        soo2[] = {0x00, 0x03, 0xfd, 0xe8, 0, 0, 0, 8};
    const uint8_t        sid3[16] = {0x20, 0x01, 0x0d, 0xb8, [15] = 0x01};
    const uint8_t        label102[4] = {0, 0, 0, 102};

    CLI_RUN("ribout shorthand");
    r = sim.ribouts[0];
    test_result(CLI_RUN("rt 65000:1 x 3 65000:9") == 0 && r->rt_count == 4 &&
                memcmp(r->rt_values[2].bytes, rt3, 8) == 0 && r->rt_values[3].bytes[7] == 9,
                "rt <base> x <count> makes consecutive route targets, and more values can follow");
    test_result(CLI_RUN("soo 65000:7 x 2") == 0 && r->soo_count == 2 && memcmp(r->soo_values[1].bytes, soo2, 8) == 0,
                "soo <base> x <count> makes consecutive sites of origin");
    test_result(CLI_RUN("rt x 2") < 0 && CLI_RUN("soo 65000:1 x 0") < 0 && CLI_RUN("soo 65000:1 x 99") < 0 &&
                CLI_RUN("no rt") == 0 && CLI_RUN("rt 65000:4294967295 x 2") < 0,
                "rt and soo reject x without a base, a zero count, more than the list holds, and a value overflow");
    test_result(CLI_RUN("as-path 65001 x 3 65002") == 0 && r->aspath_segment_count == 1 &&
                r->aspath_segments[0].value_count == 4 && r->aspath_segments[0].as_values[2] == 65001 &&
                r->aspath_segments[0].as_values[3] == 65002 && CLI_RUN("as-path 65001 x 0") < 0 &&
                CLI_RUN("as-path 65001 x 101") < 0,
                "as-path <asn> x <count> prepends; a zero or oversized count is rejected");
    test_result(CLI_RUN("ethernet-tag 5 max") == 0 && r->ethernet_tag_count == 2 &&
                bgp_ribout_ethernet_tags_at(r, 1) == UINT32_MAX && CLI_RUN("ethernet-tag maximum") < 0,
                "ethernet-tag max is MAX-ET");
    test_result(CLI_RUN("no encap") == 0 && CLI_RUN("encap mpls") == 0 && r->encap_count == 1 &&
                r->encap_values[0].bytes[7] == 10,
                "encap mpls is tunnel type 10");
    test_result(CLI_RUN("segment-list 1 weight 1 srv6 2001:db8:: behavior 4660 x 3") == 0 &&
                r->segment_list_count == 1 && r->segment_lists[0].segment_count == 3 &&
                memcmp(r->segment_lists[0].segments[1].sid, sid3, 16) == 0 &&
                r->segment_lists[0].segments[2].sid[15] == 2 && r->segment_lists[0].segments[2].has_srv6_behavior &&
                r->segment_lists[0].segments[2].srv6_behavior.endpoint_behavior == 4660,
                "segment-list srv6 <sid> x <count> makes consecutive SIDs with the same behavior");
    test_result(CLI_RUN("segment-list 2 weight 1 mpls 100 x 3 900") == 0 && r->segment_lists[1].segment_count == 4 &&
                memcmp(r->segment_lists[1].segments[2].sid, label102, 4) == 0 &&
                r->segment_lists[1].segments[3].sid[3] == 0x84,
                "segment-list mpls <label> x <count> makes consecutive labels, and more can follow");
    test_result(CLI_RUN("segment-list 3 weight 1 mpls x 3") < 0 && CLI_RUN("segment-list 3 weight 1 mpls 5 x 33") < 0 &&
                CLI_RUN("segment-list 3 weight 1 mpls 1048575 x 2") < 0 &&
                CLI_RUN("segment-list 3 weight 1 mpls 1048576") < 0 &&
                CLI_RUN("segment-list 3 weight 1 srv6 x 2") < 0 &&
                CLI_RUN("segment-list 3 weight 1 srv6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff x 2") < 0 &&
                r->segment_list_count == 2,
                "segment-list rejects x without a segment, too many segments, and a value overflow");
    bgp_shutdown_sim(&sim);
}

void test_show_ribout_preview_evpn_type2_formatting() {
    bgp_sim_t     sim = {0};
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};
    char          stdout_buf[8192];

    bgp_init_simulator(&sim);

    CLI_RUN("ribout evpn2preview");
    CLI_RUN("rd 65000:320");
    CLI_RUN("ethernet-tag 10");
    CLI_RUN("mac 00:11:22:33:44:00 x 2");
    CLI_RUN("ip 192.0.2.1 x 2");
    CLI_RUN("label 30000");
    CLI_RUN("label2 40000 40001");
    CLI_RUN("esi 00:00:00:00:00:00:00:00:00:01");
    CLI_RUN("next-hop 192.0.2.10");
    CLI_RUN("rt 65000:320");
    CLI_RUN("encap vxlan");
    CLI_RUN("router-mac 02:00:00:00:00:01");

    mode = CLI_MODE_EXEC;
    test_capture_command(&sim, &session, &mode, "show ribout evpn2preview preview 2", stdout_buf, sizeof(stdout_buf), NULL, 0);

    test_result(strstr(stdout_buf, "#     nlri") != NULL, "EVPN Type 2 preview keeps AF-neutral NLRI column");
    test_result(strstr(stdout_buf, "label2") != NULL &&
                strstr(stdout_buf, "next-hop") != NULL &&
                strstr(stdout_buf, "path-id") == NULL,
                "EVPN Type 2 preview exposes label2 without unrelated path-id column");
    test_result(strstr(stdout_buf, "encap") != NULL &&
                strstr(stdout_buf, "router-mac") != NULL,
                "EVPN Type 2 preview exposes encap and router-mac columns");
    test_result(strstr(stdout_buf, "eth-tag") == NULL,
                "EVPN Type 2 preview keeps Ethernet Tag inside compact NLRI text");
    test_result(strstr(stdout_buf,
                       "<etag=10,mac=00:11:22:33:44:00,ip=192.0.2.1>") != NULL,
                "EVPN Type 2 preview renders host identity compactly");
    test_result(strstr(stdout_buf, "vxlan") != NULL &&
                strstr(stdout_buf, "02:00:00:00:00:01") != NULL,
                "EVPN Type 2 preview renders EVPN attr-side ext comm values");

    bgp_shutdown_sim(&sim);
}

void test_srpolicy_ribout_tokens() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};

    CLI_RUN("ribout srpol");
    CLI_RUN("distinguisher 100 x 2");
    CLI_RUN("color 200 201");
    CLI_RUN("endpoint 10.0.0.1 x 4");
    CLI_RUN("rt 192.0.2.10:100");
    CLI_RUN("enlp 1 4");
    CLI_RUN("priority 7 9");
    CLI_RUN("preference 300 400");
    CLI_RUN("binding-sid srv6 2001:db8:100::1 x 2");
    CLI_RUN("segment-list 1 weight 10 mpls 16010 16011");
    CLI_RUN("segment-list 2 weight 20 srv6 2001:db8:1::1 behavior 4660 structure 48 16 16 48 2001:db8:1::2");

    test_result(sim.ribouts[0]->distinguisher_count == 2, "SR Policy distinguisher values set");
    test_result(sim.ribouts[0]->color_count == 2, "SR Policy color values set");
    test_result(sim.ribouts[0]->endpoint_spec.count == 4, "SR Policy endpoint count set");
    test_result(sim.ribouts[0]->enlp_count == 2, "SR Policy ENLP values set");
    test_result(sim.ribouts[0]->priority_count == 2, "SR Policy priority values set");
    test_result(sim.ribouts[0]->preference_count == 2, "SR Policy preference values set");
    test_result(sim.ribouts[0]->binding_sid_kind ==
                BGP_RIBOUT_SR_BINDING_SID_SRV6 &&
                sim.ribouts[0]->binding_sid_srv6_spec.count == 2,
                "SR Policy SRv6 binding SID values set");
    test_result(sim.ribouts[0]->segment_list_count == 2, "SR Policy segment-lists set");
    test_result(sim.ribouts[0]->segment_lists[1].segments[0].has_srv6_behavior &&
                sim.ribouts[0]->segment_lists[1].segments[0].srv6_behavior.endpoint_behavior == 4660 &&
                sim.ribouts[0]->segment_lists[1].segments[0].srv6_behavior.locator_block_len == 48,
                "SR Policy SRv6 segment behavior and structure set");
    test_result(bgp_ribout_resolve_family(sim.ribouts[0]) ==
                BGP_RIBOUT_FAMILY_SR_POLICY_IPV4,
                "SR Policy ribout resolves IPv4 family from endpoint token");

    bgp_shutdown_sim(&sim);
}

void test_srpolicy_random_controls() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t       mode = CLI_MODE_CONFIG;
    cli_session_t    session = {0};
    test_env_guard_t randseed_guard;

    test_env_guard_capture(&randseed_guard, "RANDSEED");
    setenv("RANDSEED", "777", 1);
    CLI_RUN("ribout srrand");
    CLI_RUN("distinguisher 100");
    CLI_RUN("color 200");
    CLI_RUN("endpoint 10.0.0.1");
    CLI_RUN("rt 192.0.2.10:100");
    CLI_RUN("enlp randrange(1,4)");
    CLI_RUN("priority range(7,8)");
    CLI_RUN("preference rand(4096)");
    CLI_RUN("binding-sid mpls randrange(16,1048575)");
    CLI_RUN("segment-list 1 weight 10 mpls 16010 16011");

    test_result(sim.ribouts[0]->enlp_spec.enabled == 1 &&
                sim.ribouts[0]->enlp_spec.mode == BGP_U32_MODE_RANDOM_RANGE &&
                sim.ribouts[0]->enlp_spec.range_start == 1 &&
                sim.ribouts[0]->enlp_spec.range_end == 4,
                "SR Policy ribout accepts random ENLP");
    test_result(sim.ribouts[0]->priority_spec.enabled == 1 &&
                sim.ribouts[0]->priority_spec.mode == BGP_U32_MODE_RANGE &&
                sim.ribouts[0]->priority_spec.range_start == 7 &&
                sim.ribouts[0]->priority_spec.range_end == 8,
                "SR Policy ribout accepts ranged priority");
    test_result(sim.ribouts[0]->preference_spec.enabled == 1 &&
                sim.ribouts[0]->preference_spec.value == 4096,
                "SR Policy ribout accepts random preference");
    test_result(sim.ribouts[0]->binding_sid_spec.enabled == 1 &&
                sim.ribouts[0]->binding_sid_spec.mode ==
                    BGP_U32_MODE_RANDOM_RANGE &&
                sim.ribouts[0]->binding_sid_spec.range_start == 16 &&
                sim.ribouts[0]->binding_sid_spec.range_end == 1048575,
                "SR Policy ribout accepts strict-valid random binding SID range");

    CLI_RUN("no enlp");
    CLI_RUN("no priority");
    CLI_RUN("no preference");
    CLI_RUN("no binding-sid");

    test_result(sim.ribouts[0]->enlp_spec.enabled == 0 &&
                sim.ribouts[0]->enlp_count == 0,
                "SR Policy ribout clears random ENLP");
    test_result(sim.ribouts[0]->priority_spec.enabled == 0 &&
                sim.ribouts[0]->priority_count == 0,
                "SR Policy ribout clears ranged priority");
    test_result(sim.ribouts[0]->preference_spec.enabled == 0 &&
                sim.ribouts[0]->preference_count == 0,
                "SR Policy ribout clears random preference");
    test_result(sim.ribouts[0]->binding_sid_spec.enabled == 0 &&
                sim.ribouts[0]->binding_sid_count == 0,
                "SR Policy ribout clears random binding SID");
    test_env_guard_restore(&randseed_guard, "RANDSEED");
    bgp_shutdown_sim(&sim);
}

void test_show_ribout_preview_srpolicy_formatting() {
    bgp_sim_t     sim = {0};
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};
    char          stdout_buf[8192];

    bgp_init_simulator(&sim);

    CLI_RUN("ribout srpreview");
    CLI_RUN("distinguisher 100 101");
    CLI_RUN("color 200");
    CLI_RUN("endpoint 10.0.0.1 x 2");
    CLI_RUN("path-id 7 8");
    CLI_RUN("next-hop 2001:db8::1");
    CLI_RUN("rt 192.0.2.10:100");
    CLI_RUN("enlp 3");
    CLI_RUN("priority 7");
    CLI_RUN("preference 300 400");
    CLI_RUN("binding-sid srv6 fc00:0:77::1 x 2");
    CLI_RUN("segment-list 1 weight 10 mpls 16010 16011");
    CLI_RUN("segment-list 2 weight 20 srv6 2001:db8:20::1 behavior 4660 structure 48 16 16 48");
    CLI_RUN("origin egp");

    mode = CLI_MODE_EXEC;
    test_capture_command(&sim, &session, &mode, "show ribout srpreview preview 2", stdout_buf, sizeof(stdout_buf), NULL, 0);

    test_result(strstr(stdout_buf, "#     nlri") != NULL, "SR Policy preview keeps AF-neutral NLRI column");
    test_result(strstr(stdout_buf, "enlp") != NULL &&
                strstr(stdout_buf, "prio") != NULL,
                "SR Policy preview exposes ENLP and priority columns");
    test_result(strstr(stdout_buf, "pref") != NULL &&
                strstr(stdout_buf, "bsid") != NULL &&
                strstr(stdout_buf, "seg-lists") != NULL,
                "SR Policy preview exposes tunnel attribute columns");
    test_result(strstr(stdout_buf, "<dist=100,color=200,endpoint=10.0.0.1>") != NULL,
                "SR Policy preview renders the NLRI identity compactly");
    test_result(strstr(stdout_buf, "fc00:0:77::1") != NULL, "SR Policy preview renders SRv6 binding SID values");
    test_result(strstr(stdout_buf, "1,2") != NULL, "SR Policy preview shows configured segment-list identifiers");

    bgp_shutdown_sim(&sim);
}

/*
 * FlowSpec ribout commands at the block level: the match components, the actions, and the "no" forms
 */
void test_flowspec_ribout_tokens() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t                   mode = CLI_MODE_CONFIG;
    cli_session_t                session = {0};
    const bgp_ribout_flowspec_t *fs;

    CLI_RUN("ribout fs");
    bgp_ribout_config_t *block = bgp_sim_find_ribout(&sim, "fs");
    CLI_RUN("address-family ipv4 flowspec");
    CLI_RUN("as-path 65001");
    CLI_RUN("prefix 10.1.0.0/24 x 3");
    CLI_RUN("protocol 6");
    CLI_RUN("dst-port 80 443");
    CLI_RUN("tcp-flags syn+ack !rst");
    CLI_RUN("src-port each(1000, 2000)");
    CLI_RUN("action redirect-ip 192.0.2.1 x 2 copy");
    CLI_RUN("color 100 co 01");
    CLI_RUN("action mark 10");
    fs = block->flowspec;

    test_result(session.config_mode == CONFIG_MODE_RIBOUT, "FlowSpec lines stay in the ribout mode");
    test_result(fs != NULL && block->prefix_spec.count == 3 &&
                fs->components[FLOWSPEC_IP_PROTOCOL].alternative_count == 1 &&
                fs->components[FLOWSPEC_DEST_PORT].alternatives[0].num_values == 2 &&
                fs->components[FLOWSPEC_TCP_FLAGS].alternatives[0].num_values == 2 &&
                fs->components[FLOWSPEC_SRC_PORT].alternative_count == 2,
                "prefix is the destination; the components belong to the block");
    test_result(fs != NULL && fs->actions.line_count == 2 &&
                fs->actions.lines[0].value_count == 2 && fs->actions.lines[0].value_len == 8 &&
                (fs->actions.lines[0].values[1][7] & 0x01) == 0x01 &&
                fs->actions.lines[0].values[1][5] == 2,
                "A redirect-ip sequence holds one value per address, each with the copy bit");
    test_result(bgp_ribout_resolve_family(block) == BGP_RIBOUT_FAMILY_FLOWSPEC_IPV4 &&
                bgp_ribout_total_paths(block) == 6,
                "FlowSpec ribout resolves its family; 3 prefixes x 2 source ports");

    CLI_RUN("no dst-port");
    CLI_RUN("no action");
    fs = block->flowspec;  /* Each successful edit replaces the FlowSpec part. */
    test_result(fs->components[FLOWSPEC_DEST_PORT].alternative_count == 0 &&
                fs->components[FLOWSPEC_IP_PROTOCOL].alternative_count == 1 &&
                fs->actions.line_count == 0,
                "FlowSpec 'no' forms clear one component or all action lines");
    CLI_RUN("exit");

    bgp_shutdown_sim(&sim);
}

/*
 * FlowSpec ribout lines reject malformed components and actions, and leave the block unchanged
 */
void test_flowspec_ribout_rejects_bad_input() {
    static const char *bad_lines[] = {
        "protocol =6",
        "protocol 6&",
        "protocol &6",
        "protocol 6&&7",
        "protocol 4294967296",
        "tcp-flags syn++ack",
        "tcp-flags +syn",
        "tcp-flags =syn",
        "tcp-flags syn:4",
        "tcp-flags bogus",
        "tcp-flags any(syn",
        "dscp 1:2",
        "fragment df:2",
        "dst-port 1 2 3 4 5 6 7 8 9",
        "protocol each(6)",
        "protocol each(6,,7)",
        "dst-port 80 x 0",
        "dst-port >=1&<=2 x 3",
        "src-prefix 10.0.0.0/8-24",
        "src-prefix 2001:db8::/64-64",
        "action mark 64",
        "action mark 60 x 5",
        "action color 5",
        "action discard",
        "action bogus",
        "action redirect-ip 192.0.2.1 extra",
        "action redirect-ip 192.0.2.1 2001:db8::1",
        "action redirect-ip 192.0.2.1 192.0.2.2 x 2",
        "action traffic-rate bytes -1",
        "action traffic-rate bytes 1 as 65536",
        "action interface-set 1:16384",
        "action redirect-vrf 65000",
        "steer sr-policy endpoint 192.0.2.1 color 5",
        "rule r1",
    };
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t            mode = CLI_MODE_CONFIG;
    cli_session_t         session = {0};
    bgp_ribout_flowspec_t before;
    int                   all_rejected = 1;

    CLI_RUN("ribout fs-bad");
    bgp_ribout_config_t *block = bgp_sim_find_ribout(&sim, "fs-bad");
    CLI_RUN("prefix 10.1.0.0/24");
    CLI_RUN("protocol 17");
    before = *block->flowspec;

    for (size_t i = 0; i < sizeof(bad_lines) / sizeof(bad_lines[0]); i++) {
        if (CLI_RUN(bad_lines[i]) >= 0) {
            fprintf(stderr, "accepted: %s\n", bad_lines[i]);
            all_rejected = 0;
        }
    }

    test_result(all_rejected, "FlowSpec lines reject malformed components and actions");
    test_result(memcmp(&before, block->flowspec, sizeof(before)) == 0,
                "FlowSpec rejected lines leave the block unchanged");
    CLI_RUN("exit");

    bgp_shutdown_sim(&sim);
}

/*
 * color outside SR Policy: per-value CO types, show and preview views, a rejected line, and "no color"
 */
void test_color_community_ribout_cli() {
    bgp_sim_t            sim = {0};
    cli_mode_t           mode = CLI_MODE_CONFIG;
    cli_session_t        session = {0};
    bgp_ribout_config_t *block;
    char                 stdout_buf[16384];

    bgp_init_simulator(&sim);
    CLI_RUN("ribout colored");
    block = bgp_sim_find_ribout(&sim, "colored");
    CLI_RUN("prefix 10.1.0.0/24 x 3");
    CLI_RUN("next-hop 10.255.0.201 x 3");
    CLI_RUN("color 1 x 3 co 01");
    test_result(block->color_count == 3 && bgp_ribout_colors_at(block, 2) == 3 && bgp_ribout_color_co_at(block, 2) == BGP_COLOR_CO_NULL,
                "color sequence with co is stored per value");
    CLI_RUN("color 5 co 2");
    test_result(block->color_count == 3 && bgp_ribout_colors_at(block, 0) == 1, "A rejected color line leaves the colors unchanged");
    CLI_RUN("exit");

    mode = CLI_MODE_EXEC;
    test_capture_command(&sim, &session, &mode, "show ribout colored", stdout_buf, sizeof(stdout_buf), NULL, 0);
    test_result(strstr(stdout_buf, "Color communities: 1 x 3 co 01") != NULL,
                "Detail view labels unicast colors as Color communities");
    test_capture_command(&sim, &session, &mode, "show ribout colored preview", stdout_buf, sizeof(stdout_buf), NULL, 0);
    test_result(strstr(stdout_buf, "color") != NULL && strstr(stdout_buf, "10.255.0.202") != NULL &&
                strstr(stdout_buf, "2 co 01") != NULL,
                "Preview shows the Color community of each path");

    mode = CLI_MODE_CONFIG;
    CLI_RUN("ribout colored");
    CLI_RUN("color 4 co 10 7");
    test_result(block->color_count == 2 && bgp_ribout_color_co_at(block, 0) == BGP_COLOR_CO_ANY &&
                bgp_ribout_color_co_at(block, 1) == BGP_COLOR_CO_SPECIFIC,
                "A new color line replaces the old values and CO types");
    CLI_RUN("no color");
    test_result(block->color_count == 0 && block->colors == NULL && block->color_co == NULL,
                "no color releases the values and the CO types");
    CLI_RUN("color set 100 co 01 300 co 10 200");
    test_result(block->color_set && block->color_count == 3, "CLI accepts a fixed Color set");
    CLI_RUN("exit");

    mode = CLI_MODE_EXEC;
    test_capture_command(&sim, &session, &mode, "show ribout colored", stdout_buf, sizeof(stdout_buf), NULL, 0);
    test_result(strstr(stdout_buf, "Color communities: set 100 co 01 300 co 10 200") != NULL,
                "Detail view distinguishes a fixed Color set from rotation");
    test_capture_command(&sim, &session, &mode, "show ribout colored preview", stdout_buf, sizeof(stdout_buf), NULL, 0);
    const char *row = strstr(stdout_buf, "100 co 01,300 co 10,200");
    test_result(row && (row = strstr(row + 1, "100 co 01,300 co 10,200")) &&
                strstr(row + 1, "100 co 01,300 co 10,200"), "Every previewed path carries the entire Color set");

    bgp_shutdown_sim(&sim);
}

static int count_substring(const char *text, const char *needle) {
    int count = 0;

    for (const char *at = strstr(text, needle); at; at = strstr(at + 1, needle)) {
        count++;
    }
    return count;
}

/*
 * "show ribout <name>" reports the published snapshot and whether the configuration changed since it.
 */
void test_show_ribout_snapshot_status() {
    bgp_sim_t     sim = {0};
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};
    char          stdout_buf[16384];

    bgp_init_simulator(&sim);
    CLI_RUN("ribout snap");
    CLI_RUN("prefix 10.1.0.0/24 x 3");
    CLI_RUN("next-hop 192.0.2.1");
    CLI_RUN("end");

    test_capture_command(&sim, &session, &mode, "show ribout snap", stdout_buf, sizeof(stdout_buf), NULL, 0);
    test_result(strstr(stdout_buf, "No messages generated (run 'update generate')") != NULL &&
                strstr(stdout_buf, "Snapshot:") == NULL,
                "show ribout before generation reports no snapshot");

    test_capture_command(&sim, &session, &mode, "update generate", stdout_buf, sizeof(stdout_buf), NULL, 0);
    test_capture_command(&sim, &session, &mode, "show ribout snap", stdout_buf, sizeof(stdout_buf), NULL, 0);
    test_result(count_substring(stdout_buf, "Generation Time:") == 1 &&
                count_substring(stdout_buf, "Generation CPU:") == 1 &&
                strstr(stdout_buf, "Message Count:     1") != NULL &&
                strstr(stdout_buf, "(ipv4-unicast, add-path off, classic)") != NULL &&
                strstr(stdout_buf, "Status:            current") != NULL,
                "show ribout reports the current snapshot and its wire profile once");

    mode = CLI_MODE_CONFIG;
    CLI_RUN("ribout snap");
    CLI_RUN("localpref 300");
    CLI_RUN("end");
    test_capture_command(&sim, &session, &mode, "show ribout snap", stdout_buf, sizeof(stdout_buf), NULL, 0);
    test_result(strstr(stdout_buf, "Status:            stale") != NULL &&
                strstr(stdout_buf, "Message Count:     1") != NULL,
                "An edit after generation marks the kept snapshot stale");

    bgp_shutdown_sim(&sim);
}

/*
 * FlowSpec "show ribout" preview and detail views: family, RD, the NLRI of each path, rotating actions, and the
 * match and action lines
 */
void test_show_ribout_preview_flowspec_formatting() {
    bgp_sim_t     sim = {0};
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};
    char          stdout_buf[16384];

    bgp_init_simulator(&sim);

    CLI_RUN("ribout fspreview");
    CLI_RUN("address-family ipv4 flowspec-vpn");
    CLI_RUN("rd 65000:7");
    CLI_RUN("prefix 10.1.0.0/24 x 2");
    CLI_RUN("dst-port >=1024&<=2048");
    CLI_RUN("action redirect-ip 192.0.2.1 192.0.2.2");
    CLI_RUN("color 100");
    CLI_RUN("action mark 10");
    CLI_RUN("exit");

    mode = CLI_MODE_EXEC;
    test_capture_command(&sim, &session, &mode, "show ribout fspreview preview 3", stdout_buf, sizeof(stdout_buf), NULL, 0);

    test_result(strstr(stdout_buf, "family: ipv4-flowspec-vpn") != NULL, "FlowSpec preview names the family");
    test_result(strstr(stdout_buf, "actions") != NULL &&
                strstr(stdout_buf, "rd") != NULL &&
                strstr(stdout_buf, "color") != NULL,
                "FlowSpec preview exposes actions, RD and color columns");
    test_result(strstr(stdout_buf, "prefix 10.1.1.0/24 dst-port >=1024&<=2048") != NULL,
                "FlowSpec preview renders the NLRI of each path");
    test_result(strstr(stdout_buf, "redirect-ip 192.0.2.1; mark 10") != NULL &&
                strstr(stdout_buf, "redirect-ip 192.0.2.2; mark 10") != NULL,
                "FlowSpec preview shows the rotating redirect value of each path");
    test_result(strstr(stdout_buf, "65000:7") != NULL, "FlowSpec VPN preview shows the RD");

    test_capture_command(&sim, &session, &mode, "show ribout fspreview", stdout_buf, sizeof(stdout_buf), NULL, 0);
    test_result(strstr(stdout_buf, "Match:             dst-port >=1024&<=2048") != NULL &&
                strstr(stdout_buf, "Actions:           redirect-ip 192.0.2.1 192.0.2.2") != NULL &&
                strstr(stdout_buf, "Color communities: 100") != NULL,
                "FlowSpec detail view lists the match and action lines");

    bgp_shutdown_sim(&sim);
}

/*
 * Test 27: Generator integration - verify paths can be generated
 */
void test_generator_integration() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};

    CLI_RUN("ribout gentest");
    CLI_RUN("prefix 10.0.0.0/24 x 5");
    CLI_RUN("label 16000 16001");
    CLI_RUN("path-id 0 1");
    CLI_RUN("next-hop 192.168.1.1");
    CLI_RUN("as-path 100 200");
    CLI_RUN("localpref 100");
    CLI_RUN("origin igp");

    // Initialize generator
    bgp_ribout_gen_t gen;
    int              result = bgp_ribout_generator_init(&gen, sim.ribouts[0]);

    test_result(result == 0, "Generator initialization successful");
    test_result(bgp_ribout_gen_total_paths(&gen) == 20, "Total paths = 5 prefixes × 2 labels × 2 path-ids");

    // Generate first path
    bgp_gen_path_t path;
    int            has_next = bgp_ribout_generator_has_next(&gen);
    test_result(has_next, "Generator has paths");

    if (has_next) {
        bgp_ribout_generator_next(&gen, &path);
        test_result(path.has_label == 1, "First path is labeled");
        test_result(path.label == 16000, "First path has label 16000");
        test_result(path.path_id == 0, "First path has path-id 0");
        test_result(path.local_pref == 100, "First path has localpref 100");
    }
    bgp_shutdown_sim(&sim);
}

void test_vpn_ribout_tokens() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t       mode = CLI_MODE_CONFIG;
    cli_session_t    session = {0};
    bgp_ribout_gen_t gen;
    bgp_gen_path_t   path;

    CLI_RUN("ribout vpn4");
    CLI_RUN("prefix 10.10.0.0/24 x 2");
    CLI_RUN("rd 65000:100 65000:101");
    CLI_RUN("label 16000 16001");
    CLI_RUN("path-id 1 2");
    CLI_RUN("next-hop 192.0.2.1");
    CLI_RUN("rt 65000:100");
    CLI_RUN("rt 65000:101");
    CLI_RUN("soo 65000:9");
    CLI_RUN("med 50");

    test_result(sim.ribouts[0]->rd_count == 2, "VPN ribout RD count is 2");
    test_result(sim.ribouts[0]->rt_count == 2, "VPN ribout RT count is 2");
    test_result(sim.ribouts[0]->soo_count == 1, "VPN ribout SoO count is 1");
    test_result(sim.ribouts[0]->med_spec.enabled == 1, "VPN ribout MED enabled");
    test_result(sim.ribouts[0]->med_spec.value == 50, "VPN ribout MED value is 50");
    test_result(bgp_ribout_resolve_family(sim.ribouts[0]) == BGP_RIBOUT_FAMILY_VPNV4, "VPN ribout resolves to VPNv4");

    test_result(bgp_ribout_generator_init(&gen, sim.ribouts[0]) == 0, "VPN ribout generator initialization succeeds");
    test_result(bgp_ribout_gen_total_paths(&gen) == 16,
                "VPN ribout total paths include RD, label, and path-id dimensions");

    if (bgp_ribout_generator_has_next(&gen) &&
        bgp_ribout_generator_next(&gen, &path) == 0) {
        test_result(path.has_rd == 1, "VPN ribout path includes RD");
        test_result(path.has_label == 1, "VPN ribout path includes label");
        test_result(path.has_med == 1, "VPN ribout path includes MED");
        test_result(path.ext_comm_len == 24, "VPN ribout path carries RT and SoO ext comms");
    }

    bgp_shutdown_sim(&sim);
}

void test_evpn_ribout_tokens() {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t       mode = CLI_MODE_CONFIG;
    cli_session_t    session = {0};
    bgp_ribout_gen_t gen;
    bgp_gen_path_t   path;

    CLI_RUN("ribout evpn5");
    CLI_RUN("prefix 192.168.0.0/24 x 2");
    CLI_RUN("rd 65000:300");
    CLI_RUN("label 30000");
    CLI_RUN("ethernet-tag 0 100");
    CLI_RUN("gateway-ip 10.255.0.1 x 2");
    CLI_RUN("rt-set [65000:300] [65000:301,65000:302]");
    CLI_RUN("encap vxlan");
    CLI_RUN("router-mac 02:aa:bb:cc:dd:ee");
    CLI_RUN("next-hop 192.0.2.10");
    CLI_RUN("med rand(25)");

    test_result(sim.ribouts[0]->ethernet_tag_count == 2, "EVPN ribout Ethernet Tag count is 2");
    test_result(sim.ribouts[0]->gateway_ip_spec.count == 2, "EVPN ribout gateway IP count is 2");
    test_result(sim.ribouts[0]->rt_set_count == 2, "EVPN ribout RT-set count is 2");
    test_result(sim.ribouts[0]->encap_count == 1, "EVPN ribout encap count is 1");
    test_result(sim.ribouts[0]->router_mac_count == 1, "EVPN ribout router-mac count is 1");
    test_result(sim.ribouts[0]->med_spec.mode == BGP_U32_MODE_RANDOM, "EVPN ribout MED is random");
    test_result(
        bgp_ribout_resolve_family(sim.ribouts[0]) == BGP_RIBOUT_FAMILY_EVPN_TYPE5_IPV4,
        "EVPN ribout resolves to EVPN type 5 IPv4");

    test_result(bgp_ribout_generator_init(&gen, sim.ribouts[0]) == 0, "EVPN ribout generator initialization succeeds");
    test_result(bgp_ribout_gen_total_paths(&gen) == 8,
                "EVPN ribout total paths include Ethernet Tag and gateway IP dimensions");

    if (bgp_ribout_generator_has_next(&gen) &&
        bgp_ribout_generator_next(&gen, &path) == 0) {
        test_result(path.has_rd == 1, "EVPN ribout path includes RD");
        test_result(path.has_ethernet_tag == 1, "EVPN ribout path includes Ethernet Tag");
        test_result(path.has_gateway_ip == 1, "EVPN ribout path includes gateway IP");
        test_result(path.ext_comm_len == 24, "EVPN ribout path carries RT, encap, and router-mac ext comms");
    }

    bgp_shutdown_sim(&sim);
}

void test_ribout_no_commands() {
    bgp_sim_t     sim;
    cli_mode_t    mode;
    cli_session_t session;

    memset(&sim, 0, sizeof(sim));
    bgp_init_simulator(&sim);
    mode = CLI_MODE_CONFIG;
    session = (cli_session_t){0};

    CLI_RUN("ribout test1");
    CLI_RUN("prefix 10.0.0.0/24 x 10");
    test_result(sim.ribouts[0]->prefix_spec.count == 10, "Prefix set to 10");
    CLI_RUN("no prefix");
    test_result(sim.ribouts[0]->prefix_spec.count == 0, "Prefix removed (count = 0)");
    bgp_shutdown_sim(&sim);

    memset(&sim, 0, sizeof(sim));
    bgp_init_simulator(&sim);
    mode = CLI_MODE_CONFIG;
    session = (cli_session_t){0};

    CLI_RUN("ribout test2");
    CLI_RUN("path-id 0 1 2 3");
    test_result(sim.ribouts[0]->path_id_count == 4, "Path-IDs set (count = 4)");
    CLI_RUN("no path-id");
    test_result(sim.ribouts[0]->path_id_count == 0, "Path-IDs removed (count = 0)");
    bgp_shutdown_sim(&sim);

    memset(&sim, 0, sizeof(sim));
    bgp_init_simulator(&sim);
    mode = CLI_MODE_CONFIG;
    session = (cli_session_t){0};

    CLI_RUN("ribout test3");
    CLI_RUN("next-hop 192.168.1.1");
    test_result(sim.ribouts[0]->next_hop_spec.count == 1, "Next-hop set (count = 1)");
    CLI_RUN("no next-hop");
    test_result(sim.ribouts[0]->next_hop_spec.count == 0, "Next-hop removed (count = 0)");
    bgp_shutdown_sim(&sim);

    memset(&sim, 0, sizeof(sim));
    bgp_init_simulator(&sim);
    mode = CLI_MODE_CONFIG;
    session = (cli_session_t){0};

    CLI_RUN("ribout test4");
    CLI_RUN("as-path 100 200 300");
    test_result(sim.ribouts[0]->aspath_segment_count == 1, "AS-path set (segment count = 1)");
    CLI_RUN("no as-path");
    test_result(sim.ribouts[0]->aspath_segment_count == 0, "AS-path removed (segment count = 0)");
    bgp_shutdown_sim(&sim);

    memset(&sim, 0, sizeof(sim));
    bgp_init_simulator(&sim);
    mode = CLI_MODE_CONFIG;
    session = (cli_session_t){0};

    CLI_RUN("ribout test5");
    CLI_RUN("localpref 200");
    test_result(sim.ribouts[0]->localpref_spec.value == 200, "Localpref set to 200");
    CLI_RUN("no localpref");
    test_result(sim.ribouts[0]->localpref_spec.value == 100, "Localpref reset to default (100)");
    test_result(sim.ribouts[0]->localpref_spec.mode == BGP_U32_MODE_FIXED, "Localpref type is FIXED");
    bgp_shutdown_sim(&sim);

    memset(&sim, 0, sizeof(sim));
    bgp_init_simulator(&sim);
    mode = CLI_MODE_CONFIG;
    session = (cli_session_t){0};

    CLI_RUN("ribout test6");
    CLI_RUN("origin egp");
    test_result(sim.ribouts[0]->origin == ORIGIN_EGP, "Origin set to EGP");
    CLI_RUN("no origin");
    test_result(sim.ribouts[0]->origin == ORIGIN_IGP, "Origin reset to default (IGP)");
    bgp_shutdown_sim(&sim);

    memset(&sim, 0, sizeof(sim));
    bgp_init_simulator(&sim);
    mode = CLI_MODE_CONFIG;
    session = (cli_session_t){0};

    CLI_RUN("ribout test7");
    CLI_RUN("prefix 10.0.0.0/24 x 100");
    CLI_RUN("path-id 0 1 2");
    CLI_RUN("next-hop 192.168.1.1");
    CLI_RUN("as-path 100 200");
    CLI_RUN("localpref 150");
    CLI_RUN("origin incomplete");

    test_result(sim.ribouts[0]->prefix_spec.count == 100, "All attributes set - prefix count");
    test_result(sim.ribouts[0]->path_id_count == 3, "All attributes set - path-id count");
    test_result(sim.ribouts[0]->localpref_spec.value == 150, "All attributes set - localpref");
    test_result(sim.ribouts[0]->origin == ORIGIN_INCOMPLETE, "All attributes set - origin");

    CLI_RUN("no path-id");
    CLI_RUN("no localpref");

    test_result(sim.ribouts[0]->prefix_spec.count == 100, "Prefix still set after partial removal");
    test_result(sim.ribouts[0]->path_id_count == 0, "Path-IDs removed");
    test_result(sim.ribouts[0]->next_hop_spec.count == 1, "Next-hop still set after partial removal");
    test_result(sim.ribouts[0]->aspath_segment_count == 1, "AS-path still set after partial removal");
    test_result(sim.ribouts[0]->localpref_spec.value == 100, "Localpref reset to default");
    test_result(sim.ribouts[0]->origin == ORIGIN_INCOMPLETE, "Origin still set after partial removal");
    bgp_shutdown_sim(&sim);

    memset(&sim, 0, sizeof(sim));
    bgp_init_simulator(&sim);
    mode = CLI_MODE_CONFIG;
    session = (cli_session_t){0};

    CLI_RUN("ribout test8");
    CLI_RUN("localpref rand(200)");
    test_result(sim.ribouts[0]->localpref_spec.mode == BGP_U32_MODE_RANDOM, "Random localpref type set");
    test_result(sim.ribouts[0]->localpref_spec.value == 200, "Random localpref max value is 200");
    CLI_RUN("no localpref");
    test_result(sim.ribouts[0]->localpref_spec.mode == BGP_U32_MODE_FIXED, "Random localpref reset to FIXED");
    test_result(sim.ribouts[0]->localpref_spec.value == 100, "Random localpref reset to default value");
    bgp_shutdown_sim(&sim);

    memset(&sim, 0, sizeof(sim));
    bgp_init_simulator(&sim);
    mode = CLI_MODE_CONFIG;
    session = (cli_session_t){0};

    CLI_RUN("ribout test9");
    CLI_RUN("as-path 100 { 200 300 } [rand(500) x 10]");
    test_result(sim.ribouts[0]->aspath_segment_count == 3, "Complex AS-path set (3 segments)");
    CLI_RUN("no as-path");
    test_result(sim.ribouts[0]->aspath_segment_count == 0, "Complex AS-path removed");
    bgp_shutdown_sim(&sim);

    memset(&sim, 0, sizeof(sim));
    bgp_init_simulator(&sim);
    mode = CLI_MODE_CONFIG;
    session = (cli_session_t){0};

    CLI_RUN("ribout test10");
    CLI_RUN("rd 65000:100 65000:101");
    test_result(sim.ribouts[0]->rd_count == 2, "RD values set");
    CLI_RUN("no rd");
    test_result(sim.ribouts[0]->rd_count == 0, "RD values removed");
    bgp_shutdown_sim(&sim);

    memset(&sim, 0, sizeof(sim));
    bgp_init_simulator(&sim);
    mode = CLI_MODE_CONFIG;
    session = (cli_session_t){0};

    CLI_RUN("ribout test11");
    CLI_RUN("ethernet-tag 0 100");
    test_result(sim.ribouts[0]->ethernet_tag_count == 2, "Ethernet Tags set");
    CLI_RUN("no ethernet-tag");
    test_result(sim.ribouts[0]->ethernet_tag_count == 0, "Ethernet Tags removed");
    bgp_shutdown_sim(&sim);

    memset(&sim, 0, sizeof(sim));
    bgp_init_simulator(&sim);
    mode = CLI_MODE_CONFIG;
    session = (cli_session_t){0};

    CLI_RUN("ribout test12");
    CLI_RUN("gateway-ip 10.255.0.1 x 4");
    test_result(sim.ribouts[0]->gateway_ip_spec.count == 4, "Gateway IPs set");
    CLI_RUN("no gateway-ip");
    test_result(sim.ribouts[0]->gateway_ip_spec.count == 0, "Gateway IPs removed");
    bgp_shutdown_sim(&sim);

    memset(&sim, 0, sizeof(sim));
    bgp_init_simulator(&sim);
    mode = CLI_MODE_CONFIG;
    session = (cli_session_t){0};

    CLI_RUN("ribout test13");
    CLI_RUN("esi 00:00:00:00:00:00:00:00:00:01");
    test_result(sim.ribouts[0]->esi_count == 1, "ESI values set");
    CLI_RUN("no esi");
    test_result(sim.ribouts[0]->esi_count == 0, "ESI values removed");
    bgp_shutdown_sim(&sim);

    memset(&sim, 0, sizeof(sim));
    bgp_init_simulator(&sim);
    mode = CLI_MODE_CONFIG;
    session = (cli_session_t){0};

    CLI_RUN("ribout test14");
    CLI_RUN("med 50");
    test_result(sim.ribouts[0]->med_spec.enabled == 1, "MED enabled");
    CLI_RUN("no med");
    test_result(sim.ribouts[0]->med_spec.enabled == 0, "MED removed");
    bgp_shutdown_sim(&sim);

    memset(&sim, 0, sizeof(sim));
    bgp_init_simulator(&sim);
    mode = CLI_MODE_CONFIG;
    session = (cli_session_t){0};

    CLI_RUN("ribout test15");
    CLI_RUN("rt 65000:100");
    CLI_RUN("rt 65000:101");
    test_result(sim.ribouts[0]->rt_count == 2, "RT values set");
    CLI_RUN("no rt");
    test_result(sim.ribouts[0]->rt_count == 0, "RT values removed");
    bgp_shutdown_sim(&sim);

    memset(&sim, 0, sizeof(sim));
    bgp_init_simulator(&sim);
    mode = CLI_MODE_CONFIG;
    session = (cli_session_t){0};

    CLI_RUN("ribout test16");
    CLI_RUN("rt-set [65000:100] [65000:200,65000:201]");
    test_result(sim.ribouts[0]->rt_set_count == 2, "RT sets set");
    CLI_RUN("no rt-set");
    test_result(sim.ribouts[0]->rt_set_count == 0, "RT sets removed");
    bgp_shutdown_sim(&sim);

    memset(&sim, 0, sizeof(sim));
    bgp_init_simulator(&sim);
    mode = CLI_MODE_CONFIG;
    session = (cli_session_t){0};

    CLI_RUN("ribout test17");
    CLI_RUN("soo 65000:9");
    test_result(sim.ribouts[0]->soo_count == 1, "SoO values set");
    CLI_RUN("no soo");
    test_result(sim.ribouts[0]->soo_count == 0, "SoO values removed");
    bgp_shutdown_sim(&sim);

    memset(&sim, 0, sizeof(sim));
    bgp_init_simulator(&sim);
    mode = CLI_MODE_CONFIG;
    session = (cli_session_t){0};

    CLI_RUN("ribout test18");
    CLI_RUN("prefix 10.0.0.0/24");
    CLI_RUN("rd 65000:100");
    CLI_RUN("label 30000");
    CLI_RUN("encap vxlan");
    CLI_RUN("router-mac 02:00:00:00:00:01");
    test_result(sim.ribouts[0]->encap_count == 1, "encap values set");
    test_result(sim.ribouts[0]->router_mac_count == 1, "router-mac values set");
    CLI_RUN("no encap");
    CLI_RUN("no router-mac");
    test_result(sim.ribouts[0]->encap_count == 0, "encap values removed");
    test_result(sim.ribouts[0]->router_mac_count == 0, "router-mac values removed");
    bgp_shutdown_sim(&sim);
}

/*
 * community / large-community through the CLI: typed lines append, a bad line changes nothing, long bracketed sets
 * (more than 63 characters in one token) are accepted, show ribout lists the sets as written and the preview shows the
 * set of each path.
 */
void test_community_ribout_cli() {
    bgp_sim_t            sim = {0};
    cli_mode_t           mode = CLI_MODE_CONFIG;
    cli_session_t        session = {0};
    bgp_ribout_config_t *block;
    char                 stdout_buf[16384];
    char                 line[1024];
    int                  len;

    bgp_init_simulator(&sim);
    CLI_RUN("ribout tagged");
    block = bgp_sim_find_ribout(&sim, "tagged");
    CLI_RUN("prefix 10.1.0.0/24 x 4");
    CLI_RUN("next-hop 192.0.2.1");
    test_result(CLI_RUN("community [65000:1,no-export] 65000:100 x 2") == 0 &&
                CLI_RUN("large-community [65000:1:10] x 2") == 0,
                "community and large-community lines are accepted");
    test_result(CLI_RUN("community 65000:5 70000:1") != 0 && block->community_group_count == 2,
                "A line with a bad value is rejected and adds no set");
    len = snprintf(line, sizeof(line), "large-community [");
    for (int i = 0; i < MAX_LARGE_COMMUNITIES_PER_SET; i++) {
        len += snprintf(line + len, sizeof(line) - (size_t)len, "%s4294967295:4294967295:%d", i ? "," : "", i);
    }
    snprintf(line + len, sizeof(line) - (size_t)len, "]");
    test_result(CLI_RUN(line) == 0 &&
                block->large_community_group_count == 2 &&
                block->large_community_groups[1].count == MAX_LARGE_COMMUNITIES_PER_SET,
                "A set of 16 large communities (one token of ~400 characters) is accepted");
    CLI_RUN("no large-community");
    CLI_RUN("large-community [65000:1:10] x 2");
    CLI_RUN("exit");

    mode = CLI_MODE_EXEC;
    test_capture_command(&sim, &session, &mode, "show ribout tagged", stdout_buf, sizeof(stdout_buf), NULL, 0);
    test_result(strstr(stdout_buf, "Communities:       [65000:1,no-export] 65000:100 x 2 (3 sets, rotating)") &&
                strstr(stdout_buf, "Large Communities: 65000:1:10 x 2 (2 sets, rotating)"),
                "show ribout lists the sets as written, well-known values by name, with the set count");
    test_capture_command(&sim, &session, &mode, "show ribout tagged preview", stdout_buf, sizeof(stdout_buf), NULL, 0);
    test_result(strstr(stdout_buf, "comm") &&
                strstr(stdout_buf, "lcomm") &&
                strstr(stdout_buf, "65000:1,no-export") &&
                strstr(stdout_buf, "65000:101") &&
                strstr(stdout_buf, "65000:1:11"),
                "The preview shows the community and large-community set of each path");

    mode = CLI_MODE_CONFIG;
    CLI_RUN("ribout tagged");
    CLI_RUN("no community");
    CLI_RUN("no large-community");
    test_result(block->community_group_count == 0 && block->large_community_group_count == 0,
                "no community / no large-community clear every set");
    test_capture_command(&sim, &session, &mode, "community ?", stdout_buf, sizeof(stdout_buf), NULL, 0);
    test_result(strstr(stdout_buf, "x <count>") != NULL, "community ? describes the set syntax");
    bgp_shutdown_sim(&sim);
}

/*
 * rotate on the key lists through the CLI: show ribout marks rotating lists and counts the paths without them; a
 * misplaced or empty rotate is rejected and leaves the block as it was.
 */
void test_key_rotation_ribout_cli() {
    bgp_sim_t            sim = {0};
    cli_mode_t           mode = CLI_MODE_CONFIG;
    cli_session_t        session = {0};
    bgp_ribout_config_t *block;
    char                 stdout_buf[16384];

    bgp_init_simulator(&sim);
    CLI_RUN("ribout policies");
    block = bgp_sim_find_ribout(&sim, "policies");
    test_result(CLI_RUN("distinguisher rotate 5 x 4") == 0 &&
                CLI_RUN("color rotate 100 x 4") == 0 &&
                CLI_RUN("endpoint 10.0.0.1 x 8") == 0 &&
                CLI_RUN("path-id rotate 7 x 2") == 0 &&
                CLI_RUN("segment-list 1 weight 10 mpls 16001") == 0 &&
                CLI_RUN("rt 192.0.2.1:100") == 0,
                "SR Policy rotate lines are accepted");
    test_result(CLI_RUN("color 100 rotate") != 0 &&
                CLI_RUN("color rotate") != 0 &&
                CLI_RUN("endpoint rotatex 10.0.0.1") != 0 &&
                CLI_RUN("path-id 1 rotate") != 0 &&
                block->color_count == 4 &&
                block->color_rotate &&
                block->path_id_count == 2 &&
                block->path_id_rotate &&
                block->endpoint_spec.count == 8 &&
                !block->endpoint_rotate,
                "Misplaced or empty rotate is rejected; the lists and flags stay");
    CLI_RUN("exit");

    mode = CLI_MODE_EXEC;
    test_capture_command(&sim, &session, &mode, "show ribout policies", stdout_buf, sizeof(stdout_buf), NULL, 0);
    test_result(strstr(stdout_buf, "Distinguishers:    rotate 5 x 4") &&
                strstr(stdout_buf, "Colors:            rotate") &&
                strstr(stdout_buf, "Path-IDs:          rotate 7 x 2") &&
                strstr(stdout_buf, "Endpoints:         10.0.0.1 x 8") &&
                strstr(stdout_buf, "Total Paths:       8"),
                "show ribout marks the rotating lists; 8 endpoints make 8 policies");
    test_capture_command(&sim, &session, &mode, "show ribout", stdout_buf, sizeof(stdout_buf), NULL, 0);
    test_result(strstr(stdout_buf, "policies") && strstr(stdout_buf, "8              ") != NULL,
                "The summary counts the rotating path IDs once");

    mode = CLI_MODE_CONFIG;
    CLI_RUN("ribout tags");
    CLI_RUN("prefix 172.16.0.0/24 x 6");
    CLI_RUN("rd rotate 65551:1 x 3");
    CLI_RUN("label 10");
    test_result(CLI_RUN("ethernet-tag rotate 100 x 3") == 0 &&
                sim.ribouts[1]->ethernet_tag_rotate &&
                bgp_ribout_total_paths(sim.ribouts[1]) == 6,
                "ethernet-tag rotate: 6 routes");
    CLI_RUN("exit");
    CLI_RUN("ribout rules");
    CLI_RUN("address-family ipv4 flowspec");
    CLI_RUN("prefix 10.60.0.0/24 x 2");
    test_result(CLI_RUN("dst-port rotate 80 x 3") == 0 &&
                CLI_RUN("protocol rotate each(6, 17)") == 0 &&
                CLI_RUN("dst-port rotate") != 0 &&
                sim.ribouts[2]->flowspec->components[FLOWSPEC_DEST_PORT].rotate,
                "FlowSpec component rotate; rotate with nothing after it is rejected");
    CLI_RUN("exit");
    mode = CLI_MODE_EXEC;
    test_capture_command(&sim, &session, &mode, "show ribout rules", stdout_buf, sizeof(stdout_buf), NULL, 0);
    test_result(strstr(stdout_buf, "dst-port rotate 80 x 3") &&
                strstr(stdout_buf, "protocol rotate each(6, 17)") &&
                strstr(stdout_buf, "Total Paths:       2"),
                "show ribout lists the rotating components; 2 rules");
    bgp_shutdown_sim(&sim);
}

static void test_template_show(void) {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};
    int ok = CLI_RUN("ribout inclusive") == 0 &&
             CLI_RUN("nlri evpn type3 rd 65000:1 ethernet-tag 1 router 192.0.2.1 x 3") == 0 &&
             CLI_RUN("pmsi flags 0 type 6 label 1000 id c0000201") == 0 && CLI_RUN("end") == 0;
    char text[8192];
    CLI_SHOW("show ribout inclusive");
    ok &= strstr(text, "evpn-type3") && strstr(text, "router 192.0.2.1 x 3") &&
          strstr(text, "pmsi flags 0 type 6 label 1000 id c0000201") &&
          strstr(text, "Total Paths:       3");
    CLI_SHOW("show ribout inclusive preview 3");
    ok &= strstr(text, "router=192.0.2.1") && strstr(text, "router=192.0.2.2") &&
          strstr(text, "router=192.0.2.3");
    bgp_shutdown_sim(&sim);
    test_result(ok, "Template detail and preview expose configured fields and stepped router identities");
}

static void test_path_attribute_show(void) {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};
    int ok = CLI_RUN("ribout attrs") == 0 && CLI_RUN("prefix 10.0.0.0/24 x 4") == 0 &&
             CLI_RUN("next-hop 192.0.2.1") == 0 && CLI_RUN("aggregator 65010 192.0.2.9") == 0 &&
             CLI_RUN("atomic-aggregate") == 0 && CLI_RUN("originator-id 10.0.0.1") == 0 &&
             CLI_RUN("cluster-list 10.0.0.2 3") == 0 && CLI_RUN("aigp 1000 x 4") == 0 && CLI_RUN("otc 65001") == 0 &&
             CLI_RUN("prefix-sid srgb range 16000 8000") == 0 && CLI_RUN("prefix-sid index 100 x 4") == 0 &&
             CLI_RUN("attribute type 99 value dead") == 0 && sim.ribouts[0]->path_attr_count == 9;
    // A malformed line changes nothing; a line of the same attribute replaces; `no` removes one attribute.
    ok &= CLI_RUN("aggregator 65010") != 0 && CLI_RUN("prefix-sid no-such 1") != 0 && CLI_RUN("atomic-aggregate 1") != 0 &&
          sim.ribouts[0]->path_attr_count == 9;
    ok &= CLI_RUN("otc 65002") == 0 && CLI_RUN("no cluster-list") == 0 && sim.ribouts[0]->path_attr_count == 8 &&
          CLI_RUN("end") == 0 && bgp_ribout_generate(sim.ribouts[0]) == BGP_RIBOUT_GENERATED;
    char text[8192];
    CLI_SHOW("show ribout attrs");
    ok &= strstr(text, "Path attribute:    atomic-aggregate (type 6)") && strstr(text, "aggregator 65010 192.0.2.9 (type 7)") &&
          strstr(text, "aigp 1000 x 4 (type 26)") && strstr(text, "otc 65002 (type 35)") &&
          strstr(text, "prefix-sid index 100 x 4 (type 40)") && strstr(text, "attribute type 99 value dead (type 99)") &&
          !strstr(text, "cluster-list") && !strstr(text, "otc 65001") && strstr(text, "Message Count:     4");
    // Running-config lists the lines in type order, the TLVs of the Prefix-SID in the order of their types.
    CLI_SHOW("show running-config");
    ok &= strstr(text, "\n  atomic-aggregate\n  aggregator 65010 192.0.2.9\n  originator-id 10.0.0.1\n  aigp 1000 x 4\n"
                       "  otc 65002\n  prefix-sid index 100 x 4\n  prefix-sid srgb range 16000 8000\n"
                       "  attribute type 99 value dead\n") != NULL;
    bgp_shutdown_sim(&sim);
    test_result(ok, "Path attribute lines: edit, replace, clear, detail and running-config");
}

/*
 * `message-size <octets>`: 3000 /24 routes of one attribute group are 12000 octets of NLRI. They need three UPDATEs
 * of 4096 octets, one of 65535, and with 21 octets of attributes 600 UPDATEs of 64 (five routes in each).
 */
/*
 * The confederation segments of `as-path` come back from running-config in the form they are entered in, and the
 * route preview shows them with the same brackets. (`show ribout-map <name>` has nothing to show after generation:
 * the grouped map is freed once the UPDATEs are built.)
 */
static void test_as_path_confederation_show(void) {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};
    char          text[8192];
    int ok = CLI_RUN("ribout confed") == 0 && CLI_RUN("prefix 10.0.0.0/24 x 2") == 0 &&
             CLI_RUN("next-hop 192.0.2.1") == 0 &&
             CLI_RUN("as-path (64512 64513) [64514 64515] 65001 {65002 65003}") == 0 &&
             // A malformed line changes nothing.
             CLI_RUN("as-path ( 1 2") != 0 && CLI_RUN("as-path [ ]") != 0 && CLI_RUN("end") == 0 &&
             bgp_ribout_generate(sim.ribouts[0]) == BGP_RIBOUT_GENERATED;
    CLI_SHOW("show running-config");
    ok &= strstr(text, "\n  as-path ( 64512 64513 ) [ 64514 64515 ] 65001 { 65002 65003 }\n") != NULL;
    CLI_SHOW("show ribout confed preview 1");
    ok &= strstr(text, "(64512 64513) [64514 64515] 65001 {65002 65003}") != NULL;
    bgp_shutdown_sim(&sim);
    test_result(ok, "as-path confederation segments: running-config and preview");
}

/*
 * `as-path two-byte` through the command table: the word comes back in running-config, `show ribout` names the form
 * on the path and on the snapshot, and the path alone returns to four octets.
 */
static void test_as_path_two_byte_show(void) {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};
    char          text[8192];
    int ok = CLI_RUN("ribout old") == 0 && CLI_RUN("prefix 10.0.0.0/24 x 2") == 0 && CLI_RUN("next-hop 192.0.2.1") == 0 &&
             CLI_RUN("as-path two-byte 65001 70000 {65002}") == 0 && CLI_RUN("as-path 65001 two-byte") != 0 &&
             CLI_RUN("end") == 0 && bgp_ribout_generate(sim.ribouts[0]) == BGP_RIBOUT_GENERATED;
    test_result(ok, "as-path two-byte is accepted; the word after an AS is refused");
    CLI_SHOW("show running-config");
    test_result(strstr(text, "\n  as-path two-byte 65001 70000 { 65002 }\n") != NULL, "as-path two-byte in running-config");
    CLI_SHOW("show ribout old");
    test_result(strstr(text, "AS-Path:           65001 70000 {65002} (two-byte)\n") != NULL &&
                    strstr(text, "(ipv4-unicast, add-path off, classic, two-octet AS)\n") != NULL,
                "the two-byte form on the path and on the snapshot in show ribout");
    // The word alone: an empty path in that form.
    ok = CLI_RUN("config") == 0 && CLI_RUN("ribout old") == 0 && CLI_RUN("as-path two-byte") == 0 && CLI_RUN("end") == 0 &&
         bgp_ribout_generate(sim.ribouts[0]) == BGP_RIBOUT_GENERATED;
    CLI_SHOW("show running-config");
    test_result(ok && strstr(text, "\n  as-path two-byte\n") != NULL, "an empty two-byte path in running-config");
    CLI_SHOW("show ribout old");
    test_result(strstr(text, "AS-Path:           unset (two-byte)\n") != NULL, "an empty two-byte path in show ribout");
    // A path without the word, then `no as-path`.
    ok = CLI_RUN("config") == 0 && CLI_RUN("ribout old") == 0 && CLI_RUN("as-path 65001 70000") == 0 && CLI_RUN("end") == 0 &&
         bgp_ribout_generate(sim.ribouts[0]) == BGP_RIBOUT_GENERATED;
    CLI_SHOW("show running-config");
    test_result(ok && strstr(text, "\n  as-path 65001 70000\n") != NULL && !strstr(text, "two-byte"),
                "a path without the word replaces the two-byte one");
    CLI_SHOW("show ribout old");
    test_result(strstr(text, "AS-Path:           65001 70000\n") != NULL && !strstr(text, "two-octet AS"),
                "the four-octet form in show ribout");
    ok = CLI_RUN("config") == 0 && CLI_RUN("ribout old") == 0 && CLI_RUN("as-path two-byte 65001") == 0 &&
         CLI_RUN("no as-path") == 0 && CLI_RUN("end") == 0;
    CLI_SHOW("show running-config");
    test_result(ok && !strstr(text, "as-path"), "no as-path removes the path and the form");
    bgp_shutdown_sim(&sim);
}

static void test_localpref_none_show(void) {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};
    char          text[8192];
    int ok = CLI_RUN("ribout ext") == 0 && CLI_RUN("prefix 10.0.0.0/24 x 2") == 0 && CLI_RUN("next-hop 192.0.2.1") == 0 &&
             CLI_RUN("localpref none") == 0 && CLI_RUN("localpref none 1") != 0 && CLI_RUN("end") == 0 &&
             bgp_ribout_generate(sim.ribouts[0]) == BGP_RIBOUT_GENERATED;
    test_result(ok, "localpref none is accepted; none with a value is refused");
    CLI_SHOW("show running-config");
    test_result(strstr(text, "\n  localpref none\n") != NULL, "localpref none in running-config");
    CLI_SHOW("show ribout ext");
    test_result(strstr(text, "Local Preference:  none\n") != NULL, "localpref none in show ribout");
    // The lp column: three wide for the default of 100, then the two spaces between columns.
    CLI_SHOW("show ribout ext preview 1");
    test_result(strstr(text, "10.0.0.0/24  192.0.2.1  -    igp") != NULL, "localpref none in the preview");
    // A value replaces it; `no localpref` returns to the default of 100.
    ok = CLI_RUN("config") == 0 && CLI_RUN("ribout ext") == 0 && CLI_RUN("localpref 300") == 0 && CLI_RUN("end") == 0;
    CLI_SHOW("show running-config");
    test_result(ok && strstr(text, "\n  localpref 300\n") != NULL && !strstr(text, "localpref none"),
                "a value replaces localpref none");
    ok = CLI_RUN("config") == 0 && CLI_RUN("ribout ext") == 0 && CLI_RUN("localpref none") == 0 &&
         CLI_RUN("no localpref") == 0 && CLI_RUN("end") == 0 && bgp_ribout_generate(sim.ribouts[0]) == BGP_RIBOUT_GENERATED;
    CLI_SHOW("show running-config");
    test_result(ok && strstr(text, "\n  localpref 100\n") != NULL && !strstr(text, "localpref none"),
                "no localpref returns running-config to the default of 100");
    CLI_SHOW("show ribout ext");
    test_result(strstr(text, "Local Preference:  100\n") != NULL, "no localpref returns to 100");
    bgp_shutdown_sim(&sim);
}

/*
 * The extended community lines through the command table: the bare `default-gateway`, running-config in the fixed
 * order of the lines, the octets of each in `show ribout`, and the `no` forms.
 */
static void test_extended_community_lines_show(void) {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};
    char          text[8192];
    int ok = CLI_RUN("ribout mac") == 0 && CLI_RUN("rd 65000:100") == 0 && CLI_RUN("mac 00:00:5e:00:53:01") == 0 &&
             CLI_RUN("ethernet-tag 0") == 0 && CLI_RUN("label 100") == 0 && CLI_RUN("rt 65000:100") == 0 &&
             CLI_RUN("encap vxlan") == 0 && CLI_RUN("next-hop 192.0.2.1") == 0 &&
             CLI_RUN("ext-community 4300000000000007 80061234DEADBEEF") == 0 && CLI_RUN("default-gateway") == 0 &&
             CLI_RUN("mac-mobility 5 sticky") == 0 && CLI_RUN("link-bandwidth 65001 10g") == 0 &&
             CLI_RUN("default-gateway yes") != 0 && CLI_RUN("mac-mobility") != 0 && CLI_RUN("ext-community 43") != 0 &&
             CLI_RUN("end") == 0 && bgp_ribout_generate(sim.ribouts[0]) == BGP_RIBOUT_GENERATED;
    test_result(ok, "the four extended community lines are accepted; malformed ones are refused");
    CLI_SHOW("show running-config");
    test_result(strstr(text, "\n  link-bandwidth 65001 10g\n  mac-mobility 5 sticky\n  default-gateway\n"
                             "  ext-community 4300000000000007 80061234DEADBEEF\n") != NULL,
                "the extended community lines in running-config");
    CLI_SHOW("show ribout mac");
    test_result(strstr(text, "Ext community:     link-bandwidth 65001 10g (4004fde94e9502f9)\n"
                             "                   mac-mobility 5 sticky (0600010000000005)\n"
                             "                   default-gateway (030d000000000000)\n"
                             "                   ext-community 4300000000000007 80061234DEADBEEF "
                             "(4300000000000007 80061234deadbeef)\n") != NULL,
                "each extended community line with its octets in show ribout");
    // `no` takes the bare keyword and removes that line only.
    ok = CLI_RUN("config") == 0 && CLI_RUN("ribout mac") == 0 && CLI_RUN("no mac-mobility") == 0 &&
         CLI_RUN("no ext-community") == 0 && CLI_RUN("end") == 0;
    CLI_SHOW("show running-config");
    test_result(ok && strstr(text, "\n  link-bandwidth 65001 10g\n  default-gateway\n") != NULL &&
                    !strstr(text, "mac-mobility") && !strstr(text, "ext-community"),
                "no mac-mobility and no ext-community leave the other two lines");
    ok = CLI_RUN("config") == 0 && CLI_RUN("ribout mac") == 0 && CLI_RUN("no default-gateway") == 0 &&
         CLI_RUN("no link-bandwidth") == 0 && CLI_RUN("end") == 0;
    CLI_SHOW("show running-config");
    test_result(ok && !strstr(text, "default-gateway") && !strstr(text, "link-bandwidth"),
                "no default-gateway and no link-bandwidth remove the last two lines");
    CLI_SHOW("show ribout mac");
    test_result(strstr(text, "Family:") != NULL && !strstr(text, "Ext community:"),
                "show ribout has no extended community row without a line");
    bgp_shutdown_sim(&sim);
}

static void test_message_size_show(void) {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};
    char          text[8192];
    char          errors[1024];
    int ok = CLI_RUN("ribout big") == 0 && CLI_RUN("prefix 10.0.0.0/24 x 3000") == 0 && CLI_RUN("next-hop 192.0.2.1") == 0;
    // A value outside 64-65535, a word, or a second value changes nothing.
    ok &= CLI_RUN("message-size 63") != 0 && CLI_RUN("message-size 65536") != 0 && CLI_RUN("message-size big") != 0 &&
          CLI_RUN("message-size 9000 1") != 0 && sim.ribouts[0]->message_size == 0 && CLI_RUN("end") == 0;
    CLI_SHOW("update generate");
    CLI_SHOW("show ribout big");
    ok &= strstr(text, "Message Count:     3\n") && !strstr(text, "Message size:") &&
          strstr(text, "(ipv4-unicast, add-path off, classic)");

    static const struct {
        const char *line;
        const char *shown;
        const char *count;
        const char *profile;
    } sizes[] = {
        {"message-size 65535", "Message size:      65535 octets (Extended Message)\n", "Message Count:     1\n",
         "(ipv4-unicast, add-path off, classic, extended-message)"},
        {"message-size 4097", "Message size:      4097 octets (Extended Message)\n", "Message Count:     3\n",
         "(ipv4-unicast, add-path off, classic, extended-message)"},
        {"message-size 4096", "Message size:      4096 octets\n", "Message Count:     3\n",
         "(ipv4-unicast, add-path off, classic)"},
        {"message-size 64", "Message size:      64 octets\n", "Message Count:     600\n",
         "(ipv4-unicast, add-path off, classic)"},
    };
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        char saved[64];

        ok &= CLI_RUN("config") == 0 && CLI_RUN("ribout big") == 0 && CLI_RUN(sizes[i].line) == 0 && CLI_RUN("end") == 0;
        CLI_SHOW("update generate");
        CLI_SHOW("show ribout big");
        ok &= strstr(text, sizes[i].shown) && strstr(text, sizes[i].count) && strstr(text, sizes[i].profile) &&
              strstr(text, "Total Paths:       3000");
        snprintf(saved, sizeof(saved), "\n  %s\n", sizes[i].line);
        CLI_SHOW("show running-config");
        ok &= strstr(text, saved) != NULL;
    }
    // Ten ASes make 63 octets of attributes: with the 23 of an UPDATE and one route they do not fit 64 octets.
    ok &= CLI_RUN("config") == 0 && CLI_RUN("ribout big") == 0 && CLI_RUN("as-path 1 2 3 4 5 6 7 8 9 10") == 0 &&
          CLI_RUN("end") == 0;
    test_capture_command(&sim, &session, &mode, "update generate", text, sizeof(text), errors, sizeof(errors));
    ok &= strstr(text, "ribout big: Message generation failed") &&
          strstr(errors, "Error: ribout big: the path attributes and one route do not fit an UPDATE of 64 octets "
                         "(message-size)\n");
    // `no message-size` returns to 4096, where they fit.
    ok &= CLI_RUN("config") == 0 && CLI_RUN("ribout big") == 0 && CLI_RUN("no message-size") == 0 &&
          sim.ribouts[0]->message_size == 0 && CLI_RUN("end") == 0;
    test_capture_command(&sim, &session, &mode, "update generate", text, sizeof(text), errors, sizeof(errors));
    ok &= !strstr(text, "failed") && errors[0] == '\0';
    CLI_SHOW("show ribout big");
    ok &= strstr(text, "Message Count:     3\n") && !strstr(text, "Message size:");
    CLI_SHOW("show running-config");
    ok &= !strstr(text, "message-size");
    bgp_shutdown_sim(&sim);
    test_result(ok, "message-size: range, UPDATE counts at 4096, 65535 and 64 octets, the too-small error, and the no form");
}

static void test_bgpls_show(void) {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    cli_mode_t    mode = CLI_MODE_CONFIG;
    cli_session_t session = {0};
    int ok = CLI_RUN("ribout links") == 0 &&
             CLI_RUN("nlri bgp-ls link protocol isis-l2 identifier 0 local-as 65000 local-router 0000.0000.0001 "
                     "remote-as 65000 remote-router 0000.0000.0002 local-ip 10.0.0.1 remote-ip 10.0.0.2 "
                     "step node x 3") == 0 &&
             CLI_RUN("ls te-metric 100") == 0 && CLI_RUN("ls adj-sid flags v,l label 24001 x 3") == 0 &&
             CLI_RUN("ls srv6-endx-sid fc00:0:1:e001::/64 behavior end.x flags b structure 32 16 16 0 x 3") == 0 &&
             CLI_RUN("next-hop 192.0.2.1") == 0;
    // A malformed line changes nothing. A line of another NLRI type is kept, like any family attribute, and stops
    // generation until it is removed; `no ls` clears every line.
    ok &= CLI_RUN("ls te-metric") != 0 && CLI_RUN("ls no-such-tlv 1") != 0 && sim.ribouts[0]->ls_attr_count == 3 &&
          bgp_ribout_generate(sim.ribouts[0]) == BGP_RIBOUT_GENERATED;
    ok &= CLI_RUN("ls node-name r1") == 0 && bgp_ribout_generate(sim.ribouts[0]) != BGP_RIBOUT_GENERATED;
    ok &= CLI_RUN("no ls") == 0 && sim.ribouts[0]->ls_attr_count == 0 && CLI_RUN("ls te-metric 100") == 0 &&
          CLI_RUN("ls adj-sid flags v,l label 24001 x 3") == 0 && CLI_RUN("ls igp-metric 10 per node") == 0 &&
          CLI_RUN("ls-attribute type 65000 value dead") == 0 && CLI_RUN("end") == 0 &&
          bgp_ribout_generate(sim.ribouts[0]) == BGP_RIBOUT_GENERATED;
    char text[8192];
    CLI_SHOW("show ribout links");
    ok &= strstr(text, "Family:            bgp-ls") && strstr(text, "BGP-LS attribute:  te-metric 100 (TLV 1092)") &&
          strstr(text, "adj-sid flags v,l label 24001 x 3 (TLV 1099)") &&
          strstr(text, "igp-metric 10 per node (TLV 1095)") &&
          strstr(text, "raw type 65000 value dead (TLV 65000)") && !strstr(text, "srv6-endx-sid") &&
          strstr(text, "Total Paths:       3") && strstr(text, "Message Count:     3");
    CLI_SHOW("show ribout links preview 3");
    ok &= strstr(text, "bgp-ls type2 node=000000000001") && strstr(text, "bgp-ls type2 node=000000000002") &&
          strstr(text, "bgp-ls type2 node=000000000003");
    CLI_SHOW("show running-config");
    ok &= strstr(text, "\n  ls te-metric 100\n  ls igp-metric 10 per node\n  ls adj-sid flags v,l label 24001 x 3\n"
                       "  ls raw type 65000 value dead\n") != NULL;
    bgp_shutdown_sim(&sim);
    test_result(ok, "BGP-LS attribute lines: edit, clear, detail, preview and running-config");
}

int main() {
    test_template_show();
    test_bgpls_show();
    test_path_attribute_show();
    test_message_size_show();
    test_as_path_confederation_show();
    test_as_path_two_byte_show();
    test_extended_community_lines_show();
    test_localpref_none_show();
    printf("BGP RIB-OUT CLI Interactive Configuration Tests\n");
    printf("================================================\n\n");

    // Run all tests
    test_create_ribout();
    test_router_mac_rejects_multicast_and_broadcast();
    test_add_prefix();
    test_add_prefix_default_count();
    test_add_path_ids();
    test_add_single_path_id();
    test_add_labels();
    test_add_label_sequence();
    test_add_next_hop_ip();
    test_add_next_hop_prefix();
    test_add_next_hop_link_local();
    test_add_aspath_sequence();
    test_add_aspath_set();
    test_add_aspath_random();
    test_add_localpref_fixed();
    test_add_localpref_random();
    test_scalar_range_controls();
    test_add_origin_igp();
    test_add_origin_egp();
    test_add_origin_incomplete();
    test_create_complete_ribout();
    test_create_multiple_ribouts();
    test_delete_ribout();
    test_delete_nonexistent_ribout();
    test_attributes_without_ribout();
    test_attributes_apply_to_recent();
    test_ipv6_prefix();
    test_max_ribouts_limit();
    test_show_ribout_exec();
    test_show_ribout_preview_formatting();
    test_srpolicy_ribout_tokens();
    test_srpolicy_random_controls();
    test_show_ribout_preview_srpolicy_formatting();
    test_flowspec_ribout_tokens();
    test_flowspec_ribout_rejects_bad_input();
    test_show_ribout_preview_flowspec_formatting();
    test_color_community_ribout_cli();
    test_community_ribout_cli();
    test_key_rotation_ribout_cli();
    test_show_ribout_snapshot_status();
    test_evpn_type2_ribout_tokens();
    test_evpn_identifier_shorthand_forms();
    test_sequence_shorthand_forms();
    test_show_ribout_preview_evpn_type2_formatting();
    test_generator_integration();
    test_vpn_ribout_tokens();
    test_evpn_ribout_tokens();
    test_ribout_no_commands();

    // Print summary
    printf("\n================================================\n");
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    printf("================================================\n");

    return (tests_failed == 0) ? 0 : 1;
}
