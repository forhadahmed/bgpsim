#include "test_wire.h"
#include "test_result.h"

/*
 * Literal bytes make the shared oracle testable without using any encoder.
 */
static const uint8_t origin_update[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x1b, 0x02, 0x00, 0x00, 0x00, 0x04, 0x40, 0x01, 0x01, 0x00
};

int main(void) {
    const uint8_t *value = NULL;
    uint16_t       length = 0;
    uint8_t        flags = 0;
    test_result(test_wire_find_attr(origin_update, sizeof(origin_update), 1, &value, &length, &flags) &&
                value == origin_update + 26 && length == 1 && flags == 0x40 && *value == 0,
                "Independent literal UPDATE decodes exact ORIGIN bytes and flags");
    int passed = 1;
    for (size_t size = 0; size < sizeof(origin_update); size++) {
        passed &= !test_wire_find_attr(origin_update, size, 1, NULL, NULL, NULL);
    }
    test_result(passed, "Every physical truncation is rejected by the shared wire reader");
    test_result(test_wire_path_attr_len(origin_update, sizeof(origin_update)) == 4 &&
                test_wire_withdrawn_len(origin_update, sizeof(origin_update)) == 0,
                "Bounded length readers distinguish a present attribute from empty withdrawals");
    passed = 1;
    for (size_t size = 0; size < sizeof(origin_update); size++) {
        passed &= test_wire_path_attr_len(origin_update, size) == -1 &&
                  test_wire_withdrawn_len(origin_update, size) == -1;
    }
    test_result(passed && test_wire_path_attr_len(NULL, 27) == -1 &&
                test_wire_withdrawn_len(NULL, 27) == -1,
                "Truncated or null fields never masquerade as valid empty lengths");
    uint8_t bad[32];
    passed = 1;
    for (unsigned declared = 0; declared < 256; declared++) {
        memcpy(bad, origin_update, sizeof(origin_update));
        bad[17] = declared;
        if (declared != sizeof(origin_update)) {
            passed &= !test_wire_find_attr(bad, sizeof(origin_update), 1, NULL, NULL, NULL) &&
                      test_wire_path_attr_len(bad, sizeof(origin_update)) == -1;
        }
    }
    test_result(passed, "Declared message lengths cannot substitute for the physical buffer size");
    memcpy(bad, origin_update, sizeof(origin_update));
    bad[0] = 0;
    passed = !test_wire_find_attr(bad, sizeof(origin_update), 1, NULL, NULL, NULL);
    memcpy(bad, origin_update, sizeof(origin_update));
    bad[18] = BGP_MSG_KEEPALIVE;
    test_result(passed && !test_wire_find_attr(bad, sizeof(origin_update), 1, NULL, NULL, NULL),
                "Attribute readers reject non-UPDATE framing and invalid markers");
    memcpy(bad, origin_update, sizeof(origin_update));
    bad[16] = 0;
    bad[17] = sizeof(bad);
    bad[22] = 9;
    bad[27] = 0x50;
    bad[28] = 2;
    bad[29] = 0xff;
    bad[30] = 0xff;
    bad[31] = 0;
    test_result(!test_wire_find_attr(bad, sizeof(bad), 1, NULL, NULL, NULL),
                "Malformed trailing attributes cannot hide behind an earlier matching attribute");
    memcpy(bad, origin_update, sizeof(origin_update));
    bad[17] = 31;
    bad[22] = 8;
    memcpy(bad + 27, origin_update + 23, 4);
    test_result(!test_wire_find_attr(bad, 31, 1, NULL, NULL, NULL), "Duplicate target attributes are rejected");
    memcpy(bad, origin_update, sizeof(origin_update));
    passed = 1;
    for (unsigned size = 0; size < 256; size++) {
        bad[21] = size;
        bad[22] = size;
        passed &= !test_wire_find_attr(bad, sizeof(origin_update), 1, NULL, NULL, NULL);
    }
    test_result(passed, "Oversized attribute sections cannot escape the physical message boundary");

    // Withdrawn 10.1.0.0/16 and 192.0.2.0/24 in the classic field, no attributes.
    static const uint8_t classic_withdraw[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x1e, 0x02, 0x00, 0x07, 0x10, 0x0a, 0x01, 0x18, 0xc0, 0x00, 0x02, 0x00, 0x00
    };
    test_wire_update_t view;
    test_result(test_wire_update_view(classic_withdraw, sizeof(classic_withdraw), &view) &&
                view.withdrawn_len == 7 && view.withdrawn == classic_withdraw + 21 && view.attr_count == 0 &&
                view.nlri_len == 0 && !view.has_reach && !view.has_unreach &&
                test_wire_nlri_size(1, 1, 0, view.withdrawn, 7) == 3 &&
                test_wire_nlri_size(1, 1, 0, view.withdrawn + 3, 4) == 4,
                "Classic Withdrawn Routes decode to whole prefixes");

    // MP_UNREACH_NLRI for VPNv4 with Add-Path: path ID 7, 112 bits, label 0x800000, RD 0:1, 10.0.0/24.
    static const uint8_t vpn_unreach[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x30, 0x02, 0x00, 0x00, 0x00, 0x19, 0x80, 0x0f, 0x16, 0x00, 0x01, 0x80,
        0x00, 0x00, 0x00, 0x07, 0x70, 0x80, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00
    };
    int vpn_ok = test_wire_update_view(vpn_unreach, sizeof(vpn_unreach), &view);
    vpn_ok = vpn_ok && view.has_unreach && view.unreach_afi == 1 && view.unreach_safi == 128 &&
             view.unreach_len == 19 && view.attr_count == 1 &&
             test_wire_nlri_size(1, 128, 1, view.unreach, view.unreach_len) == 19 &&
             test_wire_nlri_size(1, 128, 1, view.unreach, view.unreach_len - 1) == 0;
    test_result(vpn_ok, "MP_UNREACH_NLRI decodes AFI/SAFI and an Add-Path VPN NLRI; a short NLRI is rejected");
    passed = 1;
    for (size_t size = 0; size < sizeof(classic_withdraw); size++) {
        passed &= !test_wire_update_view(classic_withdraw, size, &view);
    }
    test_result(passed, "Every truncation of a withdrawal UPDATE is rejected");

    static const uint8_t flowspec_long[] = {0xf1, 0x02};
    test_result(test_wire_nlri_size(1, 133, 0, flowspec_long, 2) == 0 &&
                test_wire_nlri_size(25, 70, 0, (const uint8_t[]){0x02, 0x03, 1, 2, 3}, 5) == 5 &&
                test_wire_nlri_size(1, 73, 0, (const uint8_t[]){96, 0, 0, 0, 1, 0, 0, 0, 2, 10, 0, 0, 1}, 13) == 13,
                "FlowSpec two-octet, EVPN and SR Policy NLRI lengths");
    return tests_failed ? 1 : 0;
}
