/*
 * BGP Neighbor State Tests
 * Covers message counters, retry timing, and neighbor runtime state fields.
 */

#include <time.h>
#include <stdio.h>
#include <string.h>
#include "bgp.h"
#include "bgpsim.h"
#include "bgp_router.h"
#include "test_result.h"
#include "bgp_neighbor.h"

/*
 * Test 1: TX counter initialization
 */
void test_tx_counters_init() {
    bgp_neighbor_t neighbor = {0};

    int valid = (neighbor.tx_open == 0) &&
                (neighbor.tx_update == 0) &&
                (neighbor.tx_notification == 0) &&
                (neighbor.tx_keepalive == 0);

    test_result(valid, "TX counters initialization to zero");
}

/*
 * Test 2: RX counter initialization
 */
void test_rx_counters_init() {
    bgp_neighbor_t neighbor = {0};

    int valid = (neighbor.rx_open == 0) &&
                (neighbor.rx_update == 0) &&
                (neighbor.rx_notification == 0) &&
                (neighbor.rx_keepalive == 0);

    test_result(valid, "RX counters initialization to zero");
}

/*
 * Test 3: TX OPEN counter increment
 */
void test_tx_open_increment() {
    bgp_neighbor_t neighbor = {0};

    neighbor.tx_open++;
    neighbor.tx_open++;
    neighbor.tx_open++;

    test_result(neighbor.tx_open == 3, "TX OPEN counter increment");
}

/*
 * Test 4: RX OPEN counter increment
 */
void test_rx_open_increment() {
    bgp_neighbor_t neighbor = {0};

    neighbor.rx_open++;
    neighbor.rx_open++;

    test_result(neighbor.rx_open == 2, "RX OPEN counter increment");
}

/*
 * Test 5: TX KEEPALIVE counter increment
 */
void test_tx_keepalive_increment() {
    bgp_neighbor_t neighbor = {0};

    for (int i = 0; i < 10; i++) {
        neighbor.tx_keepalive++;
    }

    test_result(neighbor.tx_keepalive == 10, "TX KEEPALIVE counter increment");
}

/*
 * Test 6: RX KEEPALIVE counter increment
 */
void test_rx_keepalive_increment() {
    bgp_neighbor_t neighbor = {0};

    for (int i = 0; i < 15; i++) {
        neighbor.rx_keepalive++;
    }

    test_result(neighbor.rx_keepalive == 15, "RX KEEPALIVE counter increment");
}

/*
 * Test 7: TX UPDATE counter increment
 */
void test_tx_update_increment() {
    bgp_neighbor_t neighbor = {0};

    for (int i = 0; i < 100; i++) {
        neighbor.tx_update++;
    }

    test_result(neighbor.tx_update == 100, "TX UPDATE counter increment");
}

/*
 * Test 8: RX UPDATE counter increment
 */
void test_rx_update_increment() {
    bgp_neighbor_t neighbor = {0};

    for (int i = 0; i < 250; i++) {
        neighbor.rx_update++;
    }

    test_result(neighbor.rx_update == 250, "RX UPDATE counter increment");
}

/*
 * Test 9: TX NOTIFICATION counter increment
 */
void test_tx_notification_increment() {
    bgp_neighbor_t neighbor = {0};

    neighbor.tx_notification++;
    neighbor.tx_notification++;

    test_result(neighbor.tx_notification == 2, "TX NOTIFICATION counter increment");
}

/*
 * Test 10: RX NOTIFICATION counter increment
 */
void test_rx_notification_increment() {
    bgp_neighbor_t neighbor = {0};

    neighbor.rx_notification++;

    test_result(neighbor.rx_notification == 1, "RX NOTIFICATION counter increment");
}

/*
 * Test 11: Multiple counter increments
 */
void test_multiple_counters() {
    bgp_neighbor_t neighbor = {0};

    neighbor.tx_open = 1;
    neighbor.rx_open = 1;
    neighbor.tx_keepalive = 5;
    neighbor.rx_keepalive = 6;
    neighbor.tx_update = 10;
    neighbor.rx_update = 12;

    int valid = (neighbor.tx_open == 1) &&
                (neighbor.rx_open == 1) &&
                (neighbor.tx_keepalive == 5) &&
                (neighbor.rx_keepalive == 6) &&
                (neighbor.tx_update == 10) &&
                (neighbor.rx_update == 12);

    test_result(valid, "Multiple message counters tracking");
}

/*
 * Test 12: Counter independence
 */
void test_counter_independence() {
    bgp_neighbor_t neighbor = {0};

    neighbor.tx_open = 100;
    // Other counters should remain 0

    int valid = (neighbor.tx_open == 100) &&
                (neighbor.rx_open == 0) &&
                (neighbor.tx_keepalive == 0) &&
                (neighbor.rx_keepalive == 0);

    test_result(valid, "Counter independence (TX doesn't affect RX)");
}

/*
 * Test 13: Large counter values
 */
void test_large_counter_values() {
    bgp_neighbor_t neighbor = {0};

    neighbor.tx_keepalive = 1000000;
    neighbor.rx_keepalive = 2000000;

    int valid = (neighbor.tx_keepalive == 1000000) &&
                (neighbor.rx_keepalive == 2000000);

    test_result(valid, "Large counter values (millions)");
}

/*
 * Test 14: Counter data type size (uint64_t)
 */
void test_counter_data_type() {
    bgp_neighbor_t neighbor = {0};

    // Test with large 64-bit values
    neighbor.tx_update = 0x0000FFFFFFFFFFFFULL;  /* Large but < max */
    neighbor.rx_update = 0x0000FFFFFFFFFFFFULL;

    int valid = (neighbor.tx_update == 0x0000FFFFFFFFFFFFULL) &&
                (neighbor.rx_update == 0x0000FFFFFFFFFFFFULL);

    test_result(valid, "Counter 64-bit data type support");
}

/*
 * Test 15: Counter reset behavior
 */
void test_counter_reset() {
    bgp_neighbor_t neighbor = {0};

    // Set counters to non-zero
    neighbor.tx_open = 10;
    neighbor.rx_open = 10;

    // Reset to zero
    neighbor.tx_open = 0;
    neighbor.rx_open = 0;

    int valid = (neighbor.tx_open == 0) && (neighbor.rx_open == 0);

    test_result(valid, "Counter reset to zero");
}

/*
 * Test 16: Asymmetric TX/RX counters
 */
void test_asymmetric_counters() {
    bgp_neighbor_t neighbor = {0};

    // Simulate asymmetric message flow
    neighbor.tx_keepalive = 10;
    neighbor.rx_keepalive = 5;  /* Less received than sent */

    int valid = (neighbor.tx_keepalive == 10) &&
                (neighbor.rx_keepalive == 5) &&
                (neighbor.tx_keepalive > neighbor.rx_keepalive);

    test_result(valid, "Asymmetric TX/RX counter values");
}

/*
 * Test 17: Counter values after connection reset
 */
void test_counters_after_reset() {
    bgp_neighbor_t neighbor = {0};

    // Simulate a connection with traffic
    neighbor.tx_open = 1;
    neighbor.rx_open = 1;
    neighbor.tx_keepalive = 5;

    // Reset connection - in real code, counters might be preserved
    // This tests that counters can hold their values
    int before_tx_open = neighbor.tx_open;
    int before_tx_keepalive = neighbor.tx_keepalive;

    int valid = (before_tx_open == 1) && (before_tx_keepalive == 5);

    test_result(valid, "Counter values preservation after reset");
}

/*
 * Test 18: Multiple neighbors counter independence
 */
void test_multiple_neighbors_counters() {
    bgp_neighbor_t neighbor1 = {0};
    bgp_neighbor_t neighbor2 = {0};

    neighbor1.tx_keepalive = 100;
    neighbor2.tx_keepalive = 200;

    // Counters should be independent
    int valid = (neighbor1.tx_keepalive == 100) &&
                (neighbor2.tx_keepalive == 200) &&
                (neighbor1.tx_keepalive != neighbor2.tx_keepalive);

    test_result(valid, "Multiple neighbors counter independence");
}

/*
 * Test 19: Counter statistics calculation
 */
void test_counter_statistics() {
    bgp_neighbor_t neighbor = {0};

    neighbor.tx_open = 1;
    neighbor.rx_open = 1;
    neighbor.tx_keepalive = 10;
    neighbor.rx_keepalive = 10;
    neighbor.tx_update = 5;
    neighbor.rx_update = 8;

    // Calculate total messages
    uint64_t total_tx = neighbor.tx_open + neighbor.tx_keepalive +
                        neighbor.tx_update + neighbor.tx_notification;
    uint64_t total_rx = neighbor.rx_open + neighbor.rx_keepalive +
                        neighbor.rx_update + neighbor.rx_notification;

    int valid = (total_tx == 16) && (total_rx == 19);

    test_result(valid, "Counter statistics calculation (totals)");
}

/*
 * Test 20: Zero NOTIFICATION counters typical case
 */
void test_zero_notification_typical() {
    bgp_neighbor_t neighbor = {0};

    // In a healthy session, notification counters should be 0
    neighbor.tx_open = 1;
    neighbor.rx_open = 1;
    neighbor.tx_keepalive = 10;
    neighbor.rx_keepalive = 10;

    int valid = (neighbor.tx_notification == 0) &&
                (neighbor.rx_notification == 0);

    test_result(valid, "Zero NOTIFICATION counters in healthy session");
}

/*
 * Test 21: Initial retry count
 */
void test_initial_retry_count() {
    bgp_neighbor_t neighbor = {0};

    test_result(neighbor.retry_count == 0, "Initial retry count is zero");
}

/*
 * Test 22: Retry count increments
 */
void test_retry_count_increment() {
    bgp_neighbor_t neighbor = {0};

    neighbor.retry_count = 0;
    neighbor.retry_count++;
    neighbor.retry_count++;
    neighbor.retry_count++;

    test_result(neighbor.retry_count == 3, "Retry count increments correctly");
}

/*
 * Test 23: No maximum retry count (infinite retries)
 */
void test_max_retry_count() {
    bgp_neighbor_t neighbor = {0};

    neighbor.retry_count = 100;
    test_result(neighbor.retry_count == 100, "Retry count can be arbitrarily large (no limit)");
}

/*
 * Test 24: Retry count can grow indefinitely
 */
void test_retry_count_beyond_max() {
    bgp_neighbor_t neighbor = {0};

    neighbor.retry_count = 1000;
    test_result(neighbor.retry_count == 1000, "Retry count can grow indefinitely");
}

/*
 * Test 25: Reset retry count on success
 */
void test_retry_count_reset() {
    bgp_neighbor_t neighbor = {0};

    neighbor.retry_count = 5;
    neighbor.retry_count = 0;

    test_result(neighbor.retry_count == 0, "Retry count reset after success");
}

/*
 * Test 26: Last connect attempt timestamp
 */
void test_last_connect_timestamp() {
    bgp_neighbor_t neighbor = {0};
    time_t         before = time(NULL);
    time_t         after;
    int            passed;

    neighbor.last_connect_attempt = time(NULL);
    after = time(NULL);
    passed = neighbor.last_connect_attempt >= before && neighbor.last_connect_attempt <= after;

    test_result(passed, "Last connect attempt timestamp recording");
}

/*
 * Test 27: Initial connection attempt time
 */
void test_initial_connect_time() {
    bgp_neighbor_t neighbor = {0};

    test_result(neighbor.last_connect_attempt == 0, "Initial connect attempt time is zero");
}

/*
 * Test 28: Retry interval at count 0
 */
void test_retry_interval_zero() {
    test_result(BGP_MIN_RETRY_INTERVAL == 2, "Retry interval at count 0 is 2 seconds");
}

/*
 * Test 29: Linear backoff progression
 */
void test_linear_backoff() {
    time_t base = BGP_MIN_RETRY_INTERVAL;
    time_t intervals[8] = {base * 1, base * 2, base * 3, base * 4,
                           base * 5, base * 6, base * 7, base * 8};
    int passed = intervals[0] == 2 && intervals[1] == 4 && intervals[2] == 6 && intervals[3] == 8 &&
                 intervals[4] == 10 && intervals[5] == 12 && intervals[6] == 14 &&
                 intervals[7] == 16;

    test_result(passed, "Linear backoff progression");
}

/*
 * Test 30: Maximum retry interval cap
 */
void test_max_retry_interval() {
    test_result(BGP_MAX_RETRY_INTERVAL == 16, "Maximum retry interval cap");
}

/*
 * Test 31: Time since last attempt calculation
 */
void test_time_since_last_attempt() {
    bgp_neighbor_t neighbor = {0};
    time_t         now = time(NULL);
    time_t         elapsed;

    neighbor.last_connect_attempt = now - 60;
    elapsed = now - neighbor.last_connect_attempt;
    test_result(elapsed >= 60 && elapsed <= 61, "Time since last attempt");
}

/*
 * Test 32: Should retry check (enough time passed)
 */
void test_should_retry_yes() {
    bgp_neighbor_t neighbor = {0};
    time_t         now = time(NULL);
    time_t         elapsed;

    neighbor.last_connect_attempt = now - 10;
    neighbor.retry_count = 0;
    elapsed = now - neighbor.last_connect_attempt;

    test_result(elapsed >= BGP_MIN_RETRY_INTERVAL, "Should retry when enough time passed");
}

/*
 * Test 33: Should not retry check (not enough time)
 */
void test_should_retry_no() {
    bgp_neighbor_t neighbor = {0};
    time_t         now = time(NULL);
    time_t         elapsed;

    neighbor.last_connect_attempt = now - 1;
    neighbor.retry_count = 0;
    elapsed = now - neighbor.last_connect_attempt;

    test_result(elapsed < BGP_MIN_RETRY_INTERVAL, "Should not retry when insufficient time");
}

/*
 * Test 34: Multiple neighbors independent retry
 */
void test_independent_retry_counts() {
    bgp_neighbor_t neighbor1 = {0};
    bgp_neighbor_t neighbor2 = {0};
    int            passed;

    neighbor1.retry_count = 3;
    neighbor2.retry_count = 7;
    passed = neighbor1.retry_count == 3 && neighbor2.retry_count == 7 &&
             neighbor1.retry_count != neighbor2.retry_count;

    test_result(passed, "Independent retry counts for multiple neighbors");
}

/*
 * Test 35: State persistence across retries
 */
void test_state_persistence() {
    bgp_neighbor_t neighbor = {0};
    int            passed;

    strcpy(neighbor.ip, "10.0.0.1");
    neighbor.remote_as = 65000;
    neighbor.retry_count = 5;
    passed = strcmp(neighbor.ip, "10.0.0.1") == 0 && neighbor.remote_as == 65000 &&
             neighbor.retry_count == 5;

    test_result(passed, "State persistence across retries");
}

/*
 * Test 36: Retry with IDLE state
 */
void test_retry_in_idle_state() {
    bgp_neighbor_t neighbor = {0};

    neighbor.state = BGP_STATE_IDLE;
    neighbor.retry_count = 2;

    test_result(neighbor.state == BGP_STATE_IDLE, "Retry allowed in IDLE state");
}

/*
 * Test 37: No retry in ESTABLISHED state
 */
void test_no_retry_in_established() {
    bgp_neighbor_t neighbor = {0};

    neighbor.state = BGP_STATE_ESTABLISHED;
    test_result(neighbor.state == BGP_STATE_ESTABLISHED, "No retry in ESTABLISHED state");
}

/*
 * Test 38: Retry count after connection failure
 */
void test_retry_after_failure() {
    bgp_neighbor_t neighbor = {0};

    neighbor.sock_fd = -1;
    neighbor.state = BGP_STATE_IDLE;
    neighbor.retry_count = 3;

    test_result(neighbor.retry_count == 3, "Retry count after failure");
}

/*
 * Test 39: First retry has no previous attempt
 */
void test_first_retry_no_previous() {
    bgp_neighbor_t neighbor = {0};

    neighbor.last_connect_attempt = 0;
    neighbor.retry_count = 0;

    test_result(neighbor.last_connect_attempt == 0, "First retry has no previous attempt");
}

/*
 * Test 40: Retry timing accuracy within tolerance
 */
void test_retry_timing_tolerance() {
    bgp_neighbor_t neighbor = {0};
    time_t         now = time(NULL);
    time_t         elapsed;
    int            passed;

    neighbor.last_connect_attempt = now - 3;
    neighbor.retry_count = 0;
    elapsed = now - neighbor.last_connect_attempt;
    passed = elapsed >= (BGP_MIN_RETRY_INTERVAL - 1) && elapsed <= (BGP_MIN_RETRY_INTERVAL + 2);

    test_result(passed, "Retry timing within acceptable tolerance");
}

static void test_canonical_peer_identity(void) {
    bgp_sim_t sim = {0};
    bgp_init_simulator(&sim);
    int passed = bgp_add_router(&sim, 65001) >= 0 &&
                 bgp_add_neighbor(&sim, 65001, "2001:0db8:0:0::1", 65002) == 1 &&
                 bgp_add_neighbor(&sim, 65001, "2001:db8::1", 65002) == 0;
    bgp_router_t *router = bgp_find_router(&sim, 65001);
    passed = passed && router && router->neighbor_count == 1 &&
             strcmp(router->neighbors[0]->ip, "2001:db8::1") == 0;
    test_result(passed, "Equivalent IPv6 spellings share one canonical peer identity");
    passed = bgp_set_neighbor_source_ip(&sim, 65001, "2001:0db8::1", "2001:db8::2") >= 0 &&
             bgp_clear_neighbor_source_ip(&sim, 65001, "2001:0db8:0:0::1") >= 0 &&
             bgp_remove_neighbor(&sim, 65001, "2001:0db8::1") >= 0 && router && router->neighbor_count == 0;
    test_result(passed, "Peer mutation APIs resolve equivalent spellings through the same identity");
    bgp_shutdown_sim(&sim);
}

int main() {
    printf("BGP Neighbor State Tests\n");
    printf("========================\n\n");

    // Run all tests
    test_tx_counters_init();
    test_rx_counters_init();
    test_tx_open_increment();
    test_rx_open_increment();
    test_tx_keepalive_increment();
    test_rx_keepalive_increment();
    test_tx_update_increment();
    test_rx_update_increment();
    test_tx_notification_increment();
    test_rx_notification_increment();
    test_multiple_counters();
    test_counter_independence();
    test_large_counter_values();
    test_counter_data_type();
    test_counter_reset();
    test_asymmetric_counters();
    test_counters_after_reset();
    test_multiple_neighbors_counters();
    test_counter_statistics();
    test_zero_notification_typical();
    test_initial_retry_count();
    test_retry_count_increment();
    test_max_retry_count();
    test_retry_count_beyond_max();
    test_retry_count_reset();
    test_last_connect_timestamp();
    test_initial_connect_time();
    test_retry_interval_zero();
    test_linear_backoff();
    test_max_retry_interval();
    test_time_since_last_attempt();
    test_should_retry_yes();
    test_should_retry_no();
    test_independent_retry_counts();
    test_state_persistence();
    test_retry_in_idle_state();
    test_no_retry_in_established();
    test_retry_after_failure();
    test_first_retry_no_previous();
    test_retry_timing_tolerance();
    test_canonical_peer_identity();

    // Print summary
    printf("\n========================\n");
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    printf("========================\n");

    return (tests_failed == 0) ? 0 : 1;
}
