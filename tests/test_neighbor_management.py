#!/usr/bin/env python3
"""
Neighbor Management Test
Tests adding and removing BGP neighbors via Python API
"""

import sys
import os

# Import common test utilities
from test_common import (
    ProcessFixture, TestRunner, bgpsim
)

SESSION_NAME = f"test_neighbor_management_{os.getpid()}"

def main():
    with ProcessFixture() as fixture:
        return run_tests(fixture)


def run_tests(fixture):
    # Initialize test runner
    runner = TestRunner()

    # Start test session
    if not fixture.start_session(SESSION_NAME, log_path=fixture.root / 'neighbor.log'):
        runner.test_fail("Failed to start test session")
        return 1

    client = bgpsim.connect(SESSION_NAME)

    # ==========================================
    # TEST GROUP 1: Adding Neighbors
    # ==========================================

    # Test 1.1: Configure router and add first neighbor
    try:
        client.cli("config")
        client.cli("router bgp 65001")
        client.cli("router-id 10.0.0.1")
        client.cli("neighbor 192.168.1.2 remote-as 65002")
        client.cli("exit")

        config = client.cli("show running-config")
        if "neighbor 192.168.1.2 remote-as 65002" in config:
            runner.test_pass("First neighbor added successfully")
        else:
            runner.test_fail("First neighbor not in config", config)
    except Exception as e:
        runner.test_fail("Failed to add first neighbor", str(e))

    # Test 1.2: Add second neighbor to same router
    try:
        client.cli("config")
        client.cli("router bgp 65001")
        client.cli("neighbor 192.168.1.3 remote-as 65003")
        client.cli("exit")

        config = client.cli("show running-config")
        if "neighbor 192.168.1.3 remote-as 65003" in config:
            runner.test_pass("Second neighbor added successfully")
        else:
            runner.test_fail("Second neighbor not in config")
    except Exception as e:
        runner.test_fail("Failed to add second neighbor", str(e))

    # Test 1.3: Add third neighbor
    try:
        client.cli("config")
        client.cli("router bgp 65001")
        client.cli("neighbor 192.168.1.4 remote-as 65004")
        client.cli("exit")

        config = client.cli("show running-config")
        if "neighbor 192.168.1.4 remote-as 65004" in config:
            runner.test_pass("Third neighbor added successfully")
        else:
            runner.test_fail("Third neighbor not in config")
    except Exception as e:
        runner.test_fail("Failed to add third neighbor", str(e))

    # Test 1.4: Verify all neighbors present
    try:
        config = client.cli("show running-config")
        neighbors = [
            "neighbor 192.168.1.2 remote-as 65002",
            "neighbor 192.168.1.3 remote-as 65003",
            "neighbor 192.168.1.4 remote-as 65004"
        ]

        all_present = all(n in config for n in neighbors)
        if all_present:
            runner.test_pass("All three neighbors present in config")
        else:
            missing = [n for n in neighbors if n not in config]
            runner.test_fail("Some neighbors missing", f"Missing: {missing}")
    except Exception as e:
        runner.test_fail("Failed to verify all neighbors", str(e))

    # Test 1.5: Verify neighbors show under correct router
    try:
        config = client.cli("show running-config")
        lines = config.split('\n')

        # Find router bgp 65001 section
        in_router_section = False
        neighbor_count = 0

        for line in lines:
            if 'router bgp 65001' in line:
                in_router_section = True
            elif 'router bgp' in line and '65001' not in line:
                in_router_section = False
            elif in_router_section and 'neighbor' in line and 'remote-as' in line:
                neighbor_count += 1

        if neighbor_count == 3:
            runner.test_pass("All neighbors under router bgp 65001")
        else:
            runner.test_fail("Wrong neighbor count", f"Found {neighbor_count}, expected 3")
    except Exception as e:
        runner.test_fail("Failed to verify neighbor nesting", str(e))

    # ==========================================
    # TEST GROUP 2: Removing Neighbors
    # ==========================================

    # Test 2.1: Remove first neighbor
    try:
        client.cli("config")
        client.cli("router bgp 65001")
        client.cli("no neighbor 192.168.1.2 remote-as 65002")
        client.cli("exit")

        config = client.cli("show running-config")
        if "neighbor 192.168.1.2 remote-as 65002" not in config:
            runner.test_pass("First neighbor removed successfully")
        else:
            runner.test_fail("First neighbor still in config", config)
    except Exception as e:
        runner.test_fail("Failed to remove first neighbor", str(e))

    # Test 2.2: Verify other neighbors still present
    try:
        config = client.cli("show running-config")
        if ("neighbor 192.168.1.3 remote-as 65003" in config and
            "neighbor 192.168.1.4 remote-as 65004" in config):
            runner.test_pass("Other neighbors still present after removal")
        else:
            runner.test_fail("Other neighbors incorrectly affected")
    except Exception as e:
        runner.test_fail("Failed to verify remaining neighbors", str(e))

    # Test 2.3: Remove second neighbor
    try:
        client.cli("config")
        client.cli("router bgp 65001")
        client.cli("no neighbor 192.168.1.3 remote-as 65003")
        client.cli("exit")

        config = client.cli("show running-config")
        if "neighbor 192.168.1.3 remote-as 65003" not in config:
            runner.test_pass("Second neighbor removed successfully")
        else:
            runner.test_fail("Second neighbor still in config")
    except Exception as e:
        runner.test_fail("Failed to remove second neighbor", str(e))

    # Test 2.4: Verify only one neighbor remains
    try:
        config = client.cli("show running-config")
        if ("neighbor 192.168.1.4 remote-as 65004" in config and
            "neighbor 192.168.1.2" not in config and
            "neighbor 192.168.1.3" not in config):
            runner.test_pass("Only one neighbor remains")
        else:
            runner.test_fail("Incorrect neighbors remaining")
    except Exception as e:
        runner.test_fail("Failed to verify single neighbor", str(e))

    # Test 2.5: Remove last neighbor
    try:
        client.cli("config")
        client.cli("router bgp 65001")
        client.cli("no neighbor 192.168.1.4 remote-as 65004")
        client.cli("exit")

        config = client.cli("show running-config")
        # Check that no neighbor statements exist for this router
        lines = config.split('\n')
        in_router_section = False
        has_neighbor = False

        for line in lines:
            if 'router bgp 65001' in line:
                in_router_section = True
            elif 'router bgp' in line and '65001' not in line:
                in_router_section = False
            elif in_router_section and 'neighbor' in line and 'remote-as' in line:
                has_neighbor = True

        if not has_neighbor:
            runner.test_pass("All neighbors removed from router")
        else:
            runner.test_fail("Neighbors still present after removal")
    except Exception as e:
        runner.test_fail("Failed to remove last neighbor", str(e))

    # ==========================================
    # TEST GROUP 3: Add/Remove Cycles
    # ==========================================

    # Test 3.1: Add neighbor, remove it, add it again
    try:
        client.cli("config")
        client.cli("router bgp 65001")
        client.cli("neighbor 192.168.10.1 remote-as 65010")
        client.cli("exit")

        config = client.cli("show running-config")
        first_add = "neighbor 192.168.10.1 remote-as 65010" in config

        client.cli("config")
        client.cli("router bgp 65001")
        client.cli("no neighbor 192.168.10.1 remote-as 65010")
        client.cli("exit")

        config = client.cli("show running-config")
        removed = "neighbor 192.168.10.1 remote-as 65010" not in config

        client.cli("config")
        client.cli("router bgp 65001")
        client.cli("neighbor 192.168.10.1 remote-as 65010")
        client.cli("exit")

        config = client.cli("show running-config")
        second_add = "neighbor 192.168.10.1 remote-as 65010" in config

        if first_add and removed and second_add:
            runner.test_pass("Add/remove/add cycle works correctly")
        else:
            runner.test_fail("Add/remove/add cycle failed",
                     f"first={first_add}, removed={removed}, second={second_add}")
    except Exception as e:
        runner.test_fail("Failed add/remove/add cycle", str(e))

    # ==========================================
    # TEST GROUP 4: Multiple Routers
    # ==========================================

    # Test 4.1: Add neighbors to different routers
    try:
        client.cli("config")
        client.cli("router bgp 65001")
        client.cli("neighbor 10.1.1.1 remote-as 65002")
        client.cli("router bgp 65002")  # Mode rewind
        client.cli("neighbor 10.2.2.2 remote-as 65001")
        client.cli("exit")

        config = client.cli("show running-config")

        # Verify AS 65001 has its neighbor
        lines = config.split('\n')
        in_65001 = False
        has_10_1_1_1 = False

        for line in lines:
            if 'router bgp 65001' in line:
                in_65001 = True
            elif 'router bgp' in line and '65001' not in line:
                in_65001 = False
            elif in_65001 and 'neighbor 10.1.1.1 remote-as 65002' in line:
                has_10_1_1_1 = True

        # Verify AS 65002 has its neighbor
        in_65002 = False
        has_10_2_2_2 = False

        for line in lines:
            if 'router bgp 65002' in line:
                in_65002 = True
            elif 'router bgp' in line and '65002' not in line:
                in_65002 = False
            elif in_65002 and 'neighbor 10.2.2.2 remote-as 65001' in line:
                has_10_2_2_2 = True

        if has_10_1_1_1 and has_10_2_2_2:
            runner.test_pass("Neighbors correctly assigned to different routers")
        else:
            runner.test_fail("Neighbor assignment to routers incorrect",
                     f"65001:{has_10_1_1_1}, 65002:{has_10_2_2_2}")
    except Exception as e:
        runner.test_fail("Failed to add neighbors to multiple routers", str(e))

    # Test 4.2: Remove neighbor from one router, verify other unaffected
    try:
        client.cli("config")
        client.cli("router bgp 65001")
        client.cli("no neighbor 10.1.1.1 remote-as 65002")
        client.cli("exit")

        config = client.cli("show running-config")

        # Verify removed from 65001
        removed_from_65001 = not any(line.strip().startswith('neighbor 10.1.1.1 ')
                                    for line in config.splitlines())

        # Verify 65002 neighbor still present
        still_in_65002 = "neighbor 10.2.2.2 remote-as 65001" in config

        if removed_from_65001 and still_in_65002:
            runner.test_pass("Removing neighbor from one router doesn't affect others")
        else:
            runner.test_fail("Neighbor removal affected wrong router")
    except Exception as e:
        runner.test_fail("Failed to verify isolated removal", str(e))

    client.disconnect()

    return runner.summary()

if __name__ == '__main__':
    sys.exit(main())
