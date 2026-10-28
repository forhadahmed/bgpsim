#!/usr/bin/env python3
"""
EVPN multihoming over VXLAN against a real receiver.

Two bgpsim routers are VTEPs that share one Ethernet segment and one VNI. FRR is the remote VTEP: zebra and bgpd in a
namespace with a kernel VXLAN device for that VNI. FRR decodes the routes with its own code, builds the remote
Ethernet segment, and programs the kernel, so each check reads state that bgpsim did not produce: FRR's segment and
its per-VTEP A-D flags, the segment the MAC is bound to, and the VTEPs of the kernel next-hop group behind the MAC.

Only VTEP 1 advertises the MAC. VTEP 2 is reachable for it through aliasing alone (RFC 7432 section 8.4).

A second MAC, on no segment, carries the MAC Mobility and Default Gateway communities; FRR decodes them, zebra takes
the sequence number, and the kernel entry becomes sticky.
"""

import sys

import frr_peer
from frr_peer import FrrPeer
from interop import InteropTest
from test_results import run_unittest

VNI = 100
FRR_AS = 65000
ESI = '03:44:38:39:ff:ff:01:00:00:01'
MAC = '00:00:5e:00:53:01'
GATEWAY_MAC = '00:00:5e:00:53:02'
VTEPS = {1: '192.0.2.1', 2: '192.0.2.2'}
BOTH = ['ead-per-es', 'ead-per-evi']


def link(vtep):
    """(bgpsim's address, FRR's address) of the link that carries the session of one VTEP."""
    return f'172.30.{vtep}.1', f'172.30.{vtep}.2'


def ribouts(vtep):
    """The routes of one VTEP: Ethernet Segment, A-D per ES, A-D per EVI and inclusive multicast."""
    address = VTEPS[vtep]
    common = ['encap vxlan', f'next-hop {address}', f'as-path {FRR_AS + vtep}']
    return [
        f'ribout es{vtep}',
            f'nlri evpn type4 rd {address}:1 esi {ESI} router {address}',
            f'es-import esi {ESI}',
            *common,
            'exit',
        f'ribout ades{vtep}',
            f'nlri evpn type1 rd {address}:1 esi {ESI} ethernet-tag max label 0',
            'esi-label label 0',
            f'rt {FRR_AS}:{VNI}',
            *common,
            'exit',
        f'ribout adevi{vtep}',
            f'nlri evpn type1 rd {address}:{VNI} esi {ESI} ethernet-tag 0 label {VNI}',
            f'rt {FRR_AS}:{VNI}',
            *common,
            'exit',
        f'ribout imet{vtep}',
            f'nlri evpn type3 rd {address}:{VNI} ethernet-tag 0 router {address}',
            f'pmsi flags 0 type 6 label {VNI} id {address}',
            f'rt {FRR_AS}:{VNI}',
            *common,
            'exit']



class InteropEvpnTests(InteropTest):
    @classmethod
    def setUpClass(cls):
        cls.prepare('mh', 'EVPN multihoming against FRR', frr_peer.missing, capture=False)
        namespace = cls.namespace('', '10.0.0.3')
        for vtep, address in VTEPS.items():
            mine, theirs = link(vtep)
            cls.link(namespace, mine, theirs, device=f'eth{vtep}')
            # The tunnel endpoint of each VTEP is reachable through its own link.
            cls.fixture.run(['ip', '-n', namespace, 'route', 'add', f'{address}/32', 'via', mine])
        cls.frr = FrrPeer(cls.fixture, 'vtep', namespace, FRR_AS, '10.0.0.3',
                          {link(vtep)[0]: (FRR_AS + vtep, False) for vtep in VTEPS}, vxlan=(VNI, '10.0.0.3'))

        lines = [line for vtep in VTEPS for line in ribouts(vtep)]
        lines += [
            'ribout mac1',
                f'rd {VTEPS[1]}:{VNI}',
                f'mac {MAC}',
                f'esi {ESI}',
                'ethernet-tag 0',
                f'label {VNI}',
                f'rt {FRR_AS}:{VNI}',
                'encap vxlan',
                f'next-hop {VTEPS[1]}',
                f'as-path {FRR_AS + 1}',
                'exit']
        # A second MAC, behind VTEP 1 alone and on no segment, for the MAC Mobility and Default Gateway communities.
        lines += [
            'ribout gateway',
                f'rd {VTEPS[1]}:{VNI}',
                f'mac {GATEWAY_MAC}',
                'ethernet-tag 0',
                f'label {VNI}',
                f'rt {FRR_AS}:{VNI}',
                'encap vxlan',
                f'next-hop {VTEPS[1]}',
                f'as-path {FRR_AS + 1}',
                'exit']
        for vtep, address in VTEPS.items():
            lines += [
                f'router bgp {FRR_AS + vtep}',
                    f'router-id {address}',
                    f'neighbor {link(vtep)[1]} remote-as {FRR_AS}',
                        'address-family l2vpn evpn',
                        'exit',
                    'exit']
        cls.start([cls.frr], lines)

    def setUp(self):
        # Every case starts from all routes advertised, whatever the case before it withdrew.
        for vtep in VTEPS:
            for name in ('es', 'ades', 'adevi', 'imet'):
                self.run_tx('advertise', f'{name}{vtep}', vtep)
        self.run_tx('advertise', 'mac1', 1)
        self.expect(vteps=(1, 2), ad={1: BOTH, 2: BOTH}, mac=(1, 2), flood=(1, 2))

    def run_tx(self, verb, ribout, vtep):
        target = 'all' if ribout == 'all' else f'ribout {ribout}'
        self.cli(f'{verb} {target} peer {link(vtep)[1]}')

    def expect(self, *, vteps, ad, mac, flood):
        """
        Wait for FRR and the kernel to hold exactly this: the VTEPs of the segment, each VTEP's A-D flags, the VTEPs
        behind the MAC (None: no MAC), which never moved and is not sticky, and the flood list. Then check that the sessions stayed up and that FRR
        accepted every UPDATE.
        """
        want = dict(segments={ESI: sorted(VTEPS[v] for v in vteps)} if vteps else {},
                    flags={(ESI, VTEPS[v]): flags for v, flags in ad.items()},
                    mac_segment=None if mac is None else ESI,
                    mac_sequence=None if mac is None else 0, mac_sticky=False,
                    mac_next_hops=[] if mac is None else [sorted(VTEPS[v] for v in mac)],
                    flood=sorted(VTEPS[v] for v in flood))
        seen = {}

        def matches():
            seen.update(self.frr.evpn_state(MAC))
            return seen == want

        self.reaches(matches, lambda: f'FRR holds {seen}, expected {want}')
        self.assertEqual(set(self.frr.states().values()), {'Established'})
        notifications, errors = self.frr.log_events()
        self.assertEqual((notifications, errors), ([], []))

    def test_segment_forms_and_frr_decodes_every_route(self):
        """setUp proved the segment, aliasing and the kernel state; here FRR's own decode of each route is exact."""
        common = f'RT:{FRR_AS}:{VNI} ET:8'
        # (extended communities, VNI, PMSI label): the VNI is the label field read as a whole 24-bit value.
        want = {(f'{VTEPS[1]}:{VNI}', f'[2]:[0]:[48]:[{MAC}]'): (common, VNI, None)}
        for address in VTEPS.values():
            want.update({
                (f'{address}:1', f'[4]:[{ESI}]:[32]:[{address}]'): ('ET:8 ES-Import-Rt:44:38:39:ff:ff:01', None, None),
                (f'{address}:1', f'[1]:[4294967295]:[{ESI}]:[32]:[0.0.0.0]:[0]'): (f'{common} ESI-label-Rt:AA', 0, None),
                (f'{address}:{VNI}', f'[1]:[0]:[{ESI}]:[32]:[0.0.0.0]:[0]'): (common, VNI, None),
                (f'{address}:{VNI}', f'[3]:[0]:[32]:[{address}]'): (common, None, VNI)})
        self.assertEqual(self.frr.evpn_routes(), want)

    def test_per_evi_withdrawal_removes_one_next_hop_and_readvertising_restores_it(self):
        self.run_tx('withdraw', 'adevi2', 2)
        self.expect(vteps=(1,), ad={1: BOTH, 2: ['ead-per-es']}, mac=(1,), flood=(1, 2))
        self.run_tx('advertise', 'adevi2', 2)
        self.expect(vteps=(1, 2), ad={1: BOTH, 2: BOTH}, mac=(1, 2), flood=(1, 2))

    def test_per_es_withdrawal_removes_one_next_hop_and_readvertising_restores_it(self):
        self.run_tx('withdraw', 'ades2', 2)
        self.expect(vteps=(1,), ad={1: BOTH, 2: ['ead-per-evi']}, mac=(1,), flood=(1, 2))
        self.run_tx('advertise', 'ades2', 2)
        self.expect(vteps=(1, 2), ad={1: BOTH, 2: BOTH}, mac=(1, 2), flood=(1, 2))

    def test_mac_mobility_and_default_gateway_reach_zebra_and_the_kernel(self):
        """
        RFC 7432 sections 7.7 and 7.8. The MAC goes out plain, then with sequence number 5, then as a sticky default
        gateway with sequence number 6. After each step bgpd decodes the communities of that step, zebra holds its
        sequence number, and the kernel FDB entry is sticky only after the last. (FRR 10.3 keeps a MAC sticky once
        it was, so sticky comes last.)
        """
        common = f'RT:{FRR_AS}:{VNI} ET:8'
        seen = []

        def holds(*want):
            # bgpd's decode of the communities, zebra's sequence number, the kernel's sticky flag, the VTEP behind it.
            state = self.frr.evpn_state(GATEWAY_MAC)
            route = self.frr.evpn_routes().get((f'{VTEPS[1]}:{VNI}', f'[2]:[0]:[48]:[{GATEWAY_MAC}]'))
            seen[:] = [route and route[0], state['mac_sequence'], state['mac_sticky'], state['mac_next_hops']]
            return seen == list(want)

        def advertise(*lines):
            self.configure('ribout gateway', *lines)
            self.cli('update generate ribout gateway')
            self.run_tx('advertise', 'gateway', 1)

        advertise()
        self.reaches(lambda: holds(common, 0, False, [VTEPS[1]]), lambda: f'FRR holds {seen}')
        advertise('mac-mobility 5')
        self.reaches(lambda: holds(f'{common} MM:5', 5, False, [VTEPS[1]]), lambda: f'FRR holds {seen}')
        advertise('mac-mobility 6 sticky', 'default-gateway')
        self.reaches(lambda: holds(f'{common} Default Gateway MM:6, sticky MAC', 6, True, [VTEPS[1]]),
                     lambda: f'FRR holds {seen}')
        self.run_tx('withdraw', 'gateway', 1)
        self.reaches(lambda: holds(None, None, False, []), lambda: f'FRR holds {seen}')
        self.assertEqual(set(self.frr.states().values()), {'Established'})
        self.assertEqual(self.frr.log_events(), ([], []))

    def test_mac_stays_reachable_through_the_alias_when_its_owner_leaves_the_segment(self):
        # VTEP 1 still advertises the MAC, but is no longer on the segment: only the aliased VTEP 2 carries it.
        self.run_tx('withdraw', 'ades1', 1)
        self.expect(vteps=(2,), ad={1: ['ead-per-evi'], 2: BOTH}, mac=(2,), flood=(1, 2))
        self.run_tx('advertise', 'ades1', 1)
        self.expect(vteps=(1, 2), ad={1: BOTH, 2: BOTH}, mac=(1, 2), flood=(1, 2))

    def test_mac_withdrawal_and_final_drain(self):
        self.run_tx('withdraw', 'mac1', 1)
        self.expect(vteps=(1, 2), ad={1: BOTH, 2: BOTH}, mac=None, flood=(1, 2))
        self.run_tx('advertise', 'mac1', 1)
        self.expect(vteps=(1, 2), ad={1: BOTH, 2: BOTH}, mac=(1, 2), flood=(1, 2))
        self.run_tx('withdraw', 'all', 1)
        self.expect(vteps=(2,), ad={2: BOTH}, mac=None, flood=(2,))
        self.run_tx('withdraw', 'all', 2)
        self.expect(vteps=(), ad={}, mac=None, flood=())
        self.assertEqual(self.frr.evpn_routes(), {})


if __name__ == '__main__':
   sys.exit(run_unittest())
