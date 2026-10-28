#!/usr/bin/env python3
"""
BGP-LS over real sessions: generation, scripted churn and teardown, checked by two independent decoders.

bgpsim peers with three ExaBGP speakers, each in its own namespace. Peers 1 and 2 negotiate BGP-LS and report every
UPDATE as JSON; peer 3 does not negotiate the family. ExaBGP 5 decodes the base, traffic engineering, SR-MPLS and
SRv6 content with its own code, and reports what it does not know (Flexible Algorithm, BGP peering SIDs, the BGP
Router-ID node descriptor and the SR Policy candidate path NLRI) as raw octets. tshark decodes a capture of the same
sessions: it is the second decoder for the SRv6 content and the first for Flexible Algorithm and the peering SIDs.
Neither shares code with bgpsim. No decoder here knows SR Policy state (RFC 9857): those routes are compared, as
ExaBGP hands them over, with the octets of the RFC figures.

ExaBGP 5.0 reads the O flag of the SRv6 Capabilities TLV from the wrong bit (RFC 9352 section 2 puts it second from
the left of 16), so that flag is checked with tshark only.

The workload is one small IS-IS topology: nodes, the links between consecutive nodes, prefixes and locators of each
node, and SRv6 SIDs; one BGP router with its peers; and the candidate paths of one SR Policy. Three ribouts are then
edited and generated again, and one script sends the new attributes for the same routes and withdraws the SRv6 SIDs,
on both peers at once.
"""

import json
import sys

import exa_peer
from exa_peer import ExaPeer
from interop import InteropTest
from test_results import run_unittest

LOCAL_AS = 65001
PEER_AS = 65100
PEERS = (1, 2, 3)
LS_PEERS = (1, 2)  # Negotiate BGP-LS
PLAIN_PEER = 3     # Negotiates only IPv4 unicast
NODES = 4
ISIS = 'protocol isis-l2 identifier 0 local-as 65000'
COMMON = ['next-hop 192.0.2.1', f'as-path {LOCAL_AS}', 'exit']
# An SR Policy candidate path as RFC 9857 draws it, without its discriminator: NLRI type 5 of 65 octets, protocol 9,
# the headend (AS, BGP Router-ID, TE Router-ID), then the descriptor: origin BGP, endpoint 192.0.2.9, color 100,
# originator AS 65000 and address 10.255.0.1.
CANDIDATE_PATH = ('0005004109' '0000000000000000' '01000018' '020000040000FDE8' '020400040AFF0001' '040400040AFF0001'
                  '022A0018' '02000000' 'C0000209' '00000064' '0000FDE8' '0AFF0001')


def link(peer):
    """(bgpsim's address, ExaBGP's address) of the link to one peer."""
    return f'172.31.{peer}.1', f'172.31.{peer}.2'


def workload():
    node = f'{ISIS} local-router 0000.0000.0001'
    links = (f'nlri bgp-ls link {node} remote-as 65000 remote-router 0000.0000.0002 local-ip 10.0.0.1 '
             f'remote-ip 10.0.0.2 step node x {NODES - 1}')
    prefixes = f'nlri bgp-ls ipv4-prefix {node} prefix 10.1.0.0/24 step node x {NODES} step prefix x 2'
    return [
        'ribout nodes',
            f'nlri bgp-ls node {node} step node x {NODES}',
            'ls node-name r1',
            'ls sr-capabilities flags i,v range 16000 8000',
            'ls sr-algorithm 0 1',
            'ls srv6-capabilities flags o',
            f'ls ipv4-router-id 10.0.0.1 x {NODES}',
            'ls node-msd 1 10',
            'ls flex-algo 128 metric-type 1 priority 100 sub exclude-any 0x1 sub include-any 0x2 sub include-all 0x4',
            *COMMON,
        'ribout links',
            links,
            'ls igp-metric 10',
            'ls te-metric 100',
            'ls max-bandwidth 10g',
            'ls admin-group 0x5',
            'ls srlg 100 200',
            f'ls adj-sid flags v,l label 24001 x {NODES - 1}',
            # The End.X SID follows the node: function e001 in the /48 of each node.
            'ls srv6-endx-sid fc00:0:1:e001::/64 behavior end.x flags b structure 32 16 16 0 per node/48',
            'ls isis-srv6-lan-endx-sid fc00:0:1:e100:: behavior end.x neighbor 0000.0000.0009',
            *COMMON,
        'ribout prefixes',
            prefixes,
            f'ls prefix-sid flags n index 100 x {2 * NODES}',
            'ls prefix-metric 20',
            'ls prefix-attr-flags 0x20',
            *COMMON,
        'ribout locators',
            f'nlri bgp-ls ipv6-prefix {node} prefix fc00:0:1::/48 step prefix x {NODES}',
            'ls srv6-locator flags d algorithm 128 metric 10',
            'ls prefix-attr-flags 0x20',
            *COMMON,
        'ribout sids',
            f'nlri bgp-ls srv6-sid {node} sid fc00:0:1:1::/64 step sid x {NODES}',
            'ls srv6-endpoint-behavior end',
            'ls srv6-sid-structure 32 16 16 0',
            *COMMON,
        # BGP peering (RFC 9086): one egress router and its four peers, each with its own PeerNode SID.
        'ribout peering',
            'nlri bgp-ls link protocol bgp identifier 0 local-as 65000 local-router 10.255.0.1 remote-as 65010 '
                f'remote-router 10.255.1.1 local-ip 192.0.2.1 remote-ip 192.0.2.2 step remote x {NODES}',
            f'ls peer-node-sid flags v,l label 30001 x {NODES}',
            'ls peer-adj-sid flags v,l,b weight 5 label 30100',
            'ls peer-set-sid flags v,l label 30200',
            *COMMON,
        # SR Policy state (RFC 9857): four candidate paths of one policy, each with its own preference.
        'ribout paths',
            'nlri bgp-ls sr-policy protocol sr identifier 0 local-as 65000 local-router 10.255.0.1 '
                'local-te-router-id 10.255.0.1 origin bgp endpoint 192.0.2.9 color 100 originator-as 65000 '
                f'originator 10.255.0.1 discriminator 1 step discriminator x {NODES}',
            f'ls cp-state preference 100 x {NODES}',
            'ls policy-name gold',
            # A sequence inside a nested TLV: each candidate path has its own first segment.
            'ls segment-list weight 1 sub segment 1 flags s,v label 16000 per discriminator',
            *COMMON,
        'script churn',
            'advertise ribout links peer all',
            'advertise ribout prefixes peer all',
            'advertise ribout paths peer all',
            # A withdraw names the peers that hold the ribout: it is withheld from the peer without BGP-LS.
            *[f'withdraw ribout sids peer {link(peer)[1]}' for peer in LS_PEERS],
            'exit',
        f'router bgp {LOCAL_AS}',
            'router-id 192.0.2.1',
            *[line for peer in PEERS for line in (
                f'neighbor {link(peer)[1]} remote-as {PEER_AS + peer}',
                    *(['address-family bgp-ls'] if peer != PLAIN_PEER else []),
                    'exit')],
            'exit']


def router(nlri):
    """The local Router-ID of a decoded IS-IS NLRI: 1 for 0000.0000.0001."""
    descriptors = nlri.get('local-node-descriptors') or nlri['node-descriptors']
    return int(descriptors[1]['router-id'], 16)


class InteropBgplsTests(InteropTest):
    @classmethod
    def setUpClass(cls):
        cls.prepare('ls', 'BGP-LS sessions against ExaBGP', exa_peer.missing)
        cls.peers = {}
        for peer in PEERS:
            mine, theirs = link(peer)
            namespace = cls.namespace(f'p{peer}')
            cls.link(namespace, mine, theirs)
            cls.peers[peer] = ExaPeer(cls.fixture, f'p{peer}', namespace, PEER_AS + peer, f'10.0.0.{peer}',
                                      {mine: (LOCAL_AS, False)}, {mine: theirs},
                                      families=('bgp-ls bgp-ls',) if peer in LS_PEERS else ())
        cls.start(cls.peers.values(), workload())

    def held(self, peer):
        """
        {kind: [(decoded NLRI, decoded BGP-LS attribute)]} that one peer holds now. The kinds are ExaBGP's NLRI type
        names, with the IS-IS and the BGP links apart, and 'code 5' for the candidate paths it does not decode.
        """
        found = {}
        for nlri, attribute in self.peers[peer].ls_routes(link(peer)[0]).items():
            nlri = json.loads(nlri)
            kind = nlri.get('ls-nlri-type', f'code {nlri.get("code")}')
            if kind == 'bgpls-link' and nlri['protocol-id'] == 7:
               kind = 'bgp-link'
            found.setdefault(kind, []).append((nlri, attribute))
        return found

    def wait_held(self, counts, peers=LS_PEERS):
        """These peers hold exactly this many routes of each kind."""
        seen = {}

        def matches():
            for peer in peers:
                seen[peer] = {kind: len(routes) for kind, routes in self.held(peer).items()}
            return all(seen[peer] == counts for peer in peers)

        self.reaches(matches, lambda: f'peers hold {seen}, expected {counts}')

    def candidate_paths(self, peer, flags, preference, segments):
        """
        The candidate paths one peer holds are the four of the policy, each with this state and, with segments, a
        segment list: flags and fixed part, weight 1, then one SR-MPLS segment (type 1, flags S and V) whose label
        stack entry is 16000 plus the number of the path.
        """
        paths = sorted((nlri['raw'], attribute) for nlri, attribute in self.held(peer)['code 5'])
        expected = []
        for path in range(1, NODES + 1):
            attribute = {'generic-lsid-1202': [f'0x0000{flags}{preference + path - 1:08X}'],
                         'generic-lsid-1213': ['0x' + b'gold'.hex().upper()]}
            if segments:
               attribute['generic-lsid-1205'] = ['0x' '0000000000000000' '00000001' '04B60008' '0100A000' +
                                                 f'{(16000 + path - 1) << 12:08X}']
            expected.append((CANDIDATE_PATH + f'{path:08X}', attribute))
        self.assertEqual(paths, expected)

    def test_1_generation_churn_and_teardown(self):
        for name in ('nodes', 'links', 'prefixes', 'locators', 'sids', 'peering', 'paths'):
            self.cli(f'advertise ribout {name} peer all')
        everything = {'bgpls-node': NODES, 'bgpls-link': NODES - 1, 'bgp-link': NODES, 'bgpls-prefix-v4': 2 * NODES,
                      'bgpls-prefix-v6': NODES, 'bgpls-srv6sid': NODES, 'code 5': NODES}
        self.wait_held(everything)
        structure = {'loc_block_len': 32, 'loc_node_len': 16, 'func_len': 16, 'arg_len': 0}
        for peer in LS_PEERS:
            held = self.held(peer)
            # Nodes: each has its own Router-ID attribute, in step with its identity. The Flexible Algorithm
            # definition is raw here: algorithm 128, metric type 1, priority 100, three affinity sub-TLVs.
            for nlri, attribute in held['bgpls-node']:
                self.assertEqual(attribute['node-name'], 'r1')
                self.assertEqual(attribute['local-te-router-ids'], [f'10.0.0.{router(nlri)}'])
                self.assertEqual(attribute['sr-capability-flags'], {'I': 1, 'V': 1, 'RSV': 0})
                self.assertEqual(attribute['sids'], [[8000, 16000]])
                self.assertEqual(attribute['sr-algorithms'], [0, 1])
                self.assertEqual(attribute['generic-lsid-1039'],
                                 ['0x80010064' '0410000400000001' '0411000400000002' '0412000400000004'])
            self.assertEqual(sorted(router(nlri) for nlri, _ in held['bgpls-node']), list(range(1, NODES + 1)))
            # Links: link i joins node i to node i + 1, with adjacency SID 24000 + i and the End.X SID e001 of node
            # i. Every link
            # has the same LAN End.X SID to the same neighbor.
            for nlri, attribute in held['bgpls-link']:
                node = router(nlri)
                self.assertEqual(int(nlri['remote-node-descriptors'][1]['router-id'], 16), node + 1)
                self.assertEqual((nlri['interface-addresses'], nlri['neighbor-addresses']), (['10.0.0.1'], ['10.0.0.2']))
                self.assertEqual((attribute['te-metric'], attribute['igp-metric']), (100, 10))
                self.assertEqual(attribute['maximum-link-bandwidth'], 1250000000.0)
                self.assertEqual((attribute['admin-group-mask'], attribute['shared-risk-link-groups']), (5, [100, 200]))
                self.assertEqual(attribute['sr-adj'], {'flags': {'F': 0, 'B': 0, 'V': 1, 'L': 1, 'S': 0, 'P': 0, 'RSV': 0},
                                                       'sids': [24000 + node], 'weight': 0, 'undecoded-sids': []})
                self.assertEqual(attribute['srv6-endx'], [{
                    'flags': {'B': 1, 'S': 0, 'P': 0, 'RSV': 0}, 'behavior': 5, 'algorithm': 0, 'weight': 0,
                    'sid': f'fc00:0:{node}:e001::', 'srv6-sid-structure': structure}])
                self.assertEqual(attribute['srv6-lan-endx-isis'], [{
                    'flags': {'B': 0, 'S': 0, 'P': 0, 'RSV': 0}, 'neighbor-id': '000000000009', 'behavior': 5,
                    'algorithm': 0, 'weight': 0, 'sid': 'fc00:0:1:e100::'}])
            # BGP peering links (RFC 9086): one egress router and each of its peers, by AS and BGP Router-ID, which
            # ExaBGP reports raw. So are the peering SIDs: flags V and L, a weight, two reserved octets, the label.
            links = sorted(((nlri['local-node-descriptors'], nlri['remote-node-descriptors'], nlri['interface-addresses'],
                             nlri['neighbor-addresses'], attribute) for nlri, attribute in held['bgp-link']),
                           key=lambda entry: entry[1][1]['generic-node-descriptor-516'])
            self.assertEqual(links, [
                ([{'autonomous-system': 65000}, {'generic-node-descriptor-516': '0x0AFF0001'}],
                 [{'autonomous-system': 65010}, {'generic-node-descriptor-516': f'0x0AFF010{node}'}],
                 ['192.0.2.1'], ['192.0.2.2'],
                 {'generic-lsid-1101': [f'0xC0000000{30000 + node:06X}'], 'generic-lsid-1102': ['0xE0050000007594'],
                  'generic-lsid-1103': ['0xC00000000075F8']}) for node in range(1, NODES + 1)])
            # Prefixes: every node has both prefixes; the eight Prefix-SID indexes are all different.
            prefixes = sorted((router(nlri), nlri['ip-reach-prefix']) for nlri, _ in held['bgpls-prefix-v4'])
            self.assertEqual(prefixes, [(node, f'10.1.{index}.0/24') for node in range(1, NODES + 1) for index in (0, 1)])
            self.assertEqual(sorted(attribute['sids'][0] for _, attribute in held['bgpls-prefix-v4']),
                             list(range(100, 100 + 2 * NODES)))
            for _, attribute in held['bgpls-prefix-v4']:
                self.assertEqual(attribute['prefix-metric'], 20)
                self.assertEqual(attribute['sr-prefix-flags']['N'], 1)
                self.assertEqual(attribute['sr-prefix-attribute-flags'], {'X': 0, 'R': 0, 'N': 1, 'RSV': 0})
            # Locators and SRv6 SIDs of the first node.
            self.assertEqual(sorted(nlri['ip-reach-prefix'] for nlri, _ in held['bgpls-prefix-v6']),
                             [f'fc00:0:{index}::/48' for index in range(1, NODES + 1)])
            for _, attribute in held['bgpls-prefix-v6']:
                self.assertEqual(attribute['srv6-locator'], {'flags': {'D': 1, 'RSV': 0}, 'algorithm': 128, 'metric': 10})
            self.assertEqual(sorted(nlri['srv6-sid-descriptors']['srv6-sid'] for nlri, _ in held['bgpls-srv6sid']),
                             [f'fc00:0:1:{index}::' for index in range(1, NODES + 1)])
            for nlri, attribute in held['bgpls-srv6sid']:
                self.assertEqual(router(nlri), 1)
                self.assertEqual(attribute, {'srv6-endpoint-behavior': {'endpoint-behavior': 1, 'flags': [], 'algorithm': 0},
                                             'srv6-sid-structure': structure})
            self.candidate_paths(peer, '0000', 100, segments=True)
        # The peer without BGP-LS gets nothing, and bgpsim says why.
        self.assertEqual(self.peers[PLAIN_PEER].ls_routes(link(PLAIN_PEER)[0]), {})
        self.assertRegex(self.cli('show bgp neighbors'), r'links: withheld: .*not negotiated')

        # Edit the attributes of three ribouts and generate. Nothing is sent until the ribouts are advertised again.
        self.configure(
            'ribout links',
                'no ls',
                'ls igp-metric 10',
                'ls te-metric 999',
                'ls max-bandwidth 10g',
                'exit',
            'ribout prefixes',
                'no ls',
                f'ls prefix-sid flags n index 100 x {2 * NODES}',
                'ls prefix-metric 30',
                'exit',
            'ribout paths',
                'no ls',
                f'ls cp-state flags a,v preference 200 x {NODES}',
                'ls policy-name gold')
        self.cli('update generate')
        marks = {peer: len(self.peers[peer].messages()) for peer in LS_PEERS}
        self.wait_held(everything)
        # One script: a new link metric without adjacency or End.X SIDs, a new prefix metric, a new candidate path
        # state, and the SRv6 SIDs withdrawn.
        self.cli('run script churn')
        self.reaches(lambda: 'complete' in self.cli('show runs'), lambda: self.cli('show run 1'))
        after = {kind: count for kind, count in everything.items() if kind != 'bgpls-srv6sid'}
        self.wait_held(after)

        def changed():
            return all(attribute.get('te-metric') == 999 for peer in LS_PEERS
                       for _, attribute in self.held(peer)['bgpls-link'])

        self.reaches(changed, 'the links did not take the new TE metric')
        for peer in LS_PEERS:
            held = self.held(peer)
            for _, attribute in held['bgpls-link']:
                self.assertEqual(attribute, {'maximum-link-bandwidth': 1250000000.0, 'te-metric': 999, 'igp-metric': 10})
            self.assertEqual({attribute['prefix-metric'] for _, attribute in held['bgpls-prefix-v4']}, {30})
            self.assertEqual(sorted(attribute['sids'][0] for _, attribute in held['bgpls-prefix-v4']),
                             list(range(100, 100 + 2 * NODES)))
            for _, attribute in held['bgpls-prefix-v4']:
                self.assertNotIn('sr-prefix-attribute-flags', attribute)
            # Flags A and V are 0x4800; the edited block has no segment list.
            self.candidate_paths(peer, '4800', 200, segments=False)
            # The ribouts the script did not name are as they were.
            self.assertEqual({attribute['node-name'] for _, attribute in held['bgpls-node']}, {'r1'})
            self.assertEqual(sorted(attribute['generic-lsid-1101'][0] for _, attribute in held['bgp-link']),
                             [f'0xC0000000{30000 + node:06X}' for node in range(1, NODES + 1)])
            # Replacement is by re-announcement: the only routes withdrawn during the script are the SRv6 SIDs.
            withdrawn = [nlri for message in self.peers[peer].messages()[marks[peer]:]
                         for nlri in message['neighbor'].get('message', {}).get('update', {}).get('withdraw', {})
                         .get('bgp-ls bgp-ls', ())]
            self.assertEqual(sorted((nlri['ls-nlri-type'], nlri['srv6-sid-descriptors']['srv6-sid']) for nlri in withdrawn),
                             [('bgpls-srv6sid', f'fc00:0:1:{index}::') for index in range(1, NODES + 1)])

        # Selective re-advertisement, then the teardown of one peer: the other keeps its routes.
        self.cli(f'advertise ribout sids peer {link(1)[1]}')
        self.wait_held(everything, peers=(1,))
        self.wait_held(after, peers=(2,))
        self.cli(f'withdraw all peer {link(1)[1]}')
        self.wait_held({}, peers=(1,))
        self.wait_held(after, peers=(2,))
        for peer in self.peers.values():
            self.assertEqual(set(peer.states().values()), {'Established'})
            self.assertEqual(peer.downs(), 0)
            self.assertEqual(peer.log_events(), ([], []))

    def test_2_the_same_sessions_as_tshark_decodes_them(self):
        """Runs after the churn: the capture holds every UPDATE of the sessions, decoded by Wireshark's dissector."""
        # The last thing sent was the teardown of peer 1: the capture is complete when it holds all of it.
        last = {'types': 'bgp.ls.nlri_type'}
        teardown = f'ip.dst == {link(1)[1]} && bgp.update.path_attribute.type_code == 15 && bgp.ls.nlri_type'

        def flushed():
            return {kind for packet in self.capture.dissect(teardown, last) for kind in packet['types']} >= set('123456')

        self.captured(flushed, 'the capture does not hold the teardown of peer 1')
        self.assertEqual(self.capture.stop()[1], 0, 'tcpdump dropped packets')
        fields = {'behavior': 'bgp.ls.sr.tlv.srv6_endpoint_behavior.endpoint_behavior',
                  'block_len': 'bgp.ls.sr.tlv.srv6_sid_structure.locator_block_len',
                  'node_len': 'bgp.ls.sr.tlv.srv6_sid_structure.locator_node_len',
                  'function_len': 'bgp.ls.sr.tlv.srv6_sid_structure.fun_len',
                  'capability_o': 'bgp.ls.sr.tlv.srv6_capabilities.flags.o', 'endx': 'bgp.ls.sr.tlv.srv6_endx_sid.sid',
                  'endx_behavior': 'bgp.ls.sr.tlv.srv6_endx_sid.endpoint_behavior',
                  'endx_backup': 'bgp.ls.sr.tlv.srv6_endx_sid.flags.b',
                  'lan_neighbor': 'bgp.ls.tlv.srv6_endx_sid.neighbor_id_isis',
                  'locator_metric': 'bgp.ls.sr.tlv.srv6_locator.metric',
                  'locator_down': 'bgp.ls.sr.tlv.srv6_locator.flags.d',
                  'locator_algorithm': 'bgp.ls.sr.tlv.srv6_locator.algorithm', 'malformed': '_ws.malformed'}
        seen = {name: set(values) for name, values in self.capture.values('bgp', fields).items()}
        self.assertEqual(seen['malformed'], set())
        self.assertEqual((seen['behavior'], seen['block_len'], seen['node_len'], seen['function_len']),
                         ({'0x0001'}, {'32'}, {'16'}, {'16'}))
        # The one SRv6 flag ExaBGP 5.0 reads from the wrong bit.
        self.assertEqual(seen['capability_o'], {'True'})
        # End.X: function e001 in the /48 of each of the three nodes, and the LAN End.X SID with its IS-IS neighbor.
        self.assertEqual(seen['endx'], {'fc00:0:1:e001::', 'fc00:0:2:e001::', 'fc00:0:3:e001::', 'fc00:0:1:e100::'})
        self.assertEqual(seen['endx_behavior'], {'5'})
        self.assertEqual(seen['lan_neighbor'], {'0000.0000.0009'})
        # The End.X SID has the backup flag; the LAN End.X SID does not.
        self.assertEqual(seen['endx_backup'], {'True', 'False'})
        self.assertEqual((seen['locator_metric'], seen['locator_algorithm'], seen['locator_down']),
                         ({'10'}, {'128'}, {'True'}))

        # Flexible Algorithm definition of the nodes (RFC 9351): one node UPDATE for each node and BGP-LS peer, and
        # the same again in the teardown of peer 1 only if it carried attributes, which a withdrawal does not.
        flex = {'algorithm': 'bgp.ls.sr.tlv.flex_algo.flex_algorithm', 'metric_type': 'bgp.ls.sr.tlv.flex_algo.metric_type',
                'calculation': 'bgp.ls.sr.tlv.flex_algo.calculation_type', 'priority': 'bgp.ls.sr.tlv.flex_algo.priority',
                'exclude_any': 'bgp.ls.sr.tlv.flex_algo.exclude_any_affinity',
                'include_any': 'bgp.ls.sr.tlv.flex_algo.include_any_affinity',
                'include_all': 'bgp.ls.sr.tlv.flex_algo.include_all_affinity'}
        found = self.capture.values('bgp.ls.sr.tlv.flex_algo', flex)
        nodes = len(LS_PEERS) * NODES
        self.assertEqual([found[name] for name in ('algorithm', 'metric_type', 'calculation', 'priority')],
                         [['128'] * nodes, ['1'] * nodes, ['0'] * nodes, ['100'] * nodes])
        self.assertEqual([len(found[name]) for name in ('exclude_any', 'include_any', 'include_all')], [nodes] * 3)

        # BGP peering links (RFC 9086): protocol 7, the egress router and each of its peers by BGP Router-ID, and
        # one PeerNode SID label for each peer, on both BGP-LS peers. Each link has its own attributes, so its own
        # UPDATE.
        peering = {'protocol': 'bgp.ls.nlri_node.protocol_id', 'routers': 'bgp.ls.tlv.bgp_router_id.id',
                   'labels': 'bgp.ls.sr.tlv.peer.sid.label', 'value': 'bgp.ls.sr.tlv.peer.sid.flags.v',
                   'backup': 'bgp.ls.sr.tlv.peer.sid.flags.b', 'weights': 'bgp.ls.sr.tlv.peer.sid.weight'}
        found = self.capture.values('bgp.ls.sr.tlv.peer_node.sid', peering)
        # A segment can also hold UPDATEs of the IS-IS topology: count the NLRIs of protocol 7, one for each link.
        self.assertEqual(found['protocol'].count('7'), len(LS_PEERS) * NODES)
        routers, labels = found['routers'], [int(label) for label in found['labels']]
        links = sorted(zip(routers[0::2], routers[1::2], labels[0::3], labels[1::3], labels[2::3]))
        self.assertEqual(links, sorted([('10.255.0.1', f'10.255.1.{peer}', 30000 + peer, 30100, 30200)
                                        for peer in range(1, NODES + 1)] * len(LS_PEERS)))
        count = len(LS_PEERS) * NODES
        self.assertEqual((found['value'], found['backup'], found['weights']),
                         (['True'] * 3 * count, ['False', 'True', 'False'] * count, ['0', '5', '0'] * count))

        # SRv6 SID NLRI on the peer that was not torn down: announced, then withdrawn by the script, the same four
        # SIDs both times.
        sids = {'attributes': 'bgp.update.path_attribute.type_code', 'sids': 'bgp.ls.tlv.srv6_sid_info.sid'}
        packets = self.capture.dissect(f'ip.dst == {link(2)[1]} && bgp.ls.nlri_type == 6', sids)
        expected = [f'fc00:0:1:{index}::' for index in range(1, NODES + 1)]
        self.assertEqual([packet['sids'] for packet in packets], [expected] * 2)
        self.assertIn('14', packets[0]['attributes'])
        self.assertNotIn('15', packets[0]['attributes'])
        self.assertIn('15', packets[1]['attributes'])
        self.assertNotIn('14', packets[1]['attributes'])


if __name__ == '__main__':
   sys.exit(run_unittest())
