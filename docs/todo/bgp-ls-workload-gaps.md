# BGP-LS Workload Generator: Open Gaps

Date: 2026-11-12

The BGP-LS workload generator covers base topology and traffic engineering, SR-MPLS, SRv6, Flexible Algorithm, BGP
peering segments (EPE) and SR Policy state reporting. It is described in
[bgp-ls.md](../bgp-ls.md). This note lists what the original request asked for and is not done,
and the limits found while building it. Each item says what is missing and what would close it.

## Grammar

### 1. Two places still need hex

The request was that normal workloads need no hand-encoded hex.

- The SR Policy affinity constraint (TLV 1208, RFC 9857 section 5.6.1) has no name. It is written as
  `sub raw type 1208 value <hex>`. Its layout is three size octets, a reserved octet, then three lists of 32-bit
  words; the field kinds of the table cannot express the size octets.
- A segment's descriptor (RFC 9857 section 5.7.1.1) is `descriptor <hex>`. Types 1 and 2 are one algorithm octet.
  Types 3 to 11 carry addresses and interface identifiers.

Acceptance:

- `sub affinity exclude-any <group> ... include-any <group> ... include-all <group> ...` encodes TLV 1208, with a
  fixture written out from the RFC figure.
- A segment takes named descriptor fields for each of the eleven types, with one fixture for each type.

### 2. Attribute values vary only by adding one

`x <count>` and `per <axis>` add a number to one field. Other ribout attributes also have `rand()`, `each()` and
ranges; `ls` fields do not. Bandwidths, flags, SRLG lists, administrative groups and names cannot vary at all.

Acceptance:

- A sequence field accepts `each(a, b, c)` and a seeded `rand(low, high)`, with the same meaning they have for
  `localpref` and `med`.
- A list field (SRLG, administrative group) can take one of several lists.
- A sequence can add a stride other than one.

### 3. Topology shapes are a chain and a star

`step node` on a link moves both Router-IDs, so link i joins node i to node i + 1. `step remote` gives one node many
neighbors. There is no ring closure, full mesh or random graph. RFC 9552 section 5.2.2 describes a link as two
half-links; the reverse one is a second block written by hand with the nodes and addresses swapped.

Acceptance:

- One option on a link block also emits the reverse half-link of each link.
- A ring: the last node links back to the first.
- Decide whether a mesh or a random graph belongs in the grammar or in a script that writes blocks.

### 4. Size limits of one line

A TLV value is at most 255 octets (`BGP_RIBOUT_LS_VALUE_MAX`), and the text of a line at most 704 characters. The
text limit is reached first: about 14 segments in one segment list. A block has at most 64 lines, 6 sequences on a
line and 2048 octets of attribute.

Acceptance: a segment list of 32 segments can be configured, or the limit is documented as intended.

### 5. A line of the wrong NLRI type is refused late

`ls node-name r1` on a link block is accepted when it is entered and refused at `update generate`. The previous
snapshot stays in use, but the line stays in the configuration until it is removed. This matches `pmsi` and
`esi-label`, because an attribute line may be entered before the `nlri` line.

Acceptance: when the block already has its `nlri` line, a line of the wrong type is refused when it is entered. The
same change should cover the other family attributes.

### 6. A sequence must follow the fields of its TLV

`sub segment 1 label 16000 per node descriptor 00` is refused with "unknown field for this TLV", because `per` ends
the fields of the segment. The working form is `label 16000 descriptor 00 per node`.

Acceptance: the error names the rule, or the parser accepts fields after a sequence.

## Churn

### 7. A script cannot change attributes

A script step is advertise, withdraw, replay or sleep. Changing TE metrics or candidate path state is a
configuration edit and `update generate` before the script runs; the script then sends the new attributes. The
request asked for these changes "through one script".

Acceptance: decide between a script step that generates named ribouts and a step that selects one of several
prepared attribute sets of a ribout. Two ribouts with the same route keys cannot be bound to one peer, so prepared
variants need a design.

### 8. Withdrawal is for a whole ribout

A subset of the routes of one block cannot be withdrawn. To withdraw selected adjacency SIDs, put them in their own
block or advertise the block again without them.

Acceptance: decide whether a range of a block (`withdraw ribout links first 100`) is worth its cost in the TX
ownership model. If not, document the block-per-churn-unit pattern with an example.

## Clients and Receive Side

### 9. No typed Python helpers

`client.configure([...])` carries `nlri bgp-ls` and `ls` lines as text. There is no helper that builds them.

Acceptance: decide whether helpers add anything over text lines. If so, they return lines and add no new path to the
daemon.

### 10. Receive-side decode

The last step of the delivery order: decode received BGP-LS UPDATEs and inspect them from the Python client. Not
started.

## Verification

### 11. SR Policy state has no independent decoder

ExaBGP 5.0 and tshark 4.4 do not decode the SR Policy Candidate Path NLRI or the RFC 9857 TLVs. That feature group
rests on fixtures written out from the RFC figures, and on a comparison of ExaBGP's raw octets with those figures
in `test_interop_bgpls.py`.

Acceptance: when a decoder supports RFC 9857, the session test checks decoded fields instead of octets.

### 12. Decoder limits to recheck on upgrade

- ExaBGP 5.0.15 reads the O flag of the SRv6 Capabilities TLV with mask 0x0040. RFC 9352 section 2 puts it at
  0x4000. The session test checks that flag with tshark only. Not reported upstream yet.
- ExaBGP 5.0 reports Flexible Algorithm, the peering SIDs and the BGP Router-ID node descriptor as raw octets.
- FRR 10.3 has no BGP-LS family. Whether a newer FRR has one was not confirmed.

Acceptance: on a decoder upgrade, replace raw-octet checks by decoded fields where the decoder now has them, and
drop the tshark-only check of the O flag when ExaBGP is fixed.

### 13. Scale measurements are thin

Generation time has bench rows for each feature group (`bench_ribout_pipeline`). TX throughput and memory were
measured once, by hand, on macOS loopback, for one workload: 1M links, 74.9 MB written in 48 ms, 97 MiB RSS.

Acceptance:

- A repeatable TX and memory measurement on Linux for a node, link, prefix, SRv6 SID and candidate path workload.
- The message phase of a link is about twice that of an EVPN route for each path. Profile it again; each instance
  still copies the whole template.

### 14. Coverage not written

- Targeted regeneration (`update generate ribout <name>`, `update generate changed`) has no BGP-LS case. It is the
  shared mechanism, tested for other families.
- The heavy stress harness sends IPv4 and IPv6 unicast only. It has no BGP-LS ribout, with FRR or with ExaBGP.
- Fault injection covered the session, key-space, runtime, CLI and scale-lever checks. The byte fixtures of the
  encoder table were not mutation-tested one TLV at a time.
