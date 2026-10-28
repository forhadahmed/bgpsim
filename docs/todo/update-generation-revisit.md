# UPDATE Encoder Follow-Ups

Open items from the address-family-by-address-family review of the low-level
UPDATE encoders in `src/bgp_update*.c` against the RFC copies in `docs/rfcs/`.
The helpers that review added are part of the API in [bgp-update-api.md](../bgp-update-api.md).

## RTC

- `rtc_nlri_create*()` in `src/bgp_update_rtc.c` only exposes octet-aligned
  Route Target prefixes. RFC 4684 allows any RT prefix length up to 96 bits;
  sub-octet lengths are missing at the public helper layer.

## FlowSpec

- Mode 2 of draft-ietf-idr-ts-flowspec-srv6-policy needs a BGP Prefix-SID
  attribute encoder (SRv6 L3 Service TLV); bgpsim has none.
- `flowspec_op_value_t.value` is 32 bits, so the 8-octet numeric value form
  writes only 32 significant bits.
- ExaBGP 4.2.6 cannot decode (or encode) RFC 8956 prefixes with a non-zero
  offset: it reads ceil(length / 8) pattern octets and ignores the offset.

## BGP-LS

- Broader attribute TLV coverage: `src/bgp_update_ls.c` has descriptor helpers
  plus the generic `bgpls_tlv_create()`, and no typed constructors for the
  TLVs carried in the BGP-LS Attribute (type 29).

## MVPN

- `src/bgp_update_mvpn.c` has far fewer comments than the other encoders;
  continue the comment sweep to the same standard.
- Its route-type and AF checks carry no `TODO(FUZZ_GATE)` markers, unlike
  every other family.
- Decide whether tunnel-type-specific PMSI constructors add coverage over the
  generic `bgp_attr_create_pmsi_tunnel()`.

## Process

- Re-run the family-by-family RFC review whenever a helper surface is added,
  and keep attaching `TODO(FUZZ_GATE)` / `TODO(WIRE_MUTATION)` markers at the
  strict-validation and raw-wire choke points. [ribout-craft-grammar.md](ribout-craft-grammar.md#markers)
  defines what the markers mean.
