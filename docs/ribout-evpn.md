# EVPN Ribouts

An EVPN Type 2 or Type 5 block is made of tokens, and the family follows from
them, as [Family Inference](ribout-configuration.md#family-inference)
describes. Types 1, 3 and 4 are typed templates with one `nlri evpn` line.
They are on the [templates page](ribout-templates.md), with `esi-label`,
`es-import`, `pmsi` and a multihoming example.

| Route | Tokens |
| --- | --- |
| Type 2 | `rd` and `mac`; optional `ip`, `ethernet-tag`, `esi`, `label`, `label2` |
| Type 5 | `prefix` and `rd`, with `ethernet-tag`, `gateway-ip` or `esi` |
| Types 1, 3, 4 | `nlri evpn type1`, `type3` or `type4` |

The shared tokens work as on every family:
[`rd`](ribout-configuration.md#rd-rotate-values),
[`label`](ribout-configuration.md#label-values),
[`next-hop`](ribout-configuration.md#next-hop-ip-prefix-x-count-link-local-ipv6),
[`rt`](ribout-configuration.md#rt-values),
[`rt-set`](ribout-configuration.md#rt-set-sets), the AS path and the other
attributes. The tokens below belong to EVPN.

## Tokens

### `mac <mac|u64> [x <count>]`

Set EVPN Type 2 MAC-address values. Decimal `u64` shorthand is zero-extended
into the 48-bit MAC field.

Examples:

```text
mac 00:11:22:33:44:00
mac 1
mac 00:11:22:33:44:00 x 1024
mac 1 x 1024
```

### `ip [rotate] <ip> [x <count>]`

Set EVPN Type 2 optional IP-binding values. Several IPs multiply the routes:
each MAC is generated with each IP. With `rotate` MAC i is bound to IP i
instead (mod the IP count; MACs counted over the RD, Ethernet tag and MAC
tuples): one MAC/IP binding per host.

A ribout holds one `ip` line per address family: a line of the other family
adds a second, so every MAC is generated with an IPv4 and an IPv6 binding
(dual-stack hosts, two routes per MAC, IPv4 first); a line of a family already
set replaces it, and `no ip` removes both. Type 2 `label`, `label2` and
`rt-set` rotate per path, so add `rotate-every 2` to give a dual-stack host's
two routes the same labels and route targets.

Examples:

```text
ip 10.0.0.1
ip 10.0.0.1 x 256
ip 2001:db8:10::1 x 256
ip rotate 10.1.0.1 x 1024
ip rotate 2001:db8:20::1 x 1024
```

### `ethernet-tag [rotate] <values>`

Set EVPN Ethernet Tag values (Type 5, and Type 2). With `rotate` route i takes
tag i mod n; with `rd rotate` of the same length each VRF's RD and tag go
together. A Type 2 `ip rotate` counts MACs without the tag dimension then, so
MAC i still binds IP i. `max` is MAX-ET (4294967295), here and in an `nlri`
template.

Examples:

```text
ethernet-tag 0
ethernet-tag 0 100 200
ethernet-tag 0 x 16
ethernet-tag rotate 100 x 16
```

### `esi <esi|hex|u64> [x <count>] | <esi|hex|u64>...`

Set EVPN ESI values. Accepted forms are canonical `aa:bb:...` 10-octet ESI,
compact 20-digit hex without separators, or decimal `u64` shorthand
zero-extended into the 80-bit ESI field.

Examples:

```text
esi 00:00:00:00:00:00:00:00:00:01
esi 00112233445566778899
esi 0 x 16
```

### `label2 <values>`

Set EVPN Type 2 optional Label2 values: MPLS labels, or VNIs up to 16777215 with a VXLAN-like `encap`, as for `label`.

Examples:

```text
label2 40000
label2 40000 40001
label2 40000 x 8
```

### `gateway-ip <ip-prefix> [x <count>]`

Set EVPN Type 5 gateway IP values.

Examples:

```text
gateway-ip 10.255.0.1
gateway-ip 10.255.0.1 x 8
gateway-ip 2001:db8:ffff::10
```

### `encap <values>`

Set EVPN Encapsulation extended-community values. Common names such as
`vxlan`, `nvgre`, `gre`, `mpls-in-gre`, and `l2tpv3` are accepted, or a raw
numeric tunnel type can be used. `mpls` is tunnel type 10. `encap` is valid on every EVPN
route type, 1 to 5 (RFC 8365 section 5.1.3).

The encap also sets the form of the EVPN label fields (`label`, `label2`). With
`vxlan`, `nvgre`, `12` (VXLAN-GPE) or `19` (Geneve) they carry the 24-bit VNI
itself (RFC 8365 section 5.1.3): `label 30000` goes on the wire as `00 75 30`.
With any other encap, or none, they carry MPLS labels: `07 53 01`. Several
values rotate per path, and each path's labels follow its own encap.

The same rule applies to the `label` of an EVPN Type 1 template and to the
`pmsi` label of an EVPN Type 3 route. A value above 1048575 is accepted only
when every `encap` value of the ribout is a VNI tunnel. The order of the
`encap`, `nlri` and `pmsi` lines does not matter.

Examples:

```text
encap vxlan
encap vxlan nvgre
encap 8 9
```

### `router-mac <mac|u64> [x <count>]`

Set EVPN Router's MAC extended-community values, on EVPN Type 2 and Type 5
ribouts only. These are attr-side rotators;
they do not change route identity, but they do split attribute groups. Decimal
`u64` shorthand is zero-extended into the 48-bit MAC field.

Examples:

```text
router-mac 02:00:00:00:00:01
router-mac 1
router-mac 02:00:00:00:00:01 02:00:00:00:00:02
router-mac 1 2
router-mac 02:00:00:00:00:01 x 16
```

### `mac-mobility <sequence> [sticky]` and `default-gateway`

Add the MAC Mobility and Default Gateway extended communities (RFC 7432
sections 7.7 and 7.8) to every route of an EVPN Type 2 ribout. `sticky` sets
the flag of a static MAC. To move a MAC, enter a larger sequence number, then
generate and advertise the ribout again: the receiver takes the route with
the larger number.

```text
mac-mobility 5
mac-mobility 6 sticky
default-gateway
```

Both are described with the other extended community lines on the
[ribout configuration page](ribout-configuration.md).

## Examples

EVPN Type 5:

```text
ribout demo-evpn5
  prefix 192.168.0.0/24 x 100
  rd 65000:300
  label 30000
  ethernet-tag 0
  gateway-ip 10.255.0.1 x 2
  rt-set [65000:300] [65000:301,65000:302]
  encap vxlan
  router-mac 02:aa:bb:cc:dd:ee
  next-hop 192.0.2.10
  med rand(25)
  origin igp
!
```

EVPN Type 2:

```text
ribout demo-evpn2
  rd 65000:400 x 8
  ethernet-tag 100 200
  mac 00:11:22:33:44:00 x 1024
  ip 10.0.0.1 x 2
  label 30000 30001
  label2 40000 40001
  esi 00:11:22:33:44:55:66:77:88:99
  rt-set [65000:400] [65000:401,65000:402]
  encap vxlan nvgre
  router-mac 02:00:00:00:00:01 02:00:00:00:00:02
  next-hop 192.0.2.10 x 4
  localpref range(150,153)
  origin igp
!
```
