# BGP Simulator Configuration Guide

This document is the syntax reference for `bgpsim` configuration files and
interactive config mode: the file format, the parser, and router and neighbor
configuration.

- [Ribout Configuration](ribout-configuration.md): ribout blocks and the tokens
  every family shares
- One page for each family with its own tokens: [EVPN](ribout-evpn.md),
  [SR Policy](ribout-sr-policy.md), [FlowSpec](ribout-flowspec.md),
  [RTC, VPLS and MVPN templates](ribout-templates.md) and [BGP-LS](bgp-ls.md)
- [Sending UPDATEs](sending-updates.md): snapshots, the advertise, withdraw and
  replay commands, standing advertisements, scripts and runs

For the exact ribout generation and packing model, see [bgp-ribout.md](bgp-ribout.md).

## File Format

- `#` and `!` start comments
- blank lines are ignored
- indentation is for readability only
- the same command set is used by config files and the live CLI

## Parser Behavior

The same token parser is shared by:

- exec mode
- config mode
- config-file command processing
- control-server command execution
- the foreground auto-attached CLI client

So the same command tables drive the interactive CLI, startup config loading,
the foreground and attached control paths, and the Python client.

Complete commands are limited to 1023 bytes, excluding the line ending, and to
32 whitespace-separated tokens. Matched keywords and individual typed
arguments are limited to 63 bytes; free-form command tails, including NLRI
hex payloads and attribute sets, can contain longer tokens within the overall
line limit. Oversized input is rejected as a whole, never executed as a
truncated prefix or as multiple configuration commands. Long value lists, such
as an `as-path` with more than 31 ASNs, do not fit on one line.

The parser supports:

- fixed keywords
- typed arguments such as integers, strings, and IP addresses
- optional tokens
- router-style abbreviations when the prefix is unambiguous

Exact keyword matches beat prefix matches. For example, `rt` resolves as `rt`
instead of colliding with `rt-set`.

## Configuration Modes

The CLI uses these hierarchical modes:

- exec mode
- global config mode
- router mode
- neighbor mode
- ribout mode
- script mode

Enter config mode from exec mode with:

```text
config
configure terminal
```

Leave config mode with:

```text
exit
end
```

Most config commands also support a `no` form to remove or reset the property.

## Router and Neighbor Configuration

### Router Block

```text
router bgp <as>
  router-id <ipv4>
  vrf <name>
  update-source <ip>
  neighbor <ip> remote-as <as>
!
```

Commands:

- `router bgp <as>`
- `router-id <ipv4>`
- `vrf <name>`, `no vrf [<name>]`
- `update-source <ip>`: the IPv4 or IPv6 source address of the router's sessions
- `neighbor <ip> remote-as <as>`
- `no neighbor <ip> remote-as <as>`
- `no router bgp <as>`

### VRFs

`vrf <name>` puts the sockets of a router in an existing Linux network
namespace. bgpsim opens `/var/run/netns/<name>` exactly as written. It never
creates, changes, or deletes a namespace, so create the namespace, its
interfaces, and its addresses separately, for example with `ip netns add`.

```text
router bgp 100
  neighbor 192.0.2.2 remote-as 65002
!
router bgp 200
  vrf BLUE
  neighbor 198.51.100.2 remote-as 65002
!
```

- A router has one VRF, and a router without `vrf` uses bgpsim's own namespace.
  One local AS is therefore in one VRF per process. Several routers can share a
  VRF, and the same peer address can exist on routers in different VRFs.
- `vrf <name>` applies at any time, also to a router with neighbors, and the same
  name again changes nothing. `no vrf` returns the router to bgpsim's own namespace
  the same way. `no vrf <name>` does too, and is rejected when the router is not in
  that VRF.
- A socket cannot change namespace, so a change resets every session of the router
  (shown in `Session resets`), and the sessions reconnect in the new namespace with
  the reconnect backoff. With `--passive`, the listener moves there too. Neighbor
  configuration stays, and standing advertisements are sent again when the session
  is Established. A ribout advertised by a command or a script is not, and a script
  step that is sending to those peers fails.
- A local AS is one router, so a second `router bgp` block for that AS re-enters it.
  The last `vrf` applies to all of its neighbors. Two routers in different VRFs need
  two local ASes.
- A name up to 63 characters is accepted, except `/`, `.`, `..`, and the reserved
  selector words `all` and `default`.
- `show running-config` prints `vrf <name>`. The router lines of `show bgp summary`
  and the neighbor lines of `show bgp neighbors` end in `, VRF <name>`.
- bgpsim does not check at configuration time that the namespace exists. When it
  cannot be opened, the peers stay down and retry with the reconnect backoff,
  the error is logged once, and `show bgp summary` prints
  `VRF <name> is not available (<reason>), retrying`. A namespace created later
  is used by the next retry.
- Each new socket opens the namespace by name, so a namespace that was deleted
  and created again is used by the next connection.
- The connecting sockets and, with `--passive`, the listener are in the VRF. An
  `update-source` address must exist in the VRF. When it does not,
  `show bgp neighbors` prints `Update-source <ip> is not usable (<reason>),
  retrying`.
- This needs Linux, and root or `CAP_SYS_ADMIN`. Other routers need neither. On
  other systems the command is accepted and the peers report
  `operation not supported on socket`.

`clear bgp` takes the same scope as the commands that send UPDATEs:
`clear bgp [router <local-as> | vrf <name|all|default>] <neighbor|*>`. Without a
scope it clears that neighbor on every router. It closes the TCP connection and
sends no NOTIFICATION. Add `cease [<text>]` to send one first; see
[Session Control](#session-control).

### Neighbor Submode

After `neighbor <ip> remote-as <as>`, the CLI enters neighbor mode.

Commands:

- `advertise <ribout>`
- `address-family ipv4`
- `address-family ipv6`
- `address-family ipv4 labels`
- `address-family ipv6 labels`
- `address-family vpnv4`
- `address-family vpnv6`
- `address-family l2vpn evpn`
- `address-family ipv4 flowspec`
- `address-family ipv6 flowspec`
- `address-family ipv4 flowspec-vpn`
- `address-family ipv6 flowspec-vpn`
- `address-family ipv4 srpolicy`
- `address-family ipv6 srpolicy`
- `address-family bgp-ls`
- `address-family ipv4 mvpn`
- `address-family ipv6 mvpn`
- `address-family ipv4 rtc`
- `address-family l2vpn vpls`
- `capability graceful-restart`
- `capability graceful-restart restart-time <seconds>`
- `capability route-refresh`
- `capability extended-message`
- `capability four-byte-asn`
- `capability add-path`
- `capability add-path <af>`
- `capability ext-nh`
- `capability ext-nh <af>`
- `hold-time <seconds>`
- `shutdown [<text>]`
- `ttl-security hops <hops>`
- `password <text>`
- `update-source <ip>`

Matching `no` forms are supported.

Notes:

- `advertise <ribout>` adds a standing advertisement: the neighbor sends the
  ribout's current snapshot whenever its session is Established. A neighbor
  keeps them in config order, each on its own running-config line.
  `no advertise <ribout>` removes one without withdrawing what was sent. See
  [Standing Advertisements](sending-updates.md#standing-advertisements).
- `address-family ipv4` and `address-family ipv6` are enabled by default for
  new neighbors, so they are optional boilerplate
- `capability four-byte-asn` (RFC 6793) is on by default; `no capability
  four-byte-asn` is rejected while the local or remote AS exceeds 65535.
  A session without it on both sides takes only the ribouts that have
  [`as-path two-byte`](ribout-configuration.md#as-path-two-byte-segments):
  a 2-octet AS_PATH with AS4_PATH
- `capability extended-message` (RFC 8654) is off by default. When the peer
  advertises it too, bgpsim reads messages of up to 65535 octets from the peer
  (an OPEN stays at 4096), and sends it the ribouts that have
  [`message-size`](ribout-configuration.md#message-size-octets) above 4096.
  Without it, a message above 4096 octets from the peer is answered with Bad
  Message Length
- `capability add-path` enables ADD-PATH for all supported neighbor families
- `capability add-path <af>` enables ADD-PATH for one address family
- `capability ext-nh` enables RFC 8950 extended next-hop for all eligible
  neighbor families
- `capability ext-nh <af>` enables RFC 8950 extended next-hop for one eligible
  family
- `hold-time` and `shutdown` are described under
  [Session Control](#session-control); `ttl-security` and `password` under
  [Transport Options](#transport-options)
- `update-source <ip>` in neighbor mode sets the source address of that
  neighbor's session, in place of the router's `update-source`

Supported `<af>` values:

- `ipv4`
- `ipv6`
- `ipv4 labels`
- `ipv6 labels`
- `vpnv4`
- `vpnv6`
- `l2vpn evpn`
- `ipv4 flowspec`
- `ipv6 flowspec`
- `ipv4 flowspec-vpn`
- `ipv6 flowspec-vpn`
- `ipv4 srpolicy`
- `ipv6 srpolicy`
- `bgp-ls`
- `ipv4 mvpn`
- `ipv6 mvpn`
- `ipv4 rtc`
- `l2vpn vpls`

`capability ext-nh <af>` is currently valid for:

- `ipv4`
- `ipv4 labels`
- `vpnv4`

### Session Control

```text
router bgp 65001
  neighbor 192.0.2.2 remote-as 65002
    hold-time 30
    shutdown maintenance window
!
```

`hold-time <seconds>` sets the Hold Time that bgpsim proposes in its OPEN. The
default is 180.

- The value is 0, or 3 to 65535 (RFC 4271 section 4.2). 1 and 2 are refused.
- The session uses the smaller of this value and the peer's. bgpsim sends a
  KEEPALIVE every third of the negotiated value, and sends Hold Timer Expired
  when the peer is silent for the whole of it.
- With a negotiated value of 0, neither side sends KEEPALIVEs and the session
  never expires.
- A change resets a session that is up, so the next OPEN carries the new value.
  The same value again changes nothing. `no hold-time` restores 180.
- `show bgp neighbors` prints the negotiated value, and the configured value
  when it is not 180.

`shutdown [<text>]` holds a neighbor down.

- A session that is up gets a Cease NOTIFICATION with subcode 2, Administrative
  Shutdown (RFC 4486). The text, up to 255 octets, is sent as its Shutdown
  Communication (RFC 9003). Without text the NOTIFICATION has no data.
- bgpsim then makes no connection to the neighbor and closes any connection the
  neighbor makes, without sending an OPEN.
- `show bgp neighbors` prints `BGP state = Idle (administratively shut down)`,
  and `show running-config` prints the `shutdown` line with its text.
- `no shutdown` connects again at once. Standing advertisements are sent when
  the session is Established.

`clear bgp [<scope>] <neighbor|*> cease [<text>]` resets a session and tells the
peer why: it sends a Cease NOTIFICATION with subcode 4, Administrative Reset,
with the text as its Shutdown Communication, and then connects again. A neighbor
with no open session is reset as by plain `clear bgp`.

Removing a neighbor, removing a router, and stopping bgpsim close the TCP
connection and send no NOTIFICATION.

### Transport Options

```text
router bgp 65001
  neighbor 192.0.2.2 remote-as 65002
    ttl-security hops 1
    password s3cret
!
```

Both commands set options on the TCP socket of the session. A change resets a
session that is up, and the same value again changes nothing.

`ttl-security hops <hops>` turns on the Generalized TTL Security Mechanism
(RFC 5082) for the neighbor.

- `<hops>` is 1 to 254: the number of hops to the neighbor, 1 for a directly
  connected one.
- bgpsim sends every packet of the session with TTL 255, or Hop Limit 255 for
  an IPv6 neighbor.
- On Linux the socket also drops what arrives with a TTL under 256 minus
  `<hops>`. The peer must then send with TTL 255 too, which a peer with TTL
  security does. Other systems have no such socket option: there bgpsim sends
  TTL 255 and accepts any TTL.
- `show bgp neighbors` prints
  `TTL security: 1 hop, sends TTL 255, accepts 255 or more`, or on a system
  without the option `... accepts any TTL`.
- `no ttl-security` returns to the system's default TTL.

`password <text>` signs the TCP segments of the session with TCP MD5
(RFC 2385), and accepts only segments the peer signed with the same key.

- The text is the key, up to 80 octets. It can contain spaces. Some peers,
  FRR among them, take a key of one word only.
- `show running-config` prints the text as it was entered.
  `show bgp neighbors` prints `TCP MD5 password is set`.
- This needs Linux, where a socket holds one key for each peer address. On
  other systems the command is accepted and the neighbor stays down;
  `show bgp neighbors` prints `ttl-security or password is not usable
  (operation not supported on socket), retrying`.
- `no password` removes the key.

With `--passive`, the listener holds the key of each neighbor, so a signed
connection from a neighbor is accepted. The listener answers a SYN before it
knows the neighbor, with the system's default TTL, and sets TTL security on the
connection after it is accepted. A peer that drops a SYN-ACK with a TTL under
255 does not connect to a passive bgpsim. On systems other than Linux, a
passive bgpsim refuses the session of an IPv4 neighbor that has `ttl-security`.

### Router Example

```text
router bgp 65001
  router-id 10.0.0.1
  update-source 10.0.0.1
  neighbor 192.0.2.2 remote-as 65002
    address-family ipv4
    address-family ipv4 labels
    address-family vpnv4
    capability route-refresh
    capability graceful-restart restart-time 180
    capability add-path
    capability ext-nh
    advertise cust-a-vpn4
!
```

## Useful Exec Commands

After configuring ribouts and neighbors:

- `update generate`
- `show ribout`
- `show ribout <name> preview <count>`
- `show ribout-map <name>`
- `show running-config`
- `advertise ribout <name> peer <ip|all>` and the other
  [send commands](sending-updates.md#exec-commands)
- `show bgp neighbors` for the outbound state of each peer
