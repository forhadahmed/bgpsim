# Update Generation: Rotator Semantics and Decorrelation

## Background

[bgp-ribout.md](../bgp-ribout.md) ("Token Classes", "Overlay Rotation Rules") is the
reference for which tokens multiply `total_paths` (the NLRI-side odometer) and
which rotate. The fact that matters here: every attribute-side rotator reads
`values[idx % count]` from one shared path clock, advanced in
`bgp_ribout_generator_next()` in `src/bgp_ribout.c`. `rotate-every n` slows
that clock to one step per n paths and `rotate-period n` forces every rotating
list to the same length; both keep the rotators in lock-step on purpose.

## The Correlation Problem

All rotators share one clock (the path counter). Two rotators with counts `A`
and `B` produce only `lcm(A, B)` distinct pairings — with non-coprime counts,
many combinations are impossible.

Example: `next-hop x4, soo x2`:

```
Path 0: nh[0], soo[0]
Path 1: nh[1], soo[1]
Path 2: nh[2], soo[0]
Path 3: nh[3], soo[1]
Path 4: nh[0], soo[0]   <- cycle repeats

soo[0] ALWAYS pairs with nh[0] or nh[2]
soo[1] ALWAYS pairs with nh[1] or nh[3]
{nh[0], soo[1]} and {nh[1], soo[0]} never appear.
```

For stress-testing the purpose of multiple rotators is usually attribute
diversity. Users probably expect rotators to cycle independently.

## Related smaller issues

- **`uint32_t` overflow**: rotator indices are `uint32_t` but `total_paths` is
  `uint64_t`. With > 2^32 paths the rotators silently wrap and the pattern
  discontinuously resets.
- **Split range-mode advancement**: `localpref` / `med` in `range()` mode advance
  their index inside `ribout_u32_val()`, while list-mode rotators advance in the
  attribute-advance block of `bgp_ribout_generator_next()`. The
  `!spec.enabled` guards prevent double-increment but the logic is spread
  across two call sites.
- **EVPN Type 2 asymmetry**: label/esi/label2 are rotators for EVPN Type 2 but
  Cartesian for VPN / EVPN Type 5. Intentional and documented in
  [bgp-ribout.md](../bgp-ribout.md#overlay-rotation-rules), but Type 2 `label` takes no
  `rotate` keyword, so the config syntax still gives no hint.
- **`next_hop` can never be Cartesian**: no way to generate the full
  `prefix * next_hop` cross product. By design (next-hop is a path attribute,
  not NLRI identity), but limiting for some test scenarios.

## Options for Decorrelation

### Option 1 — Explicit stride: `x N + M`

```
next-hop 1.1.1.1 x 4 + 1
soo      65000:100 x 2 + 3
```

Internally: `values[(idx * stride) % count]`.

- Pro: explicit control.
- Con: user has to pick coprime strides manually. Mental model ("advance 3 at a
  time through 4 values") doesn't map to any networking concept. Still
  fundamentally limited by `gcd(count_a, count_b)` across rotators.

### Option 2 — Phase offset: `x N offset K`

```
next-hop 1.1.1.1 x 4
soo      65000:100 x 2 offset 1
```

Internally: `values[(idx + offset) % count]`.

- Pro: simplest syntax change.
- Con: doesn't actually decorrelate — just shifts the lock-step pattern.
  Weakest option.

### Option 3 — Automatic coprime stride (no syntax change) [RECOMMENDED FIRST]

Generator picks strides automatically at `generator_init` time. For the set of
active rotators, assign stride 1 to the first, then for each subsequent rotator
pick the smallest prime that is coprime to its count and distinct from prior
strides.

- Pro: zero user burden, backward compatible for single-rotator configs,
  breaks lock-step for common cases, ~10 LOC in `generator_init`.
- Con: still limited by shared factors in counts; sequential cycling property
  is slightly perturbed. Rotating key lists (`rd rotate`, `label rotate`, ...)
  and `rotate-period` depend on lock-step to keep one VRF's RD, label, route
  target and next hop together ([configuration.md](../configuration.md#rotate-period-n), `rotate-period`), so
  an automatic stride must exempt them.

Implementation sketch: add `stride` fields next to each rotator index in
`bgp_ribout_gen_t`, populate at init, change the `%` reads to
`(idx * stride) % count`.

### Option 4 — Cartesian promotion: `xx N` [RECOMMENDED LONG-TERM]

New syntax disambiguates rotator vs Cartesian:

```
ribout test
  prefix    10.0.0.0/24 x 100
  next-hop  1.1.1.1    xx 4        # Cartesian: 100 * 4 = 400 paths
  soo       65000:100  x 2         # rotator (unchanged)
```

`xx N` on an attribute-side token promotes it onto the NLRI odometer as an
outermost-level dimension (it multiplies `total_paths`). Its index is used
directly, not modulo.

- Pro: honest mental model (`x` = cycle, `xx` = multiply). Gives users explicit
  control when they actually need the full cross product. Also fixes the
  "can't cross-product prefix x next-hop" limitation.
- Con: more implementation work — odometer restructuring to accept a variable
  set of outermost Cartesian dimensions. Grouping key must still treat the
  token as attribute-side for the hash map (so each value produces its own
  bucket, which is the whole point).

### Option 5 — Hash-based decorrelation (no syntax change)

```c
// today:    values[gen->current_next_hop_idx % count]
// proposed: values[fnv1a(path_counter, rotator_token_seed) % count]
```

Each rotator gets a unique seed (e.g., hash of its token name) so they produce
independent pseudo-random index sequences from the shared path counter.

- Pro: truly independent rotators, zero config complexity, deterministic.
- Con: loses the predictable sequential cycling (nh0, nh1, nh2, nh0, ...);
  values appear in shuffled order. Harder to eyeball what's happening in
  generated output. Changes output for every existing multi-rotator config.

## Recommendation

Do **Option 3 first** as the quick fix — no syntax change, small diff,
improves all existing multi-rotator configs. Then do **Option 4 (`xx`)** as the
proper feature for users who need the full cross product.

Skip Option 5 — the loss of sequential cycling is a bigger debuggability cost
than its independence benefit.

## Separate follow-ups

- Widen rotator indices to `uint64_t` (or mod-reduce them after each increment
  against `lcm(counts)`).
- Consolidate the split range-mode advancement into a single pass so adding new
  spec/list dual-mode attributes doesn't require touching two code sites.
