# TODO: Move Capability Apply Logic Into Neighbor Core APIs

## Goal

Refactor neighbor capability/config mutation so OPEN-renegotiated settings are
applied through explicit core neighbor APIs instead of being changed directly in
the CLI/command layer.

This is a cleanup/refactor task, not a functional gap. The current behavior is
correct enough, but the ownership is slightly too high in the stack.

## Current State

Neighbor capability changes are currently handled in `src/commands.c`.

The pattern today is:

1. CLI/parser matches a config command.
2. The command handler directly mutates `neighbor->capabilities`.
3. The handler compares old/new values locally.
4. If the neighbor session is live, the handler calls `bgp_clear_neighbor()`
   so the session re-establishes and renegotiates OPEN.

Central helper logic already exists in `src/commands.c`:

- `command_update_capability_int()`
- `command_update_capability_u8()`
- `command_neighbor_session_live()`
- `command_restart_neighbor_if_live()`

That logic is currently used by these neighbor-level OPEN-negotiated settings:

- `address-family ...`
- `capability route-refresh`
- `capability graceful-restart`
- `capability add-path`
- `capability ext-nh`
- `capability four-byte-asn`

## Why Refactor

The current implementation works, but the CLI layer owns too much of the apply
semantics.

That has a few downsides:

- every command handler must remember to do the old/new comparison correctly
- every handler must remember to trigger a live-session reset when needed
- any future non-CLI caller would need to duplicate the same logic
- capability-apply behavior is spread across several handlers instead of being
  owned by the neighbor/core layer

The parser is not the issue here. The parser should keep parsing commands and
passing them to handlers. The cleanup is about where the mutation semantics
live.

## Desired End State

The command layer should parse intent and call explicit core apply/setter APIs.

The core neighbor layer should own:

- comparing old vs new capability state
- applying the mutation
- deciding whether a live session must reset to renegotiate OPEN
- suppressing restart during config-file load

The command layer should not directly write capability struct fields for these
OPEN-negotiated settings.

## Important Constraint

Do not implement this as "the neighbor thread notices field changes later".

That would be worse than the current design because it introduces implicit
side-effects and makes behavior harder to reason about.

If this is refactored, it should be done with explicit apply/setter calls in
the core neighbor layer.

## Proposed Shape

Add explicit helper APIs in `src/bgp_neighbor.c` / `src/bgp_neighbor.h`.

Possible shape:

```c
typedef struct {
    int defer_restart;
} bgp_neighbor_apply_opts_t;

int bgp_neighbor_set_af_enabled(bgp_neighbor_t *neighbor,
                                size_t mp_offset,
                                int enabled,
                                const bgp_neighbor_apply_opts_t *opts);

int bgp_neighbor_set_route_refresh(bgp_neighbor_t *neighbor,
                                   int enabled,
                                   const bgp_neighbor_apply_opts_t *opts);

int bgp_neighbor_set_graceful_restart(bgp_neighbor_t *neighbor,
                                      int enabled,
                                      uint16_t restart_time,
                                      const bgp_neighbor_apply_opts_t *opts);

int bgp_neighbor_set_add_path_mode(bgp_neighbor_t *neighbor,
                                   size_t add_path_offset,
                                   uint8_t mode,
                                   const bgp_neighbor_apply_opts_t *opts);

int bgp_neighbor_set_ext_nh(bgp_neighbor_t *neighbor,
                            size_t ext_nh_offset,
                            int enabled,
                            const bgp_neighbor_apply_opts_t *opts);

int bgp_neighbor_set_four_byte_asn(bgp_neighbor_t *neighbor,
                                   int enabled,
                                   const bgp_neighbor_apply_opts_t *opts);
```

Notes:

- Return value should indicate whether the capability state actually changed.
- Restart should happen inside these helpers when:
  - the value changed
  - the neighbor is live
  - restart is not deferred
- `graceful-restart` should be treated atomically as:
  - enable/disable
  - restart time

## Config-Load Handling

Current behavior correctly avoids live restarts during config-file load.

That must remain true.

Two acceptable ways to preserve it:

1. Pass `defer_restart=1` from config-file apply paths.
2. Pass the `cmd_ctx->sim->config_loading` state down as part of apply options.

Avoid making the core setter APIs depend on CLI types like `cmd_ctx_t`.

## Where To Call The Core APIs

After this refactor, `src/commands.c` should:

- keep parsing/extracting command arguments
- keep validation that is CLI/config specific
- call the new core apply helpers
- stop writing `neighbor->capabilities` fields directly for the affected knobs

It is fine for command handlers to keep some pre-validation before calling the
core layer. Example: `no capability four-byte-asn` should still reject
disabling four-byte ASN when local or remote ASN exceeds 65535.

## Suggested File Touches

Expected main files:

- `src/bgp_neighbor.h`
- `src/bgp_neighbor.c`
- `src/commands.c`

Possibly small test updates in:

- `tests/test_cli_config.c`
- `tests/test_shell_smoke.py`

## Behavior That Must Not Change

- live session resets still happen for all OPEN-negotiated neighbor capability
  changes
- config-file load does not thrash sessions during parse
- `no capability four-byte-asn` still rejects invalid OLD-speaker cases
- parser/CLI grammar does not change
- `show running-config` behavior does not change

## Tests To Keep Or Add

Existing coverage:

- `test_four_byte_asn_live_toggles_with_fresh_clients` in
  `tests/test_shell_smoke.py` toggles `capability four-byte-asn` on a live
  session and asserts the reset
- `tests/test_cli_config.c` sets the other five knobs and asserts the stored
  field values only

To add, so the refactor cannot silently drop a reset:

- live restart for `address-family`, `route-refresh`, `graceful-restart`,
  `add-path`, and `ext-nh`
- no restart during config-file load

## Acceptance Criteria

- no direct capability-field mutation remains in `src/commands.c` for the
  OPEN-negotiated neighbor knobs listed above
- live restart behavior is preserved
- config-file load behavior is preserved
- unit/integration tests remain green

## Priority

Nice cleanup, not urgent.

The current implementation is acceptable. This refactor only becomes worth
doing when the code is being touched again or when a new non-CLI control path
would otherwise duplicate the same apply/restart logic.
