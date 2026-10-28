# CLI Tree Refactor Suggestions

## Scope

This note is based on the current `main` implementation in:

- [src/parser.c](../../src/parser.c)
- [src/parser.h](../../src/parser.h)
- [src/commands.c](../../src/commands.c)
- [src/commands.h](../../src/commands.h)
- [src/cli.c](../../src/cli.c)
- [src/config.c](../../src/config.c)

The goal here is not to replace the current declarative command tables.
The goal is to explore whether the runtime representation should become
tree-shaped even if command authoring stays flat.

## Executive Summary

The current command authoring format is good:

- flat `cmd_def_t[]` tables are easy to read
- full command variants are explicit
- per-mode tables keep command scope understandable

The current runtime representation is less natural:

- the parser re-infers tree structure by scanning full command rows
- completion re-infers "what comes next?" from repeated prefixes
- root keywords like `show`, `clear`, `capability`, and `address-family`
  need extra grouping logic because the structure is not first-class

The best next-step design, if this area is revisited, is:

1. keep flat command tables as the source of truth
2. compile each command table once into an internal immutable tree
3. use the tree for:
   - execution matching
   - incomplete / ambiguous detection
   - `?` and TAB discovery
   - help rendering

This would help `help` / `?` / TAB much more than it would help mode rewind.

## Current State

Today the system is already cleaner than before:

- per-mode tables are explicit in [src/commands.c](../../src/commands.c)
- ribout tails are first-class through `TOKEN_TAIL` in
  [src/parser.h](../../src/parser.h)
- reachable command surfaces are explicit through
  `command_collect_reachable_tables()` in
  [src/commands.c](../../src/commands.c)

But the runtime is still fundamentally row-scan based:

- `parser_execute()` scans every command definition and compares full rows in
  [src/parser.c](../../src/parser.c)
- `parser_find_matches()` also scans every command definition and reconstructs
  the next-token view from repeated prefixes in
  [src/parser.c](../../src/parser.c)
- root keyword grouping like `show commands` is inferred after the fact in
  `completion_set_group_help()` in
  [src/parser.c](../../src/parser.c)

So the code has a tree-shaped user surface, but a flat internal search model.

## Where A Tree Would Help

### 1. `?` and TAB discovery

This is the strongest argument for a tree.

Current completion has to reconstruct the next valid token by:

- matching every candidate row prefix
- retaining only the best-ranked candidates
- then deduping their next token

See `parser_find_matches()` in
[src/parser.c](../../src/parser.c).

In a tree, this becomes direct:

- traverse to the current node
- list its children
- show `<cr>` if the node is also a valid leaf

That would simplify:

- `show bgp ?`
- `show ribout foo ?`
- root-keyword grouping
- incomplete-command detection
- future dynamic completions

### 2. Root/shared prefixes

These are conceptually internal nodes today:

- `show`
- `clear`
- `config`
- `capability`
- `address-family`

But in the current flat model they are only implied by repeated rows.
That is why special-case grouping is needed to produce:

- `show commands`
- `capability commands`
- `address-family commands`

In a tree, those nodes would exist naturally.

### 3. Incomplete vs unknown vs ambiguous behavior

Today `parser_execute()` tracks:

- full matches
- incomplete prefixes
- lexicographic keyword rank

That works, but it is still reconstructing a hierarchy from flattened rows.

In a tree:

- traversal ending at a non-leaf internal node is `Incomplete Command`
- traversal ending nowhere is `Unknown Command`
- traversal landing on multiple equally valid continuations can surface as
  completion ambiguity without rescanning the whole table

### 4. Future dynamic completions

If the CLI later wants live-value suggestions such as:

- `router bgp ?` showing existing configured ASNs
- `ribout ?` showing existing ribout names
- `clear bgp ?` showing known neighbors
- `advertise ?` showing known ribouts

the natural place to hang that behavior is a tree node or edge, not a
row-scanned flat-table helper.

## Where A Tree Would Not Help Much

### Mode rewind

Mode rewind is currently governed by:

- `command_execute()` in [src/commands.c](../../src/commands.c)
- `command_collect_reachable_tables()` in
  [src/commands.c](../../src/commands.c)

That logic is about search scope:

- current config mode
- parent config modes
- optional exec fallback from global config

A tree does not materially simplify that policy.
You still need:

- one command surface per config mode
- one exec command surface
- the same unwind / restore rules

So this refactor should not be sold as a mode-rewind optimization.
It is mainly a parser/discoverability improvement.

### Command authoring

The current flat `cmd_def_t[]` format is still the right authoring model.
Hand-authoring a runtime tree would be worse:

- more verbose
- harder to review
- easier to drift

The value is in a compiled tree, not a hand-maintained one.

## Recommended Design

### Keep flat source tables

Continue to author commands in the current style:

- `cli_exec_commands[]`
- `global_config_commands[]`
- `router_bgp_commands[]`
- `neighbor_commands[]`
- `ribout_commands[]`
- `script_commands[]`

This stays the single source of truth.

### Compile each table into a runtime tree

At startup or static init time, compile each table into an internal immutable
tree representation.

The parser and completion code then traverse trees, not raw arrays.

The natural boundaries are:

- one tree for EXEC
- one tree for global config
- one tree for router config
- one tree for neighbor config
- one tree for ribout config
- one tree for script mode

### Preserve `TOKEN_TAIL`

This is critical.

The runtime tree should not try to force ribout back into fake fully-tokenized
grammar. `TOKEN_TAIL` is already the right abstraction for:

- `prefix`
- `rd`
- `label`
- `path-id`
- `next-hop`
- `as-path`
- `rt-set`
- other ribout mini-language entries

In a tree, that simply means:

- keyword node
- then one tail edge
- then a leaf command

## Suggested Internal Shape

The internal representation does not need to be exposed publicly.

A reasonable private structure would look like:

- node
  - keyword children
  - optional typed parameter child
  - optional tail child
  - optional leaf command pointer
  - optional internal help/group label

Important constraints:

- keyword edges must preserve exact-vs-prefix matching semantics
- typed parameter edges must coexist cleanly with keyword edges
- tail edges must be terminal and own the rest of the line

This is not just a pure string trie.
It is a small typed command graph.

## What Would Simplify

If trees are introduced, the following current logic should shrink:

- the row-scan matching loop in `parser_execute()`
- the row-scan next-token reconstruction in `parser_find_matches()`
- root-keyword grouping in `completion_set_group_help()`
- some of the "best prefix rank" bookkeeping in
  [src/parser.c](../../src/parser.c)

The code would also read closer to user intent:

- traverse command path
- ask current node what can happen next

instead of:

- scan rows
- compute best prefix matches
- dedupe next tokens

## What Would Stay The Same

Several existing concepts should survive unchanged:

- `cmd_def_t` as authoring format
- `TOKEN_TAIL`
- per-mode command surfaces
- `supports_no`
- `command_execute()` owning mode rewind and exec fallback policy
- `command_collect_reachable_tables()` or a close equivalent

That last point may be renamed if trees are introduced, but the concept of
"reachable surfaces from this mode" should remain explicit.

## Recommended Build Strategy

If this refactor happens, do not rebuild trees on every parser init.

Instead:

1. compile each source table once
2. store the compiled tree alongside each command table
3. let parser/help/completion use the prebuilt trees

That avoids turning a design cleanup into a runtime regression.

## Risks

This is a real refactor, not a cosmetic cleanup.

Main risks:

- preserving current exact-vs-prefix behavior
- preserving current negation behavior
- keeping `TOKEN_TAIL` semantics correct
- not regressing config-mode reachable `?` behavior
- not reintroducing drift between interactive `?`, full-line `?`, and `help`

So if this is done, tests should be expanded around:

- `show ribout` vs `show ribout-map`
- `rt` vs `rt-set`
- config-mode reachable `?`
- root-group help such as `show commands`
- incomplete vs unknown command distinctions
- negated discovery via `no ?`

## Suggested Order Of Work

1. define a private tree node representation in `parser.c`
2. add a table-to-tree compiler
3. make `parser_find_matches()` operate on trees first
4. migrate `parser_execute()` to trees
5. delete now-redundant flat-scan helper logic
6. keep mode-reachable enumeration in `commands.c` as-is until the parser side
   is stable

This keeps the risk concentrated in parser/discovery code, not mode rewind.

## Bottom Line

Flat command tables are still the right authoring surface.

But a derived internal tree would be a good fit for the actual shape of the
CLI, especially for:

- `?`
- TAB
- help rendering
- internal-node grouping
- future dynamic completions

It is worth doing if the project wants to keep investing in CLI
discoverability. It is not worth doing merely to optimize mode rewind, because
mode rewind is a separate concern and would not simplify nearly as much.
