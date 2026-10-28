# TODO: Ribout Parser and CLI Cleanup

## Goal

Make ribout subcommands a clean, explicit parser concept instead of a legacy
half-fit inside the generic token grammar.

The objective is not to force ribout into the same shape as simple fixed-form
CLI commands. The objective is to make ribout different in an intentional,
canonical way, with less hidden special-casing and less accidental behavior.

## Short Version

Ribout commands are not ordinary token commands.

They are a small embedded configuration language with their own syntax rules:

- `prefix 10.0.0.0/24 x 10`
- `next-hop 2001:db8::1 x 4 link-local fe80::1`
- `as-path 100 { 200 300 } [rand(500) x 10]`
- `rt-set [65000:100] [65000:200,65000:201]`

The generic parser in `src/parser.c` is only a whitespace token matcher. It is
not the right place to understand all of that grammar.

So the clean answer is:

1. keep ribout commands as a dedicated tail-command family
2. make that shape explicit in parser/command metadata
3. stop relying on accidental behavior around `TOKEN_TAIL`, `no`, and
   incomplete-command classification

## Current State

Ribout commands are currently defined in `src/commands.c` with:

- one fixed keyword
- one `TOKEN_TAIL`
- one dispatch in `src/bgp_ribout_edit.c` (`bgp_ribout_edit()`) to the leaf
  parsers in `src/bgp_ribout_config.c`

That is already closer to the right shape than trying to model the full ribout
grammar in the generic token parser.

However, the current design still has a few structural problems:

- the parser does not know enough about tail commands to classify completeness
  cleanly
- `prefix` and `no prefix` are semantically different command shapes, but that
  distinction is not declared in the command schema
- the special behavior for negated ribout commands is implicit rather than
  first-class
- the generic parser and the ribout tail parsers jointly own command
  completeness in a way that is easy to break
- negated ribout clears are currently too permissive: commands like
  `no prefix junk`, `no next-hop 192.0.2.2`, and `no localpref junk`
  are accepted and silently ignore the extra tail instead of rejecting it

Two of the desired behaviors already exist, but only as carve-outs in the
generic parser: `prefix` alone reports `Incomplete command`, and `no prefix ?`
offers `<cr>`, because `src/parser.c` treats a missing tail as complete when
the command is negated and `supports_no` (the completion code's comment still
says it never offers `<cr>`). Those carve-outs are the hidden special case
this note wants replaced by declared shapes. `no prefix junk` is accepted
because the negated path still captures the tail and `bgp_ribout_edit()`
discards it for a clear.

That is why fixes like "report `Incomplete command` instead of `Unknown
command`" can accidentally regress `no prefix`, `no next-hop`, `no as-path`,
and similar ribout clear commands if the parser is still pretending every tail
command has exactly one completeness rule.

## What Ribout Actually Is

Ribout is best understood as:

- a fixed command root chosen by the generic parser
- followed by a mini-language owned by the ribout config parser

That is a valid design.

What is not clean is treating it as "mostly a normal command, except for a few
special cases."

If ribout stays special, it should stay special in one consistent, declared
way.

## What Not To Do

### 1. Do Not Partially Normalize Ribout

Do not convert a few ribout commands like `origin` or `localpref` into ordinary
tokenized commands while leaving `as-path`, `rt-set`, and `next-hop` as tail
parsers.

That would make the ribout subtree look like it was designed in multiple
styles.

It would also make help/completion/completeness rules harder to reason about,
not easier.

### 2. Do Not Add More Hidden Parser Special Cases

Do not keep piling behavior into "if negated and tail token and supports_no and
...".

That may work tactically, but it leaves the parser with behavior that is
correct only because multiple unrelated conditions happen to line up.

### 3. Do Not Diffuse Ribout Semantics Across CLI and Parser

The generic parser should decide:

- what command root matched
- whether the command is complete enough to dispatch

The ribout domain parser should decide:

- whether the tail syntax is valid
- how to interpret the mini-language

Those responsibilities should be explicit.

## Desired End State

Ribout commands should be represented as a first-class command family with
declared tail semantics.

The parser/command layer should understand, for each command:

- whether it has no tail
- whether it requires a tail
- whether the tail is optional
- whether the tail is required on positive form but empty on `no`

That would make the following behavior explicit and stable:

- `prefix` -> incomplete
- `no prefix` -> complete clear command
- `no prefix junk` -> invalid
- `localpref` -> incomplete
- `no localpref` -> complete reset command
- `no localpref junk` -> invalid
- `as-path` -> incomplete
- `no as-path` -> complete clear command
- `no as-path junk` -> invalid

## Recommended Shape

Add an explicit command-argument shape to the command schema.

Possible shape:

```c
typedef enum {
    CMD_ARGS_NONE,
    CMD_ARGS_TAIL_REQUIRED,
    CMD_ARGS_TAIL_OPTIONAL,
    CMD_ARGS_TAIL_REQUIRED_UNLESS_NO
} cmd_arg_shape_t;
```

Then tail commands become explicit data, not parser folklore.

Possible command definition extension:

```c
typedef struct cmd_def {
    const char *name;
    token_def_t tokens[MAX_TOKENS];
    cmd_handler_t handler;
    const char *help_text;
    int supports_no;
    cmd_arg_shape_t arg_shape;
} cmd_def_t;
```

For ribout commands, the canonical declaration would be:

- one keyword token
- one tail token
- `CMD_ARGS_TAIL_REQUIRED_UNLESS_NO`

That makes the completeness rule visible in one place.

## Why This Is Better Than "Make Ribout Like Other Commands"

Because ribout is not actually like other commands.

Simple CLI commands in this codebase are things like:

- `show log`
- `show log all`
- `show bgp neighbors`
- `show bgp neighbors <AS>`
- `capability graceful-restart`
- `capability graceful-restart restart-time <time>`

Those are fixed-form token trees.

Ribout is not.

Trying to force ribout into that same model would either:

- fail outright for the richer sub-grammars, or
- split ribout across multiple styles, which is worse

So the clean design is not "treat ribout like all other commands."
The clean design is "treat ribout as one consistent tail-language family."

## Suggested Parser Rules

For tail commands, the parser should make completeness decisions from declared
command metadata, not from accidental token absence.

Rules should be:

- `CMD_ARGS_NONE`
  - keyword path alone is complete
- `CMD_ARGS_TAIL_REQUIRED`
  - missing tail is incomplete
- `CMD_ARGS_TAIL_OPTIONAL`
  - missing tail is complete
- `CMD_ARGS_TAIL_REQUIRED_UNLESS_NO`
  - missing tail is incomplete on positive form
  - missing tail is complete on negated form

That is the canonical fix for the current ribout issue.

## Completion and Help Implications

Once tail-command shape is explicit, completion can be cleaner too.

Examples:

- `prefix ?` -> show the tail placeholder
- `no prefix ?` -> show `<cr>`
- `localpref ?` -> show the tail placeholder
- `no localpref ?` -> show `<cr>`

The corresponding execution rule should be strict too:

- bare negated ribout clears like `no prefix` are valid
- negated ribout clears with extra tail input are not

This gives users correct discoverability without pretending the generic parser
can explain the full ribout sub-grammar.

## Suggested File Touches

Main files:

- `src/parser.h`
- `src/parser.c`
- `src/commands.c`
- `src/bgp_ribout_edit.c`

Possibly small updates in:

- `src/cli.c`
- `tests/test_cli_commands.c`
- `tests/test_parser.c`
- `tests/test_cli_pty.c`
- `tests/test_cli_ribout.c`

## Testing That Should Exist

Exists today:

- `router bgp` and `show bgp` classified as incomplete
  (`tests/test_cli_commands.c`, `tests/test_parser.c`)
- `no prefix` and `no localpref` classified as complete, and the clear tests
  for every ribout keyword (`tests/test_cli_ribout.c`)
- `?` after a positive ribout keyword shows the tail placeholder
  (`tests/test_cli_commands.c`); `no ?` lists the negatable keywords
  (`tests/test_cli_commands.c`, `tests/test_cli_pty.c`)

Missing:

- bare `prefix` and `localpref` classified as incomplete
- `no prefix junk`, `no next-hop 192.0.2.2`, `no localpref junk` rejected
- `no prefix ?` offers `<cr>`

## Acceptance Criteria

- ribout remains one consistent command family
- no command-by-command parser hacks are needed for ribout clear commands
- incomplete-command reporting works for ribout positive forms
- `no <ribout-command>` clear/reset behavior remains correct
- help/completion reflect the declared tail-command semantics
- the implementation is simpler to reason about than the current implicit
  `TOKEN_TAIL` behavior

## Recommendation

Keep ribout special, but make it special in one explicit, first-class way.

That is cleaner than:

- treating ribout like ordinary token commands when it is not
- partially tokenizing only the easy ribout commands
- or continuing to accumulate parser-side special cases with no declared model

This is the right place to draw the line:

- fixed-form commands stay fixed-form
- ribout stays a tail-language
- completeness rules for tail-languages become explicit parser metadata
