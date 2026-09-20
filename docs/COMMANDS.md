# Commands

## Process

```text
processes | ps
attach <pid>
attach-name <exe-name>
detach
status
```

## Value scanner

```text
scan <byte|int16|int32|int64|float|double> <value>
scan <type> unknown
scan all <value>
scan all unknown
```

Refine:

```text
next <value>
next exact <value>
next changed
next unchanged
next increased
next decreased
next bigger <value>
next smaller <value>
results [limit]
scan-save <file.cwscan>
scan-load <file.cwscan> [force]
clear
```

`scan-save` requires a materialized result list. A raw `scan all unknown` snapshot must be refined with `next` first. `scan-load` requires an attached process and checks the stored source PID unless `force` is explicitly supplied.

## Scanner settings

Full C++ build:

```text
settings
settings alignment <natural|byte>
settings writable <on|off>
settings private <on|off>
settings tolerance <number>
settings range <min> <max>
settings range all
```

The bundled no-CRT executable currently exposes value-scan alignment.

## Inspect / write / freeze

```text
inspect <#result-index|address>
set <#result-index|address> <value>
freeze <#result-index|address> <value> [interval_ms]
freezes
unfreeze <id|all>
```

For mixed scans, prefer result indexes so the stored candidate type is preserved.

## Modules

```text
modules
```

## AOB / signature scanner

```text
aob <pattern>
aob-code <pattern>
aob-module <module-name> <pattern>
aob-module-code <module-name> <pattern>
aob-results [limit]
aob-resolve <#aob-index|address> <disp_offset> <instruction_size>
aob-decode <#aob-index|address>
aob-save <file.cwaob>
aob-load <file.cwaob>
aob-rerun <file.cwaob>
aob-clear
```

Pattern forms:

```text
8B   exact byte
??   full wildcard
?    full wildcard
A?   high nibble fixed
?F   low nibble fixed
```

Examples:

```text
aob 89 83 ?? ?? ?? ?? 8B 4B ?F
aob-code E8 ?? ?? ?? ??
aob-module target.exe 48 8D 0D ?? ?? ?? ??
aob-module-code target.exe 48 8D 0D ?? ?? ?? ??
aob-results 20
```

### rel32 decoding

For `E8 xx xx xx xx` or `E9 xx xx xx xx`:

```text
aob-resolve #0 1 5
```

For `48 8D 0D xx xx xx xx`:

```text
aob-resolve #0 3 7
```

The formula is:

```text
target = instruction_address + instruction_size + signed_int32(displacement)
```

`disp_offset` specifies where the 4-byte displacement begins inside the instruction.

### Automatic decode

```text
aob-decode #0
```

Recognizes direct `CALL/JMP rel32`, short `JMP rel8`, short/near conditional branches, selected x64 RIP-relative memory instructions, and `FF 15` / `FF 25` RIP-indirect call/jump forms. For the indirect forms, Cheat Wizard also attempts to read the current destination from the pointer slot. It is not a complete instruction decoder.

### AOB persistence

```text
aob-save useful.cwaob
aob-load useful.cwaob
aob-rerun useful.cwaob
```

`.cwaob` stores the signature and scan recipe plus saved matches. Module-contained matches are represented as `module+offset`. Prefer `aob-rerun` after a target restart; it performs a fresh scan with the saved recipe.

## Pointer settings

```text
pointer-settings
pointer-settings alignment <natural|byte|2|4|8>
pointer-settings writable <on|off>
pointer-settings private <on|off>
pointer-settings mode <auto|indexed|targeted>
pointer-settings branch <1..65536>
pointer-settings root <any|module-name>
```

- natural alignment uses the target pointer width;
- byte/2/4/8 select the pointer-slot scan stride;
- writable/private restrict which source memory regions are indexed;
- mode selects `auto` (indexed with targeted fallback), `indexed` only, or index-free `targeted`;
- branch caps candidate fan-out per search node/layer;
- root limits accepted static roots to a module name.

Pointer chains are always rooted in a loaded module. `root` narrows that set. In `auto` mode, any indexed pass that returns zero chains automatically retries using the layered targeted search.

## Live pointer scanner

```text
pointer-scan <#result-index|address> [depth] [max_offset] [max_chains] [max_negative_offset]
pointer-results [limit]
pointer-resolve <chain-index>
pointer-rescan <#result-index|address>
pointer-clear
```

Defaults:

```text
depth=3
max_offset=0x1000
max_chains=10000
max_negative_offset=0
```

Negative offsets are opt-in:

```text
pointer-scan #0 4 0x1000 10000 0x400
```

## Pointer-chain persistence

```text
pointer-save <file>
pointer-load <file>
```

`.cwchain` v2 stores signed 64-bit offsets and module-relative roots.

## Typed pointer profiles (`.cwptr`)

A profile is a redundant set of stable chains plus the numeric value type. It is intended for GUI reuse and trainer frontends.

```text
profile-load <file.cwptr>
profile-read
profile-write <value>
profile-freeze <value> [interval_ms]
```

Successful machine-facing replies begin with `PROFILE_OK`; failures begin with `PROFILE_ERR`.

Example:

```text
attach-name game.exe
profile-load profiles/currency.cwptr
profile-read
profile-write 999999
profile-freeze 999999
```

`profile-read/write/freeze` resolve the loaded chain set against the **current** attached process. The response includes a consensus count such as `agree=11/11` when redundant chains resolve to the same address.

## Pointer maps

```text
pmap-capture <file> <#result-index|address> [max_entries]
pmap-load <file>
pmap-list
pmap-compare [depth] [max_offset] [max_chains] [max_negative_offset]
pmap-compare-files <file1> <file2> [file3 ...]
pmap-clear
```

`pmap-capture` uses current pointer alignment/writable/private source filters. `pmap-compare` uses the current pointer branch cap and root-module filter. `pmap-compare-files` avoids keeping every map loaded simultaneously; it uses current pointer settings with default depth/offset limits.

## Typed raw-address access

```text
read-at <address> <byte|int16|int32|int64|float|double>
write-at <address> <type> <value>
freeze-at <address> <type> <value> [interval_ms]
```

These commands do not require an active value scan. They are useful after resolving a saved pointer chain or AOB-derived address. The bundled no-CRT executable uses a fixed 50 ms worker for `freeze-at`; the native C++ build accepts the optional interval.

