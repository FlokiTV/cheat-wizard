# Architecture

> **Architecture migration in progress:** the current direct-process topology documented below describes the pre-engine split. The accepted target architecture moves all interactive target-memory access into a locally built `cw-engine.exe`, with `cw.exe` and `Cheat Wizard.exe` acting as IPC frontends. See [`ENGINE_ARCHITECTURE.md`](ENGINE_ARCHITECTURE.md).

```text
CLI
 |
 +-- ProcessManager
 |    +-- process/module enumeration
 |    +-- OpenProcess
 |    +-- target pointer-width detection
 |
 +-- MemoryScanner
 |    +-- VirtualQueryEx / ReadProcessMemory
 |    +-- typed Exact + Unknown Initial Value
 |    +-- mixed Exact (`scan all <value>`)
 |    +-- mixed Unknown Initial Value (`scan all unknown`)
 |    +-- shared raw snapshot + typed materialization
 |    +-- per-result type metadata
 |    +-- batched Next Scan filters
 |
 +-- AobPattern / AobScanner / AobPersistence / RelativeAddress / InstructionDecode
 |    +-- exact-byte + wildcard signature parsing
 |    +-- nibble wildcards (A? / ?F)
 |    +-- VirtualQueryEx / ReadProcessMemory traversal
 |    +-- executable-page and module/range filtering
 |    +-- chunk-boundary overlap handling
 |    +-- signed rel32 address resolution
 |
 +-- MemoryWriter / FreezeManager
 |    +-- WriteProcessMemory
 |    +-- result-index writes/freezes
 |    +-- typed raw-address read/write/freeze commands
 |    +-- repeated writes
 |
 +-- PointerAlgorithms / PointerScanner
 |    +-- pointer-sized readable-memory index
 |    +-- configurable source alignment / writable / private filters
 |    +-- reverse graph search from target
 |    +-- per-node branching cap
 |    +-- positive and bounded negative offsets
 |    +-- module-rooted PointerChain results + optional root-module restriction
 |    +-- live resolve/rescan
 |
 +-- PointerPersistence
 |    +-- `.cwchain` v2 signed chain files
 |    +-- v1 backward-compatible loader
 |
 +-- PointerProfile
 |    +-- `.cwptr` typed redundant-chain profiles
 |    +-- GUI Save/Load and trainer-facing persistence
 |
 +-- PointerMap
      +-- `.cwmap` per-run pointer snapshots
      +-- module layout + target + pointer index
      +-- offline multi-session chain comparison
      +-- one-map-at-a-time file comparison for lower peak RAM
```

## Mixed value results

A normal typed scan has one global `ValueType`. A mixed scan instead stores the type with each candidate:

```cpp
struct ScanResult {
    std::uintptr_t address;
    std::uint64_t previousBits;
    ValueType type;
};
```

For `scan all 100`, Cheat Wizard first parses `100` into every supported type that can represent it, then traverses readable memory once. Candidate matching for each representation is performed against the same chunk. Later `next` operations dispatch comparison using `ScanResult::type`.

This is why a Float candidate remains a Float even when an Int32 candidate has the same visible value.

For `scan all unknown`, Cheat Wizard does **not** create six complete unknown-value candidate arrays. It stores readable bytes once in `SnapshotBlock`s, capped by the snapshot safety limit. The first `next` reads the same addresses again, interprets each eligible start as the supported numeric types, compares current versus snapshot values, and only then creates `ScanResult` entries for matches. The raw snapshot is released after that materialization step.

## Signed pointer chain representation

```cpp
struct PointerChain {
    std::wstring moduleName;
    std::uintptr_t rootOffset;
    std::vector<std::int64_t> offsets;
};
```

Example:

```text
game.exe+0x1000 -> +0x20 -> -0x18 -> +0xF8
```

Resolution is:

```text
addr = module_base + 0x1000
addr = read_pointer(addr) + 0x20
addr = read_pointer(addr) - 0x18
addr = read_pointer(addr) + 0xF8
```

All signed additions are checked for integer overflow/underflow before accepting the chain.

## Reverse pointer search

Given target `T`, pointer value `P` is a candidate predecessor when:

```text
T - max_positive_offset <= P <= T + max_negative_offset
```

The resulting chain offset is:

```text
offset = T - P
```

Therefore `P < T` produces a positive offset and `P > T` produces a negative offset. Negative offsets are disabled by default (`max_negative_offset=0`) because widening both sides of the search window increases branching quickly.

## `.cwchain` chain file

```text
magic        CWCHAIN1   (legacy loader also accepts MCEPTR01)
version      uint32     (v2 current; v1 readable)
pointer size uint32
chain count  uint64

per chain:
  module UTF-8 length uint16
  module UTF-8 bytes
  root offset         uint64
  depth               uint32
  offsets             int64 bit-pattern[depth]
```

The v2 physical field is still 8 bytes per offset, but it is interpreted as the two's-complement bit pattern of a signed 64-bit integer. v1 is read as a non-negative offset format.

## `.cwmap` pointer-map file

`.cwmap` remains a per-process-run snapshot containing pointer width, target address, module layout, pointer index, and completeness metadata. Chain offsets are generated during comparison, so the map format itself did not need to change for signed offsets.

## Multi-map comparison

For maps `M0..Mn`:

1. generate bounded module-rooted chains from `M0.target`;
2. resolve the same module-relative root and signed offset sequence in each later map;
3. retain a chain only when it resolves exactly to every map's recorded target.

`pmap-compare` uses maps already loaded in RAM. `pmap-compare-files` instead loads the first map, generates bounded candidate chains, releases it, and then loads/resolves one later map at a time. Peak entry storage is therefore approximately one map rather than the sum of all maps. Each individual map still needs to fit the per-map safety limit; a true on-disk address/value index is post-1.0 work.

## AOB scanner

`AobPattern` stores one value byte and one mask byte per token. Exact bytes use mask `0xFF`, `??` uses `0x00`, `A?` uses `0xF0`, and `?F` uses `0x0F`. Matching is therefore:

```text
(actual & mask) == (expected & mask)
```

`AobScanner` walks readable committed regions with `VirtualQueryEx`, reads them in 4 MiB chunks with `ReadProcessMemory`, and carries `pattern_length - 1` bytes of overlap into each read so a signature beginning near the end of one chunk is not missed. The scanner stores match addresses only; `aob-results` resolves current module-relative offsets for display.

## Pointer-index filters

`PointerScanOptions` separates index-generation controls from graph-search controls. The index phase can restrict source regions before pointer values are materialized:

```text
alignment = natural(pointer width) | 1 | 2 | 4 | 8
writableOnly = true/false
privateOnly = true/false
```

Alignment is computed from the target virtual address, not the temporary local buffer offset. This matters when a chunk begins at an address that is not itself aligned to the requested stride.

The reverse graph search then applies:

```text
maxCandidatesPerNode
rootModuleName
maxDepth
maxOffset
maxNegativeOffset
maxChains
```

Final chains are always rooted in a loaded module. `rootModuleName` narrows which module may terminate a chain, while intermediate nodes may still live in heap or other readable regions.

## rel32 address decoding

`AobPersistence` stores the active signature/search recipe and saved matches in `.cwaob`. Module-contained matches are encoded as module-name + relative offset; non-module hits remain absolute and are explicitly less restart-stable.

`InstructionDecode` is a deliberately bounded decoder for common relative-control-flow and x64 RIP-relative forms. It is used by `aob-decode`; it does not attempt complete x86/x64 instruction-length decoding.

`RelativeAddress::resolveRel32` implements the common x86/x64 relation:

```text
target = instruction_address + instruction_size + sign_extend(int32 displacement)
```

The CLI reads the four displacement bytes directly from the attached process at `instruction_address + disp_offset`. This is enough for `CALL/JMP rel32` and for RIP-relative memory operands when the caller supplies the correct displacement offset and total instruction size. Cheat Wizard does not infer those fields from machine code yet; that requires a disassembler.

## Value-scan persistence (`ScanPersistence`)

`.cwscan` files store only materialized scan results: absolute address, stable type code, previous-value bits, primary/mixed scan metadata, source PID, and scan settings. Raw Unknown Initial Value snapshots are intentionally excluded to avoid turning the format into a large memory dump. `MemoryScanner::restoreMaterializedScan` rehydrates the comparison baseline used by subsequent `next` operations.

## v1.5 Scanner + Pointers GUI frontend

`portable_win/CW_GUI_NoCRT.cpp` is the no-CRT Windows x64 GUI frontend source used to build `bin/Cheat Wizard.exe`. The portable build intentionally keeps no CRT dependency.

The v1.5 frontend uses a custom GDI-rendered application shell rather than legacy `LISTBOX`/`COMBOBOX` composition. Numeric text entry is also custom retained/drawn. The renderer owns cards, buttons, dropdowns, virtual value/pointer tables, hover/selection states, status indicators and freeze checkboxes. Whole-window painting is double-buffered.

Logical GUI architecture:

```text
UI thread
  +-- App/layout state
  +-- process picker state
  +-- scan form state
  +-- virtual result viewport
  +-- address watch list
  +-- write/readback actions
  +-- status feedback
  |
  +-- Scan worker thread
  |     +-- existing First/Next scan algorithms
  |
  +-- Freeze worker thread
        +-- repeated WriteProcessMemory every 10 ms
```

The scan worker is the only thread allowed to mutate candidate/snapshot state while `g_uiBusy` is active. During that period the GUI renders a scan-busy state and does not enumerate the result vector, avoiding the prior presentation/worker race.

The result and watch tables are virtual: scroll offsets map visible rows directly onto engine/watch data, so GUI work is proportional to the viewport rather than candidate cardinality. Current-value refresh rereads only visible rows during the one-second invalidation cadence.

The watch list is separate from scan candidate state. `New Scan` clears candidate/snapshot state while preserving watched addresses. Attaching to a different target clears watches and freezes because their absolute addresses are not assumed to remain valid across processes.

Write actions follow a typed write/readback transaction. When a watched address is already frozen, its freeze slot is disabled before changing bytes, then reactivated with the new target value.

Advanced pointer/AOB/persistence algorithms remain available through `cw.exe` until dedicated GUI workspaces are designed. See `SYSTEM_DESIGN.md` and `DESIGN_SYSTEM.md` for the full frontend contract.


Pointer GUI path:

```text
Address List row
  -> target handoff
  -> pointer preset/root policy
  -> background pointer index + DFS
  -> PointerChain[]
  -> visible-row resolve cache
  -> restart/new target
  -> background rescan filter
```


## `.cwptr` pointer profile

`.cwptr` is the durable object used by the GUI/trainer layer after pointer stability has been validated. Unlike a raw watched address, it survives process restarts because every root is module-relative.

```text
magic        CWPROF01   (legacy loader also accepts MCEPROF1)
version      uint32 (1)
pointer size uint32
value type   uint32
process len  uint16
chain count  uint64
process UTF-8 bytes

per chain:
  module UTF-8 length uint16
  module UTF-8 bytes
  root offset         uint64
  depth               uint32
  signed offsets      int64 bit-pattern[depth]
```

Cheat Wizard resolves all chains and reports majority consensus as `agree/resolved`. The file intentionally stores multiple equivalent paths when they survived repeated restarts.

## Trainer alpha

The first trainer frontend is deliberately thin:

```text
JSON manifest + `.cwptr`
          |
          v
 trainer_basic.py
          |
          | stdin/stdout `profile-*`
          v
        cw.exe
          |
          v
     target process
```

This is an integration prototype, not the final SDK ABI. The planned durable interface is versioned stdio RPC, with a native manifest runner later.
