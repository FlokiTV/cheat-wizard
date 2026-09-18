# Cheat Wizard System Design — GUI v2

Version: 1.7.0
Platform: Windows x64
Primary frontend: `cw-gui.exe`
Current engine/diagnostic frontend: `cw.exe` (legacy direct-access topology during migration)
Target engine boundary: locally built `cw-engine.exe`; `cw.exe` and `cw-gui.exe` become IPC frontends. See [`ENGINE_ARCHITECTURE.md`](ENGINE_ARCHITECTURE.md).

## 1. Problem statement

Cheat Wizard already had a capable memory-scanning engine, but the first GUI was built directly from classic Win32 controls with absolute pixel placement. That created three classes of problems:

1. **Poor information hierarchy** — process selection, scan controls, results, and address tracking competed for space instead of forming one workflow.
2. **Weak state visibility** — a successful `WriteProcessMemory` call was not clearly distinguished from a value that the target immediately recalculated; freeze state was also too implicit.
3. **Presentation debt** — native list boxes/combo boxes did not visually match the Zinc dark theme, did not scale well, and made the interface look like a collection of unrelated controls.

The GUI v2 design treats scanning as a product workflow rather than a thin collection of Win32 widgets.

## 2. Goals

The v1.5 GUI must:

- make the process -> scan -> refine -> pin -> write/freeze workflow obvious;
- keep scan results and pinned addresses conceptually separate;
- display both the value captured by the scan and the value currently in memory;
- refresh live values at a human-readable cadence (~1 second);
- make write verification and freeze state explicit;
- keep scanning off the UI thread;
- remain portable as one Windows x64 executable with no Visual C++ Redistributable dependency;
- contain no target/game-specific values or offsets;
- expose the normal pointer discovery/rescan workflow without requiring CLI commands;
- persist validated redundant pointer sets as typed `.cwptr` profiles;
- reuse a loaded profile without repeating value scanning;
- preserve the advanced CLI for pointer-map and AOB workflows until those panels have a proper GUI design.

## 3. Non-goals for this milestone

v1.5 does not attempt to add:

- kernel drivers;
- anti-cheat bypasses;
- Linux support;
- a debugger / “what writes this address” implementation;
- full AOB and pointer-map/persistence workflows in the graphical shell;
- multi-process scan sessions;
- a complete accessibility layer.

Those are separate features and should not distort the scanner workspace.

## 4. Product architecture

```text
+-------------------------------------------------------------+
|                    Cheat Wizard GUI                        |
|                                                             |
|  App shell / interaction state                              |
|    |                                                        |
|    +-- Target process picker                                |
|    +-- Scan form                                            |
|    +-- Results viewport                                     |
|    +-- Address watch list                                   |
|    +-- Status / error feedback                              |
|                                                             |
|  GUI -> existing memory engine bridge                       |
|    |                                                        |
|    +-- attach_pid                                           |
|    +-- scan_exact / scan_unknown / next_scan_text           |
|    +-- ReadProcessMemory                                    |
|    +-- write_address / WriteProcessMemory                   |
|    +-- freeze worker                                        |
    +-- pointer index / DFS / chain resolver                  |
|                                                             |
+-----------------------------+-------------------------------+
                              |
                              v
                     Windows target process
```

The GUI does not implement a second scanner. It is a presentation and interaction layer over the same memory operations used by the CLI.

## 5. UI technology decision

### Previous approach

The first GUI used standard Win32 `LISTBOX`, `COMBOBOX`, `BUTTON`, and `STATIC` controls, then owner-drew some of them. This still left the application constrained by legacy control geometry and behavior.

### v1.5 approach

The GUI v2 uses a small custom GDI renderer for:

- cards;
- buttons;
- dropdowns;
- table headers/rows;
- scroll indicators;
- status indicators;
- freeze checkboxes;
- selection/hover states.

Text entry is also retained and painted by the custom renderer; the GUI no longer overlays native `EDIT` child windows.

The entire window is double-buffered with a compatible bitmap before being copied to the screen, reducing flicker.

### Why not Dear ImGui in this milestone

Dear ImGui is still a viable future frontend. For the current portable release, however, adding a renderer backend and its dependencies would change the build/distribution model. The custom GDI shell lets Cheat Wizard keep:

- one small PE executable;
- no CRT dependency in the portable GUI build;
- no external DLLs;
- cross-compilation with the existing `clang-cl` + `lld-link` pipeline.

The system design intentionally keeps engine behavior independent of the renderer, so a later ImGui/WinUI frontend can replace presentation without changing scanner semantics.

## 6. Information architecture

The scanner workspace has four visual regions.

```text
+------------------------------------------------------------------+
| Cheat Wizard  [target process................] [refresh] [attach] |
+---------------+--------------------------------------------------+
| Scanner       | Scan results                                     |
|               | # | Address | Type | Scan value | Current        |
| value         |                                                  |
| scan type     |                                                  |
| value type    +--------------------------------------------------+
| alignment     | Address list                                     |
|               | F | Address | Type | Scan value | Current        |
| first / next  |                                                  |
| new scan      | [new value......] [write] [freeze] [remove]      |
+---------------+--------------------------------------------------+
| status / verification / error                                    |
+------------------------------------------------------------------+
```

This layout mirrors the user's actual mental model:

1. choose a target;
2. describe the value to search;
3. reduce candidates;
4. promote interesting candidates to a persistent list;
5. monitor or modify only those promoted addresses.

## 7. State model

### 7.1 Target state

```text
Detached
   |
   | attach successful
   v
AttachedIdle
   |
   | First/Next Scan
   v
Scanning
   |
   | worker completion
   v
AttachedWithResults
```

Process-changing controls are disabled while the scanner worker mutates scan state.

### 7.2 Scan form state

```text
ScanType:
  Exact
  UnknownInitial
  Changed
  Unchanged
  Increased
  Decreased
  BiggerThan
  SmallerThan

ValueType:
  Byte
  Int16
  Int32
  Int64
  Float
  Double
  Mixed

Alignment:
  Natural
  Byte
```

Validation rules are explicit:

- First Scan accepts `Exact` or `Unknown Initial` only.
- Next Scan does not accept `Unknown Initial`.
- Exact/Bigger/Smaller require a typed value.
- Changed/Unchanged/Increased/Decreased do not require one.

### 7.3 Address watch state

A pinned address is independent from the active scan:

```cpp
struct UiWatch {
    bool active;
    uintptr_t address;
    ValueType type;
    byte scanValue[8];
};
```

`scanValue` is the baseline captured when the candidate was promoted to the address list. The live value is intentionally not persisted in this object: it is reread from the target when the visible row is refreshed.

This means `New Scan` can safely destroy candidate state while watch entries remain useful.

## 8. Write semantics

A write operation follows a deterministic transaction:

```text
parse typed input
      |
      v
if frozen -> temporarily disable existing freeze
      |
      v
WriteProcessMemory
      |
      v
read same typed bytes back
      |
      +--> match: “write confirmed”
      |
      +--> differ: “target overwrote/recalculated value”
      |
      v
if previously frozen -> update freeze target and reactivate
```

This removes a confusing failure mode from the earlier GUI, where an old frozen value could immediately undo a new manual write.

## 9. Freeze semantics

Freeze is a state on a pinned address, not on a transient scan row.

Rules:

- adding an address does not automatically freeze it;
- clicking the row checkbox freezes the current/edit value;
- the dedicated Freeze button uses the same operation;
- writing while frozen changes the freeze target to the newly written value;
- removing a watch also removes its freeze;
- changing target process clears all watches/freezes because absolute addresses are not safe across processes;
- `Unfreeze` clears every active freeze but keeps watched addresses.

The worker writes active values every 10 ms. The UI does not imply that a successful memory write guarantees an in-game semantic change; it reports the actual memory state separately.

## 10. Refresh model

There are three cadences:

| Work | Thread | Cadence |
|---|---|---|
| UI paint / input | UI thread | event driven |
| live current-value refresh | UI thread, visible rows only | 1000 ms invalidation |
| freeze writes | freeze worker | 10 ms |
| scan traversal/refinement | scan worker | on demand |

Only visible table rows are reread while painting, so the 1-second refresh cost is bounded by viewport size instead of total scan-result count.

## 11. Result scalability

The scanner can retain millions of candidates, but a GUI cannot reasonably create one OS control per candidate.

The v1.5 result table is a virtual viewport:

- no list-box item objects are created;
- a scroll offset identifies the first visible logical result;
- only visible rows are formatted and reread;
- the GUI caps browsing at 5,000 rows to encourage refinement while the engine continues to retain the complete candidate set for Next Scan.

This is a deliberate separation between **engine cardinality** and **presentation cardinality**.

## 12. Visual design system

The primary palette is Tailwind Zinc-inspired:

```text
Background       zinc-950  #09090B
Panel            zinc-900  #18181B
Surface          zinc-800  #27272A
Hover            ~zinc-750
Selected         zinc-700  #3F3F46
Border           zinc-800 / zinc-700
Secondary text   zinc-400  #A1A1AA
Primary text     zinc-100  #F4F4F5
Strong text      zinc-50   #FAFAFA
```

A single blue action color is used to make primary actions identifiable without turning the whole UI blue:

```text
Primary          blue-600
Primary hover    blue-500
```

State colors are semantic only:

- green = confirmed/active success;
- amber = warning or immediate overwrite;
- red = operation failure.

See `DESIGN_SYSTEM.md` for component-level rules.

## 13. Interaction rules

### Process selection

- Process field is a custom dropdown.
- Process list is alphabetically sorted.
- Refresh preserves the selected PID if it still exists.
- Attach is a separate explicit action.

### Scan results

- Single click selects a row.
- Double click promotes the row to Address List.
- `+ Adicionar` performs the same action.
- Mouse wheel scrolls virtual rows.

### Address list

- Single click selects and loads its current value into the edit field.
- Clicking the Freeze cell toggles freeze for that row.
- Write performs typed write + readback verification.
- Remove clears both watch and freeze.

## 14. Status and error model

Recoverable errors are shown in the persistent footer instead of modal dialogs.

Status severity:

```text
neutral  gray
success  green
warning  amber
error    red
```

Modal dialogs are reserved for fatal application/bootstrap failures.

This keeps scan iteration fast and avoids the application repeatedly interrupting the user.

## 15. Threading contract

### UI thread owns

- window state;
- selection/scroll state;
- process-picker state;
- watch-list mutations;
- UI rendering.

### Scan worker owns while `busy == true`

- mutation of `g_results` / snapshots through existing scanner routines.

The UI must not enumerate or format result memory while the scan worker is active. During scanning, the result viewport renders a placeholder instead.

### Freeze worker owns

- repeated `WriteProcessMemory` for active freeze slots;
- `lastWriteOk` state.

Freeze entries are disabled before their bytes/target are mutated by the UI, then reenabled after the mutation is complete.

## 16. Resource lifecycle

On target attach:

- previous target handle is closed;
- scan state is cleared by the engine;
- watch list and freeze table are cleared by the GUI.

On application shutdown:

- timer is stopped;
- target handle and freezes are cleared;
- scanner/pointer/AOB heap allocations are released;
- GDI brushes/pens/fonts are released.

## 17. Performance budgets

Targets for the scanner frontend:

- ordinary UI interactions should not invoke a whole-memory scan;
- scan work must never block the Windows message pump;
- a 1-second live refresh should read only visible result/watch rows;
- table paint should be O(visible rows), not O(total results);
- process refresh may enumerate the process snapshot synchronously because its expected duration is small;
- freeze cadence remains independent from UI repaint cadence.

## 18. Acceptance criteria for GUI v2

A build is considered ready for user validation when all of these are true:

1. GUI launches without CRT or extra DLL requirements.
2. Process dropdown enumerates real processes and Attach opens the selected target.
3. Exact and Unknown first scans remain functional.
4. Next Scan filtering remains functional.
5. Scan table shows Address / Type / Scan Value / Current.
6. Current value visibly changes without requiring another scan.
7. Double-click/Add promotes a result to Address List.
8. Address List survives New Scan.
9. Write performs readback verification and reports outcome.
10. Freeze can be toggled from the row or action button.
11. A write on an already frozen address updates the freeze target.
12. Removing an address removes its freeze.
13. UI remains responsive while scanning.
14. Window redraw is double-buffered and uses the documented design tokens.
15. Core scanner/AOB/pointer tests remain green.

## 19. Next architectural steps

After the scanner workspace is stable on a real Windows machine:

1. extract the GUI engine bridge and renderer into physical translation units;
2. add description/naming support to watched addresses;
3. add `.cwscan` load/save actions to the GUI;
4. add a dedicated Pointers workspace;
5. add a dedicated AOB workspace;
6. add keyboard navigation and process filtering;
7. consider replacing the custom renderer with Dear ImGui only if the distribution/build tradeoff is justified.

## Pointer workspace design

The Pointer workspace is intentionally task-oriented. Users do not type a raw address or configure every scanner knob before the first useful result. The normal entry point is a watched scanner address:

```text
Address List row -> Ponteiros -> target card -> preset -> Encontrar ponteiros
```

The search target is stored separately from the watch table because the watch table is process-instance-local while pointer chains are intended to survive process restarts. On reattach:

- watches/freezes are cleared;
- old absolute pointer target is invalidated;
- pointer chains are preserved;
- after the user finds the new address, `Reescanear` filters the preserved chains.

The default root is the main executable module because restart-stable chains need a stable module-relative anchor. `qualquer modulo` is an explicit relaxation, not the default.

Pointer indexing and chain search run on a worker thread. Result rendering never enumerates the pointer index. Once chains exist, only visible chains are resolved by the UI, and those resolutions are cached until the next 1-second refresh. This bounds live-monitor overhead by viewport size rather than total chain count.

Cancellation contract:

- pointer indexing/search checks a shared cancellation flag;
- cancelled new searches discard partial chain output;
- rescan writes matches into a temporary chain buffer and commits only after successful completion, so cancellation preserves the previous chain set.

### Pointer UI states

```text
NoTarget -> TargetSelected -> PointerScanning -> ChainsAvailable
                                      |
                                      +-> Cancelled

ChainsAvailable --process restart/reattach--> TargetInvalid + ChainsPreserved
TargetInvalid --new watched address--> TargetSelected
TargetSelected + ChainsPreserved --Reescanear--> ChainsAvailable
```

### Preset intent

`Rapida`, `Equilibrada` and `Profunda` are product-level presets over depth, max offset and branching budget. Raw settings remain available through the CLI. This keeps the first pointer workflow understandable while retaining an escape hatch for advanced users.


## 15. Pointer profile boundary (v1.5)

A stable pointer result is no longer treated as a transient table row. The persistence unit is a **typed redundant chain set**:

```text
PointerProfile
  pointer_width
  value_type
  process_name_metadata
  chains[]
    module + root_offset
    signed offsets[]
```

At runtime Cheat Wizard resolves all chains it can. The first resolved address becomes the candidate address and Cheat Wizard counts how many other resolved chains agree with it. This consensus is diagnostic metadata, not a cryptographic guarantee, but it is substantially more useful than arbitrarily saving only one surviving chain.

The profile never stores a heap address as its durable identity. Absolute resolved addresses belong only to the current process instance.

## 16. Trainer architecture boundary

The trainer layer must not copy Win32 memory-scanning code into generated frontends. The desired dependency direction is:

```text
trainer UI / manifest
        |
        v
Cheat Wizard engine protocol
        |
        v
PointerProfile resolution + read/write/freeze
        |
        v
target process
```

Historical v1.5 shipped an alpha adapter that drove the legacy `minice.exe` through stdin/stdout using dedicated `PROFILE_OK` / `PROFILE_ERR` commands. This proved the manifest/profile model while keeping one memory engine.

The stable boundary should become a versioned stdio RPC process (`cw-engine.exe --rpc-stdio`). A future native runner and graphical Trainer Builder can then share the same RPC/profile contract. See `TRAINER_DESIGN.md`.

## v1.6 executable boundaries

The project now treats executable separation as an architectural invariant:

```text
cw.exe                  -> CLI only
cw-gui.exe              -> visual engineering + trainer project authoring
cw-trainer-builder.exe  -> offline standalone-EXE packager
GeneratedTrainer.exe-> self-contained runtime for the configured profiles
```

The GUI never shells out to the CLI for memory operations. Generated trainers never launch any Cheat Wizard executable. Reuse is source/build-level: scanner/profile/process primitives are implemented from the same project contracts and formats.

The trainer builder embeds a native runtime at build time and packages validated `.cwptr` bytes plus normalized project metadata into the generated executable. This prevents the exported trainer from depending on external configuration at runtime.
