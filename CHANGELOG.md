# Changelog

## 1.7.3 - 2026-09-18

### Release packaging hotfix

- Confirmed that the final `v1.7.2` GitHub ZIP can still trigger Microsoft Defender `Trojan:Win32/Wacatac.B!ml` on a real user browser download. The 2026-09-18 10:29 detection points specifically to `cw.exe` inside the ZIP; `cw-gui.exe` and `cw-trainer-builder.exe` are not listed in that event.
- Treat the earlier automated/headless browser acceptance as a false negative: it did not reproduce the cloud/FastPath classification seen in the user's normal browser session and is no longer considered sufficient proof by itself.
- The prebuilt `v1.7.3` Windows ZIP excludes `cw.exe`. The CLI remains built, tested and available from source, while the downloadable package contains the GUI and Trainer Builder only.
- This packaging change is intentionally conservative: users are not asked to disable, bypass or whitelist Microsoft Defender. The CLI can return to prebuilt releases after its reputation/classification issue is resolved through normal publisher/security channels.

## 1.7.2 - 2026-09-18

### Windows binary heuristic hardening

- Normalized the official Win32 GUI, trainer runtime and trainer builder from custom `/NODEFAULTLIB` entrypoints to the standard MSVC CRT startup path while keeping the CRT statically linked (`/MT`) so the binaries remain standalone.
- Restored the normal MSVC stack security cookie (`/GS`) and enabled Control Flow Guard, CET compatibility, ASLR, high-entropy VA and NX compatibility on the official Windows executables.
- Added conventional Win32 `VERSIONINFO` resources with product/file version, product name, description, original filename and open-source project publisher metadata.
- Removed the custom `memcpy`/`memset` implementations from official MSVC builds; the historical no-CRT implementations remain only for the legacy cross-build path.
- Candidate `v1.7.2` passes core tests, CLI smoke, Trainer Builder current/legacy smoke, GUI/generated-trainer startup smoke and Microsoft Defender scans on the individual executables, staged payload and ZIP.
- Validated the hardened `v1.7.2-rc1` through a real Chrome download from the GitHub Release asset URL: the ZIP arrived with Internet Mark-of-the-Web, matched the published SHA-256, and produced no new Defender 1116/1117 FastPath detection after the download window.

## 1.7.1 - 2026-09-17

### Release pipeline hardening

- Pin Windows CI and release builds to the `windows-2022` runner / Visual Studio 2022 instead of inheriting the moving `windows-latest` compiler family.
- Verify that CMake selected the VS2022 MSVC `19.4x` compiler family and reject newer `19.5x` codegen for official Windows builds.
- Add fail-closed Microsoft Defender gates to both main CI and release publication. CI scans the three distributable executables; release additionally scans the staged payload and final ZIP with remediation disabled and blocks publication on either a detection or scanner error.

## 1.7.0 - 2026-09-17

### Cheat Wizard rebrand and locales

- Renamed the public product from MiniCE to **Cheat Wizard (CW)** before GitHub publication.
- Public Windows outputs are now `cw.exe`, `cw-gui.exe` and `cw-trainer-builder.exe`.
- Added external UTF-8 GUI locale JSONs with `en-US` and `pt-BR` included, dynamic discovery of additional `locales/*.json`, runtime language switching and persistence in `cw-settings.json`.
- Added compiled English fallback strings so a missing, malformed or incomplete locale cannot prevent GUI startup.
- Migrated the internal C++ identity to `cw::`, `include/cw/` and `cw_*` build targets.
- New persistence now uses `.cwptr`/`CWPROF01`, `.cwchain`/`CWCHAIN1`, `.cwmap`/`CWMAP001`, `.cwscan`/`CWSCAN01`, `.cwaob`/`CWAOB001` and `.cwtrainer`/`cheat-wizard-trainer` v1; corresponding MiniCE formats remain readable for backward compatibility.
- Generated trainers now use `CWTRPKG1` package and `CWTRFTR1` footer identifiers, while the runtime can still parse the historical trainer package/footer identifiers.

### GUI/input polish

- Reworked custom text editing in the Cheat Wizard GUI with caret placement, selection rendering, Ctrl+A, Shift+arrows, Home/End, Delete/Backspace and double-click select-all.
- Reorganized Pointer profile actions to avoid cramped buttons and clarified **Valor atual**, profile semantics, and the double-click-to-Scanner workflow.
- Renamed Trainer entry toggles to clearer user-facing concepts: **Mostrar valor**, **Permitir editar**, and **Freeze**.

### Visual trainer projects

- Added Configuração/Visual modes to the Trainer workspace.
- Added `.ico` selection plus configurable background, panel, surface, accent, primary-text and secondary-text colors.
- Added a live trainer preview inside Cheat Wizard.
- Extended the trainer package to version 2 with theme colors while keeping runtime support for package version 1.
- `cw-trainer-builder.exe` can apply the configured `.ico` as native PE icon resources before appending the standalone trainer package.

### Generated trainer UX

- Redesigned generated trainer cards with more spacing, explicit live-value/type/consensus status, larger numeric input, Apply and Freeze controls.
- Added normal input editing semantics to generated trainers: caret positioning, Ctrl+A, arrows, Home/End, Delete/Backspace and double-click select-all.

### Release and CI hardening

- Hardened the custom no-CRT `memcpy`/`memset` routines against recursive optimization under newer MSVC releases; this fixes the `0xC00000FD` Trainer Builder stack overflow seen on GitHub Actions with MSVC 19.51.
- Added a tag-driven Windows release workflow that builds, tests, runs CLI/Trainer Builder smokes, creates the Windows x64 ZIP, generates SHA-256 checksums and publishes the GitHub Release.
- Added reusable release packaging and CHANGELOG-to-release-notes scripts so local and GitHub packaging follow the same file contract.

## 1.6.1

### Builder fix and GUI usability

- Fixed a command-line tokenizer bug in `trainer-builder.exe` that caused valid commands such as `trainer-builder.exe build megabonk.json -o MyTrainer.exe` to print only the usage text.
- Builder now accepts both `build trainer.json -o output.exe` and the shorter `trainer.json -o output.exe` form.
- Trainer workspace can add `.mcptr` files directly and repeatedly, making multi-value trainer projects explicit.
- Kept **+ Profile atual** as an optional shortcut for the profile currently loaded/saved in the Pointer workspace.
- Pointer results now include a live typed **Valor** column.
- Double-clicking a pointer-chain row adds its resolved address to the Scanner Address List for Write/Freeze.
- Renamed persistence actions to **Salvar .mcptr** and **Carregar .mcptr** and clarified inline help.

## 1.6.0

### Single-EXE trainer architecture

- Formalized executable responsibilities: `minice.exe` is CLI-only, `minice-gui.exe` is the engineering/configuration UI, and the new `trainer-builder.exe` is the only packager.
- Added a native no-CRT `trainer-builder.exe` that consumes `trainer.json` plus `.mcptr` profiles and emits one standalone trainer EXE.
- Added an embedded native trainer runtime; generated trainers do not launch or depend on `minice.exe`, Python, JSON, `.mcptr` files, or a separate runtime.
- Generated trainers automatically wait for/re-attach to the configured process, resolve module-relative pointer profiles by strict-majority consensus, show live values, write typed values, and freeze them.
- Added a `Trainer` workspace to `minice-gui.exe` for assembling up to 8 profile-backed trainer entries and saving `trainer.json`.
- Added schema/build/design documentation and an example trainer manifest.
- Removed the v1.5 Python trainer prototype from the release path; Python is not part of the trainer runtime architecture.

### Packaging format

- Builder embeds a precompiled PE trainer runtime and appends a bounded package containing normalized trainer metadata and validated raw `.mcptr` bytes.
- Added a fixed footer containing package offset/size and CRC32; the runtime validates its own embedded package before launching the UI.
- Builder validates manifest version, target process metadata, profile format/type/pointer width and per-project entry limits.

### Validation

- Clean Linux-host Release core/mock build and 4/4 CTest suites pass.
- Windows x64 portable CLI, GUI and trainer-builder cross-builds pass.
- GUI import audit passes.
- Native trainer runtime is compiled and embedded successfully into `trainer-builder.exe`.
- Full execution of generated trainer EXEs against a real Windows process remains Windows-side validation.

## 1.5.0

### Persistent pointer profiles

- Added `.mcptr` pointer-profile format (`MCEPROF1`).
- A profile stores target pointer width, numeric value type, process-name metadata, and **all surviving module-relative pointer chains**.
- Added GUI **Salvar**, **Carregar**, and **+ Lista** actions to the Pointer workspace.
- Loading a profile resolves every available chain against the current process and reports chain consensus (`agree/resolved`).
- A loaded profile can be added directly to the Address List, so a stable value no longer needs to be rediscovered with First/Next Scan after every restart.
- Pointer profiles preserve redundancy intentionally; one broken chain does not invalidate the profile if other stable chains still agree.

### Trainer SDK alpha

- Added machine-friendly CLI commands:
  - `profile-load <file.mcptr>`;
  - `profile-read`;
  - `profile-write <value>`;
  - `profile-freeze <value> [interval_ms]` in the full native build.
- Profile command responses use `PROFILE_OK` / `PROFILE_ERR` prefixes for simple frontend parsing.
- Added `trainer_sdk/trainer_basic.py`, a small config-driven Tkinter trainer that keeps all memory operations inside `minice.exe`.
- Added JSON trainer-manifest example and documented the planned stable RPC/native-runner architecture in `docs/TRAINER_DESIGN.md`.

### Core / format parity

- Added `PointerProfileData`, `savePointerProfile`, and `loadPointerProfile` to the normal C++ core.
- Added `.mcptr` round-trip coverage to core tests.
- Portable no-CRT CLI and GUI implement the same profile format.

### Validation

- Clean Release build and all CTest suites pass.
- Portable Windows x64 CLI and GUI cross-build successfully.
- GUI PE static-import audit passes; the Common Dialog API is loaded dynamically.
- Python trainer source passes `py_compile`.
- Real `.mcptr` Save/Load dialogs and trainer-to-target behavior still require Windows-side runtime validation.

## 1.4.3

### Targeted layered pointer discovery

- Reworked the GUI **Profunda** pointer search after real Windows testing showed a useful first hop (`pais do alvo > 0`) but repeated failure caused by an 8M-entry partial index and reverse-search work-budget exhaustion.
- Deep search no longer builds one giant global pointer index. It now performs a **breadth-first targeted reverse scan by layer**:
  - layer 1 scans only for pointers that can reach the selected target within the active offset window;
  - layer 2 scans for pointers that can reach the layer-1 slots;
  - the process repeats up to depth 6 until a module-rooted chain is found or the frontier is exhausted.
- The layered engine keeps a bounded frontier (300k unique slots per layer), deduplicates parent slots, prefers short chains by BFS order, and caps parents per node.
- Source scanning is pruned to writable memory plus loaded-module ranges, avoiding code/read-only noise while still allowing static module roots.
- **Profunda** now uses this index-free engine directly (`+0x4000 / -0x400`, 4-byte source alignment). The 8M global-index ceiling no longer applies to Deep.
- Rapida/Equilibrada keep the faster global-index engine; if that index truncates or exhausts its reverse-search budget with zero chains, the GUI automatically falls back to the targeted layered engine.
- Added live layered-search progress: current level, frontier size, pointer slots inspected, and matches found. Cancellation is checked continuously while scanning memory.
- Main-module roots remain preferred; when that yields no chain, Deep can automatically retry with roots in any loaded module.
- Zero-chain diagnostics now distinguish `no references`, `references but no static root`, and `frontier limit reached` rather than reporting an incomplete index as a definitive failure.

### Validation

- Clean Release build: PASS.
- 4/4 CTest suites: PASS.
- 20 consecutive Release test cycles: PASS.
- ASan + UBSan: 5/5 cycles PASS.
- Portable Windows x64 CLI + GUI cross-builds: PASS.
- GUI PE import audit: PASS.
- The new layered engine compiles into the Windows GUI; live target behavior still requires Windows-side validation.

## v1.4.0

### Pointer Scanner in the GUI

- Added a first-class **Ponteiros** workspace to `minice-gui.exe`; the pointer engine is no longer CLI-only for the basic discovery/rescan workflow.
- Added **Ponteiros** action to every selected watched address. It transfers the exact address/type into the pointer workspace instead of making the user retype an address.
- Added `Scanner` / `Ponteiros` top-level navigation while keeping the attached process visible in both workspaces.
- Added an explicit target card showing the selected address, type, and current live value.
- Added three human-oriented search presets instead of exposing raw pointer-scanner knobs first:
  - **Rapida**: depth 3, max offset `0x400`, lower branch budget;
  - **Equilibrada**: depth 4, max offset `0x1000` (recommended);
  - **Profunda**: depth 5, max offset `0x2000`, larger branch budget.
- Default root is the attached process module; users can toggle to **qualquer modulo** when needed.
- Fast/Balanced presets index writable pointer storage first to reduce noise and memory use; Deep is broader.
- Added asynchronous pointer-index/chain discovery so the window keeps pumping messages during long scans.
- Added **Cancelar busca** and cancellation checks during pointer indexing/search.
- Added a virtualized chain table with `Base`, `Offsets`, live `Resolvido`, and `Estado`. Visible chains are resolved on the 1-second UI cadence rather than on every mouse-move repaint.
- Added guided **Reescanear** workflow. Pointer chains survive target reattachment; after a process restart the old absolute target is invalidated, the user scans the value again, selects the new address, and re-runs the chain filter.
- Rescan now uses a temporary chain buffer in the GUI worker so cancelling a rescan does not corrupt the previous chain set.
- Added inline instructions in the Pointer workspace explaining the restart/rescan stability workflow.

### GUI robustness

- Kept the custom Zinc renderer and custom text inputs introduced in v1.3.2.
- Made pointer-table columns adapt to narrower windows instead of relying on one fixed desktop width.
- Adjusted the Address List action row so the new **Ponteiros** action stays inside the card at smaller window widths.
- Pointer-chain live resolution is cached and refreshed only for visible rows, bounding `ReadProcessMemory` overhead.

### Validation

- Clean Release CMake build: PASS.
- 4/4 core/mock CTest suites: PASS.
- 20 consecutive Release test cycles: PASS.
- ASan + UBSan test run: PASS.
- Portable Windows x64 CLI cross-build: PASS.
- Portable Windows x64 GUI cross-build: PASS.
- GUI PE import audit: PASS (`kernel32.dll`, `user32.dll`, `gdi32.dll`).
- Real pointer-GUI interaction still requires Windows-side validation because the build host does not provide a Windows desktop/kernel.

## v1.3.1

### GUI loader hotfix

- Fixed GUI startup failure caused by assigning `DrawTextA`, `FillRect`, and `FrameRect` to the wrong import DLL in the no-CRT cross-build.
- Added a release-time PE import audit.

## v1.3.0

### System-design round

- Added `docs/SYSTEM_DESIGN.md` covering product boundaries, state model, write/freeze semantics, threading contract, refresh cadence, performance budgets and GUI acceptance criteria.
- Added `docs/DESIGN_SYSTEM.md` defining the Zinc-based palette, typography, spacing and component rules.
- Reframed the GUI as a scanner workspace rather than a direct collection of Win32 controls.

### GUI v2

- Replaced the legacy process/scan/result composition based on Win32 list boxes and combo boxes with a custom GDI-rendered shell.
- Standard Win32 `EDIT` controls are retained only for typed numeric input; tables, dropdowns, buttons, cards, status, hover and selection are custom rendered.
- Added double-buffered whole-window painting to reduce flicker.
- Window is resizable and recomputes the scan/results/address layout from the current client area.
- Process picker is now a custom, alphabetically sorted dropdown with wheel scrolling.
- Result and address tables are virtual viewports instead of lists populated with one OS item per candidate.
- Scan rows show `Address`, `Type`, `Scan value`, and live `Current` value.
- Address-list rows show `Freeze`, `Address`, `Type`, `Scan value`, and live `Current` value.
- Mouse wheel scrolls result/address viewports; double-click promotes a result to the Address List.
- Recoverable errors and operation results use a persistent footer with neutral/success/warning/error states instead of modal dialogs.
- GUI browses up to 5,000 scan results while Next Scan continues to use the complete engine candidate vector.

### Write/freeze model

- Preserved immediate typed read-back verification after writes.
- Writing to an already-frozen address temporarily disables that freeze, replaces its target bytes, performs the write, and then reenables it.
- Freeze can be toggled either from the action button or directly from the row's Freeze cell.
- Freeze rows expose success/error state independently from the displayed live value.
- Removing a watched address removes the associated freeze.
- Attaching to another process clears watches/freezes to avoid carrying absolute addresses across targets.
- Freeze worker remains independent from the 1-second UI refresh cadence and runs every 10 ms.

### Concurrency/robustness

- Result rows are not enumerated while the scan worker mutates the scanner state; the viewport renders a busy state instead.
- First/Next Scan remains on a background thread.
- Live refresh rereads visible rows only, bounding UI-side `ReadProcessMemory` work by viewport size.
- The portable GUI remains a no-CRT PE32+ x86-64 executable.
- Static imports remain limited to `kernel32.dll`, `user32.dll`, and `gdi32.dll`; optional DWM dark-title support is loaded dynamically.

### Validation

- Clean Release CMake build passed.
- 4/4 core/mock CTest suites passed.
- 20/20 consecutive Release CTest cycles passed.
- ASan + UBSan build passed.
- 5/5 consecutive sanitizer CTest cycles passed.
- Portable CLI and GUI Windows x64 cross-builds passed using `clang-cl` + `lld-link`.
- PE import inspection passed.
- Binary audit found no `health`, `ammo`, `money`, `speed`, `ac_client`, or `megabonk` target strings.
- Real Windows GUI interaction still requires user-side validation because the build host does not provide a Windows desktop/kernel.
## v1.1.1

### GUI loader hotfix

- Fixed GUI startup failure caused by importing `InterlockedExchange` through the legacy Kernel32 surface.
- Rebuilt and inspected the GUI import table to confirm that import was removed.

## v1.1.0

### Initial native Windows GUI

- Added the first Win32 graphical frontend for process selection, value scanning, write and freeze.
- Added the background scan worker and initial live-selected-value monitor.

## v1.0.0

### Stable CLI milestone

- Declared the original scanner scope stable: process attach, value scanning/refinement, write/freeze, AOB signatures, pointer chains, pointer maps, and persistence.
- Added `read-at`, `write-at`, and `freeze-at` so resolved/raw addresses can be used without keeping an active value scan solely for type metadata.
- Added `pmap-compare-files <file1> <file2> ...`, which compares map files while keeping at most one map entry vector resident at a time.
- Added pointer-map comparison stats for pointer width, partial-map count, and peak resident entry count.
- Added value-scan and pointer-index throughput reporting to the native CLI.
- Added `version` command and updated the portable no-CRT executable banner/help.
- Portable Windows x64 executable includes raw typed-address commands and streaming-across-files pointer-map comparison.

### Validation

- Added core tests for one-map-at-a-time pointer-map comparison, partial-map reporting, stable-chain retention, and per-map safety-limit failure.
- Release and sanitizer test loops are recorded in `docs/VALIDATION.md`.


## v0.14.0

- Added `.mces` persistence for materialized value-scan result lists.
- Added `scan-save <file.mces>` and `scan-load <file.mces> [force]`.
- Saved sessions include source PID, mixed/primary type metadata, scanner settings, addresses, stable type codes, and previous-value bits used by Next Scan comparisons.
- Added default PID mismatch refusal to reduce accidental use of stale heap addresses after a target restart.
- Added `MemoryScanner::restoreMaterializedScan` for safe in-memory restoration.
- Unknown-initial raw snapshots are intentionally not persisted; refine once with `next` before saving.
- Added portable Windows x64 no-CRT support for `.mces` save/load.
- Added core round-trip/safety-limit tests for the new format.

## v0.13.0

### Added

- `.mcea` AOB session persistence with wildcard pattern, scan scope, optional module restriction, and saved matches.
- `aob-save <file.mcea>`, `aob-load <file.mcea>`, and `aob-rerun <file.mcea>`.
- Module-contained AOB results are saved as module-relative offsets for ASLR-aware restore.
- `aob-decode <#aob-index|address>` for common direct relative branches, short/near conditional branches, x64 RIP-relative memory operands, and RIP-indirect `CALL/JMP`.
- RIP-indirect decoding dereferences the pointer slot using the attached target's 32/64-bit pointer width when readable.
- Core persistence/decoder tests and portable Windows x64 no-CRT parity.

### Robustness

- `.mcea` loading validates magic/version, pattern masks, counts, name lengths, address fit, and trailing data.
- `aob-load` reports unresolved module-relative hits and warns when absolute saved hits may be stale.
- `aob-rerun` is the preferred restart-safe workflow because it executes the saved signature against current memory rather than trusting old addresses.
- Relative-instruction decoding rejects address-space overflow/underflow and does not treat x86 absolute-indirect `FF /2` or `FF /4` as x64 RIP-relative forms.

### Validation

- See `docs/VALIDATION.md` for the exact checks executed for this package.

## v0.12.0

### Added

- `pointer-settings alignment <natural|byte|2|4|8>` for pointer-index alignment control.
- `pointer-settings writable <on|off>` and `private <on|off>` source-region filters.
- `pointer-settings branch <count>` to expose the per-node branching cap.
- `pointer-settings root <any|module-name>` to restrict static roots to one module.
- `aob-module-code <module> <pattern>` for executable-page AOB scanning inside one module.
- `aob-resolve <#aob-index|address> <disp_offset> <instruction_size>` for signed x86/x64 rel32 target resolution.
- Portable Windows x64 no-CRT parity for the new pointer settings and AOB rel32 helper.

### Robustness

- Pointer indexing now applies alignment relative to virtual addresses rather than buffer offsets.
- Pointer writable/private filtering happens before pointer bytes are indexed, reducing map/index size instead of filtering only after search.
- Root-module matching is case-insensitive.
- rel32 resolution rejects address-space overflow/underflow.

### Validation

- All four Release test suites pass.
- 50 consecutive Release CTest cycles pass.
- AddressSanitizer + UndefinedBehaviorSanitizer build passes, followed by 10 consecutive sanitizer CTest cycles.
- Real Win32 translation units pass C++20 syntax checks with warnings enabled against Win32 stubs.
- Portable Windows x64 no-CRT PE cross-compilation succeeds.
- PE inspection confirms PE32+ x86-64 and `kernel32.dll`-only imports.

## v0.11.0

### Added

- `aob <pattern>` real-process Array-of-Bytes signature scanning.
- `aob-code <pattern>` executable-page-only scanning.
- `aob-module <module> <pattern>` module-bounded scanning.
- `aob-results` / `aob-clear`.
- Full-byte wildcards (`?` / `??`) and nibble wildcards (`A?` / `?F`).
- Module-relative labels for AOB results when the current module layout is available.
- Portable Windows x64 no-CRT executable parity for AOB scanning.
- `minice_mock_aob_tests` against mocked Win32 memory.

### Robustness

- AOB reads use overlap equal to `pattern_length - 1`, so signatures crossing the internal 4 MiB scanner chunk boundary are detected.
- AOB scanning honors the full scanner's address-range, writable-only and private-only restrictions; `aob-code` adds executable protection filtering.
- Stored AOB results are capped at 1,000,000 matches to prevent pathological wildcard scans from consuming unbounded memory.

### Validation

- All four Release test suites pass.
- 50 consecutive Release CTest cycles pass.
- AddressSanitizer + UndefinedBehaviorSanitizer build passes, followed by 10 consecutive sanitizer CTest cycles.
- Real Win32 translation units pass C++20 syntax checks with warnings enabled against the Win32 stubs.
- Portable Windows x64 no-CRT PE cross-compilation succeeds.
- PE inspection confirms PE32+ x86-64 and `kernel32.dll`-only imports.

## v0.10.0

### Added

- `scan all unknown` mixed-type Unknown Initial Value scanning.
- A single raw snapshot is shared by all supported numeric interpretations instead of storing six complete unknown-value result sets.
- The first mixed-unknown `next` materializes typed candidates; later mixed refinements, writes and freezes preserve those types.
- Portable Windows x64 no-CRT executable parity for the mixed unknown workflow.
- Mock Win32 tests covering mixed unknown snapshot capture, typed materialization and later refinement.

### Changed

- `scan all` now accepts either a concrete value or `unknown` / `?`.
- `results` explains when a mixed unknown snapshot is still waiting for its first refinement.
- Mixed unknown snapshots use the same 512 MiB raw snapshot safety cap as typed Unknown Initial Value in the full C++ scanner.

### Validation

- All three Release test suites pass.
- 50 consecutive Release CTest cycles pass.
- AddressSanitizer + UndefinedBehaviorSanitizer build passes, followed by 10 consecutive sanitizer CTest cycles.
- Portable Windows x64 no-CRT PE cross-compilation succeeds.
- PE inspection confirms PE32+ x86-64 and the expected `kernel32.dll` imports.

## v0.9.0

### Added

- `scan all <value>` mixed-type Exact Value scan.
- Per-result numeric type metadata so mixed results can be refined, displayed, written, frozen, and inspected without losing their original representation.
- Mixed `next exact`, `changed`, `unchanged`, `increased`, `decreased`, `bigger`, and `smaller` filtering.
- Signed pointer-chain offsets with a separate bounded `max_negative_offset` option.
- Signed-offset support in live pointer resolution, rescan, and multi-map comparison.
- `.mcep` pointer-chain format v2 for signed 64-bit offsets, with backward-compatible loading of v1 files.
- Tests for mixed int16/int32/float scans and refinements, negative pointer offsets, and signed persistence.
- Portable Windows x64 executable parity for mixed scanning and signed pointer offsets.

### Changed

- Pointer-chain offsets are represented internally as `int64_t` instead of `uintptr_t`.
- `pointer-scan` syntax is now:
  `pointer-scan <target> [depth] [max_offset] [max_chains] [max_negative_offset]`.
- `pmap-compare` accepts the same optional `max_negative_offset` parameter.
- Mixed results print their type alongside address and value.
- Portable integer parsing now rejects out-of-range int16/int32 inputs instead of narrowing them.

### Validation

- All three Linux-hosted Release test suites pass.
- 50 consecutive Release CTest cycles pass.
- AddressSanitizer + UndefinedBehaviorSanitizer build passes, followed by 5 consecutive sanitizer CTest cycles.
- Real Win32 source translation units pass C++20 syntax checks with warnings enabled against the project's Win32 stubs.
- Portable Windows x64 no-CRT PE cross-compilation succeeds.
- PE inspection confirms x86-64 PE32+ and the expected `kernel32.dll` imports, including unsuffixed `Process32First`/`Process32Next` rather than the invalid historical `A` imports.

## v0.8.0

- Added persistent `.mcpm` pointer-map snapshots and offline multi-session chain comparison.
- Added `pmap-capture`, `pmap-load`, `pmap-list`, `pmap-compare`, and `pmap-clear`.
- Added completeness metadata for partial/truncated maps.

## v0.7.0

- Added persistent `.mcep` pointer-chain files.
- Added `pointer-save`, `pointer-load`, and `inspect`.
- Added pointer-width metadata checks.

## v0.6.0

- Added module enumeration, target pointer-width detection, pointer indexing, bounded module-rooted pointer-chain search, resolve and rescan.

## v0.5.0

- Removed the synthetic runtime scan target from the release package.
- Release runtime uses real process attach/value scanning/write/freeze only.
