# Cheat Wizard v1.7.0

Cheat Wizard (CW) is a Windows x64 memory-scanning and pointer-analysis project written in C++20. It works on user-selected processes through ordinary user-mode Win32 APIs.

## Executables and responsibilities

Cheat Wizard deliberately separates its tools:

| Executable | Responsibility |
| --- | --- |
| `cw.exe` | **CLI only**: value scans, AOB, pointer tools, maps and persistence. |
| `cw-gui.exe` | Visual engineering tool: scanner, watched addresses, write/freeze, pointer discovery/rescan, `.cwptr` profiles and `.cwtrainer` project creation. |
| `cw-trainer-builder.exe` | Offline packager: `.cwtrainer` + `.cwptr` files -> one standalone trainer EXE. |
| generated `MyTrainer.exe` | Standalone trainer. No Cheat Wizard/Python/JSON/profile files are required beside it. |

`cw.exe` is not an RPC server and is never a runtime dependency of a generated trainer.

## Rebrand and compatibility

The public product name is **Cheat Wizard**, abbreviated **CW**. Public Windows outputs are `cw.exe`, `cw-gui.exe` and `cw-trainer-builder.exe`.

The source tree uses `cw::`, `include/cw/` and `cw_*` build targets consistently. New saves use CW-native persistence (`.cwptr`, `.cwchain`, `.cwmap`, `.cwscan`, `.cwaob`, `.cwtrainer`) and CW magics/identifiers. Compatibility with earlier MiniCE releases remains at the import boundary: `.mcptr`, `.mcep`, `.mcpm`, `.mces`, `.mcea` and `minice-trainer` version 1 are still readable.

## Locales

The GUI loads UTF-8 JSON locale files from the `locales/` directory beside `cw-gui.exe`.

Included initially:

- `locales/en-US.json`
- `locales/pt-BR.json`

The language selector is shown in the GUI footer. The selected locale is persisted in `cw-settings.json` beside the executable. If the configured locale is missing, malformed or incomplete, Cheat Wizard falls back to compiled English strings and remains usable.

Locale discovery is dynamic: to add another language, place another flat JSON file in `locales/` with a valid `_meta.code`. No hard-coded language registry or rebuild is required. See `docs/BRANDING_LOCALES.md` for the locale contract and compatibility rules.

## v1.7.0 — pointer workflow, ranking and visual Trainer Builder

- Pointer workspace spacing and profile actions were reorganized, with clearer live-value/consensus information.
- Custom text fields support caret placement, selection, Ctrl+A, arrows, Home/End, Delete/Backspace and double-click select-all.
- Scanner result ranking can use proximity to the Address List while keeping the reason visible in the score/near column.
- The Address List separates scan value from the current/new value and keeps freeze actions per row.
- Trainer Builder has form/configuration and visual modes, native color selection, live preview and PNG/JPEG/BMP/GIF -> multi-size `.ico` conversion.
- `.cwtrainer` stores the Trainer project and visual settings. `cw-trainer-builder.exe` packages the theme and optional icon into the standalone trainer.
- Generated trainers use redundant pointer-chain consensus, automatically wait/reattach to the configured process, expose current values, Apply/Write and Freeze, and remain single-file executables.
- The GUI now supports external UTF-8 locale JSONs with `en-US` and `pt-BR` included.

## GUI workflow

```text
select process -> Attach
     -> First Scan / Next Scan
     -> add correct address to Address List
     -> Pointers -> discover chains
     -> restart game/process -> find new address -> Rescan
     -> repeat until stable
     -> Save .cwptr
     -> Trainer -> add .cwptr
     -> Save .cwtrainer
     -> cw-trainer-builder.exe -> single standalone EXE
```

The Scanner workspace supports Byte, Int16, Int32, Int64, Float, Double and mixed/unknown workflows. Watched addresses display scan value separately from the live current value. Write is read-back verified and Freeze uses a separate worker.

The Pointer workspace supports restart-based stability rescans, module-relative roots and redundant profile persistence. `.cwptr` profiles contain module-relative roots and signed offsets, not restart-stale absolute heap addresses. Legacy `.mcptr` profiles remain loadable.

## CLI highlights

Examples:

```text
cw> processes
cw> attach-name target.exe
cw> scan int32 100
cw> next 83
cw> results 20
cw> set #0 250
cw> freeze #0 250
```

Unknown/mixed scan:

```text
cw> scan all unknown
cw> next decreased
cw> next unchanged
cw> results 20
```

AOB/signature scan:

```text
cw> aob-module-code target.exe 48 8D 0D ?? ?? ?? ??
cw> aob-results 20
cw> aob-decode #0
```

Pointer tools:

```text
cw> pointer-scan #0 4 0x1000 10000
cw> pointer-results 20
cw> pointer-save stable.cwchain
```

See `docs/COMMANDS.md` and `docs/QUICKSTART.md` for the full CLI surface.

## Files produced by Cheat Wizard

- `.cwscan`: materialized value-scan session (`.mces` remains readable).
- `.cwaob`: AOB/signature session (`.mcea` remains readable).
- `.cwchain`: raw pointer-chain set (`.mcep` remains readable).
- `.cwmap`: pointer map (`.mcpm` remains readable).
- `.cwptr`: redundant pointer profile intended for persistent use/trainers (`.mcptr` remains readable).
- `.cwtrainer`: trainer project consumed by `cw-trainer-builder.exe`; new projects use `cheat-wizard-trainer` version 1 and the builder also accepts legacy `minice-trainer` version 1.
- `cw-settings.json`: local GUI settings, currently including the selected locale.

## Build on Windows

Requirements:

- Windows 10/11 x64
- Visual Studio 2022, Desktop development with C++
- CMake 3.20+

```bat
build-release.bat
```

CMake builds the CLI, GUI, native trainer runtime template and trainer builder. The runtime template is embedded into `cw-trainer-builder.exe`; users do not distribute that template separately. The build also copies `locales/*.json` beside `cw-gui.exe`.

Run tests:

```bat
test-windows.bat
```

## Project layout

```text
src/                 C++ core / native CLI
include/cw/          reusable Cheat Wizard algorithms and public headers
portable_win/        portable no-CRT Windows CLI/GUI/trainer tools
locales/             external UTF-8 GUI locale JSONs
cmake/               build helpers, including runtime embedding
docs/                architecture, GUI, trainer, validation and commands
tests/               core and mocked Win32 tests
examples/            example trainer project
bin/                 ready-to-run Windows x64 release files
```

## License

Cheat Wizard is open source under the **Apache License 2.0**. See `LICENSE` for the full terms.

Redistributions and derivative works must comply with the Apache-2.0 attribution requirements, including preservation of the applicable attribution notice in `NOTICE`. The project NOTICE credits **FlokiTV** as the original Cheat Wizard developer.

## Scope and limitations

Cheat Wizard is a user-mode research/debugging tool. It does not include kernel drivers, protected-process bypasses, anti-cheat bypasses, stealth injection or code-injection features. Use it only with software/processes you are authorized to inspect or modify.
