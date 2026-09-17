# Cheat Wizard branding and locale contract

## Public identity

The product name is **Cheat Wizard** and the short name is **CW**.

Public Windows artifacts for this migration are:

- `cw.exe` — CLI/diagnostic frontend.
- `cw-gui.exe` — primary graphical frontend.
- `cw-trainer-builder.exe` — standalone trainer packager.
- `Cheat-Wizard-v1.7.0-win64.zip` — portable Windows package.

The visible application title, dialogs, help text, documentation and package metadata use Cheat Wizard/CW.

## Persistence identity and compatibility

The source tree uses the Cheat Wizard identity consistently: C++ code lives under `namespace cw`, public headers are under `include/cw/`, and internal CMake targets use `cw_*` names.

Newly saved persistence objects use CW-native names and identifiers:

| Purpose | CW format | CW magic / identifier | Legacy MiniCE input |
| --- | --- | --- | --- |
| Pointer profile | `.cwptr` | `CWPROF01` | `.mcptr` / `MCEPROF1` |
| Pointer chains | `.cwchain` | `CWCHAIN1` | `.mcep` / `MCEPTR01` |
| Pointer map | `.cwmap` | `CWMAP001` | `.mcpm` / `MCEPMAP1` |
| Scan session | `.cwscan` | `CWSCAN01` | `.mces` / `MCESCAN1` |
| AOB session | `.cwaob` | `CWAOB001` | `.mcea` / `MCEAOB01` |
| Trainer project | `.cwtrainer` | `cheat-wizard-trainer` v1 | JSON / `minice-trainer` v1 |

Binary layouts remain compatible; the extension and magic/format identifier change for new saves. Loaders accept both the CW-native identifier and the corresponding MiniCE identifier, so existing projects and profiles remain usable. New code and new files must not introduce MiniCE naming outside this explicit compatibility boundary.

## Locale files

Graphical UI translations live in `locales/<locale>.json`. Locale files are UTF-8 JSON and use a deliberately small flat object schema:

```json
{
  "_meta.code": "en-US",
  "_meta.name": "English",
  "app.name": "Cheat Wizard",
  "nav.scanner": "Scanner"
}
```

Rules:

1. Keys are stable dotted identifiers. Translators change values, not keys.
2. Values are strings only. Unknown keys are ignored so newer locale files remain safe on older builds.
3. `en-US` is the canonical fallback. Critical English strings are compiled into the GUI so a missing, malformed or incomplete JSON file never prevents startup.
4. An external locale file overrides only the keys it contains. Missing keys fall back to compiled English.
5. Initial shipped locales are `en-US` and `pt-BR`.
6. Locale rendering is UTF-8 aware; locale JSON may use accented characters directly.

The shipped `en-US.json` and `pt-BR.json` cover the visible Cheat Wizard GUI surface, including Scanner/Wizard flows, scan results and ranking, Address List actions, Pointers, process picker, file dialogs and the Trainer project editor. The compiled English fallback uses the same key set, so a missing or partial external locale never exposes old Portuguese hard-codes in the main GUI.

The command-line tools and the fixed runtime chrome of generated trainer executables use English operational text. Trainer-authored titles, subtitles and field labels are stored in the project/package and are emitted exactly as authored.

## Locale discovery and persistence

The GUI resolves files relative to its own executable directory, not the process working directory:

```text
cw-gui.exe
cw-settings.json
locales/
  en-US.json
  pt-BR.json
```

`cw-settings.json` stores the selected locale:

```json
{ "locale": "pt-BR" }
```

If settings are missing or invalid, the GUI selects `pt-BR` for a Portuguese Windows UI language and `en-US` otherwise. If the selected external JSON cannot be loaded, compiled English remains active.

Changing language must not require restarting the target process or invalidate scans, watched addresses, pointer chains or trainer-project state. Only presentation strings change.

## Adding another language

To add a locale later:

1. Copy `locales/en-US.json` to a BCP-47-style code such as `es-ES.json`.
2. Keep every key unchanged and translate the values.
3. Set `_meta.code` and `_meta.name` appropriately.
4. Place the JSON in the `locales/` directory beside the GUI. The application discovers `*.json` locale files at startup; no locale registry rebuild is required.
5. Run locale fallback/UTF-8/layout validation before packaging.

The flat schema is intentional for the Win32/no-CRT frontend: it keeps the loader small, deterministic and auditable without introducing a general-purpose JSON/runtime dependency.
