## v1.7.0 — input ergonomics and Trainer Visual editor

Cheat Wizard custom text fields now support caret placement, selection, Ctrl+A, arrows, Home/End, Delete/Backspace and double-click select-all. The Pointer workspace uses clearer profile actions and live-value wording. The Trainer workspace adds Configuração/Visual sub-tabs, `.ico` selection, six theme colors and a live preview; generated trainers consume those visual settings.

# Native Windows GUI

## v1.6.0 — Scanner + Pointers + persistent profiles

`bin/Cheat Wizard.exe` is the Windows x64 graphical frontend for Cheat Wizard. It uses the custom Zinc GDI renderer, custom retained text fields, virtual tables, double-buffered painting and background workers for whole-memory operations.

## Navigation

The header contains two workspaces:

```text
Scanner | Ponteiros       [target process] [Atualizar] [Anexar]
```

The target process is shared. Switching workspaces never changes the attachment.

## Scanner workflow

```text
select process -> attach -> First Scan -> change target value -> Next Scan
-> add candidate -> watch Current -> Write / Freeze / Pointers
```

The scan-result and watched-address tables both show the value captured by the scan separately from the live value currently stored in memory. Visible live values refresh approximately once per second.

A watched row remains in the Address List across `Novo Scan`, but watched absolute addresses are cleared when attaching to a different process.

## Pointer workflow

A pointer search always starts from a watched address. Select the correct row and press **Ponteiros**. Cheat Wizard carries the address and numeric type into the Pointer workspace automatically.

The target card shows:

```text
address
type | current value
```

### Search presets

The first UI deliberately exposes presets instead of raw pointer-search parameters:

| Preset | Depth | Max offset | Work budget | Behavior |
| --- | ---: | ---: | ---: | --- |
| Rapida | 3 | `0x400` | 250k steps | Small, quick search |
| Equilibrada | 5 | `+0x2000` / `-0x100` | 2M steps | Broader default with 4-byte source alignment |
| Profunda | 6 | `+0x4000` / `-0x400` | layered | Targeted reverse scan without a giant global index |

Fast/Balanced build a bounded pointer index first. If that indexed path finds no chain, **Auto falls back to the targeted layered engine** instead of treating an empty or partial index result as final. **Deep uses targeted mode directly** and never depends on the 8M global-index ceiling. Static roots in any loaded module are considered by default; the root toggle can deliberately restrict discovery to the attached executable when desired.


### Long searches and progress

Rapida/Equilibrada still show global-index and reverse-search progress. Profunda now shows a layered search such as:

```text
Busca direcionada por camadas. Nivel 2 / 6 | fronteira 137
Slots lidos: 42811392 | matches: 816
```

Each layer is a finite pass over eligible source memory and `Cancelar busca` remains available. If a frontier grows past its safety cap, the final diagnostic says `fronteira limitada` instead of silently dropping the condition.

### Results

The chain table shows:

```text
# | Base | Offsets | Resolvido | Estado
```

`Base` is module-relative (for example `game.exe+0x123456`). `Offsets` is the dereference/offset sequence. `Resolvido` is refreshed for visible rows against the current process. `ALVO` means the chain currently resolves exactly to the selected target address.

Visible chains are cached and refreshed on the one-second UI timer; they are not reread on every mouse movement/repaint.

### Stability / Rescan

Finding chains once is not enough. The intended workflow is:

```text
1. find current value address
2. Encontrar ponteiros
3. restart target process (keep Cheat Wizard open)
4. attach to new process instance
5. find the same value again
6. add the new address to Address List
7. click Ponteiros on the new address
8. Reescanear
9. repeat as needed
```

Pointer chains are intentionally preserved across target reattachment, but the old absolute target address is invalidated. A rescan keeps only chains that resolve to the newly selected target address.

Pointer scan/rescan runs on a worker thread. **Cancelar busca** requests cancellation. GUI rescan filters into a temporary buffer so cancellation does not partially corrupt the previous chain set.

## Save and reuse a stable pointer

After repeated restart/rescan cycles leave a stable set, do not throw the redundant chains away.

```text
Pointer results -> Salvar -> value.cwptr
```

The profile stores the value type plus every surviving chain. On a later run:

```text
attach target -> Ponteiros -> Carregar -> + Lista
```

`Carregar` resolves every chain it can. The status footer reports how many resolved chains agree on the same address, for example `11/11`. `+ Lista` promotes that current resolved address into the normal Address List, where the existing Write/Freeze actions work normally.

The watched row is an absolute address for the current process instance; the **`.cwptr` file is the restart-stable object**. After another restart, load the profile again rather than reusing an old watched address.

`.cwptr` differs from `.cwchain`: `.cwchain` is a lower-level CLI chain file, while `.cwptr` is a typed redundant-chain profile intended for GUI reuse and trainer frontends.

## Write verification and Freeze

A manual write is immediately reread:

- matching bytes -> confirmed write;
- different bytes -> the target already overwrote/recalculated the location.

If a watched address is already frozen, manual Write updates the freeze target before re-enabling the worker. Freeze runs every 10 ms; UI monitoring remains approximately 1 Hz.

## Language / locale

`Cheat Wizard.exe` loads UTF-8 translation files from `locales/*.json` beside the executable. The footer language control changes the active locale immediately and stores the selection in `cw-settings.json`. Missing or invalid locale files fall back to compiled English strings. `en-US` and `pt-BR` ship by default, and additional locale JSONs are discovered at startup without recompiling the GUI.

## Advanced CLI-only areas

The GUI now includes value scanning, pointer discovery/rescan, and `.cwptr` profile Save/Load. The CLI remains the full surface for:

- pointer-chain `.cwchain` save/load;
- pointer maps and map-file comparison;
- AOB/signature scanning and persistence;
- scan-session persistence;
- raw typed address helpers.

These can be promoted into graphical workspaces in later releases without changing the underlying engine.

## Pointer diagnostics in v1.4.3

After a pointer search, the Pointer workspace records three useful diagnostics:

- **index**: how many plausible pointer values were indexed; `[PARCIAL]` means the safety ceiling was reached;
- **pais do alvo**: how many indexed pointer values fall within the current offset window of the target address;
- **fallback direcionado**: Auto exhausted a bounded index/search without a chain and switched to the layered search;
- **fallback: todos os modulos**: shown only when the user explicitly restricted roots to the main executable and that restricted search returned no chain.

The Deep preset is **index-free**: depth 6, max positive offset `0x4000`, max negative offset `0x400`, 4-byte source alignment, and a bounded/deduplicated frontier. It scans eligible source memory at every layer and preserves static roots in loaded module ranges. An 8M partial global index is therefore no longer the failure mode for Deep.

## Trainer workspace — v1.6.0

The third top-level workspace creates configuration for the standalone trainer builder. It does not build or run a trainer itself.

Workflow:

```text
save/load stable .cwptr in Pointers
    -> Trainer
    -> + Profile atual
    -> edit label/default/Current/Write/Freeze
    -> Salvar trainer.cwtrainer
    -> cw-trainer-builder.exe build trainer.cwtrainer -o MyTrainer.exe
```

The project target process is shared with the attached process when the project is initially empty. A trainer project is limited to 8 entries in v1.6.0 so the generated native runtime remains readable without a scrolling layout.

`cw.exe` is not involved in this workflow and remains a CLI-only program.
