# Cheat Wizard quick start

## GUI: find a value and then a pointer

1. Run `cw-gui.exe` (or `bin\cw-gui.exe` in the repository release layout).
2. Select the target process and click **Attach / Anexar**.
3. In **Scanner**, find/refine the value until you have the correct address.
4. Double-click the result to add it to the Address List.
5. Select that watched row and open **Pointers / Ponteiros**.
6. Start with the balanced/default settings and search for pointer chains.
7. Keep Cheat Wizard open, restart the target process, reattach, and find the value again.
8. Add the new address, return to Pointers, then rescan the existing chains.
9. Repeat the restart/rescan cycle until the chain set is small and stable.
10. Save the stable profile as `.cwptr`.

The default pointer root is the main executable module. Only broaden the root search when the normal search produces no useful chain.

## Reuse a stable `.cwptr`

On a later process run, attach to the process, load the `.cwptr` profile in the Pointers workspace and add its resolved value to the Address List. The current address is resolved from module-relative chains; old absolute heap addresses are not reused.

## Build a standalone trainer

1. Save one stable `.cwptr` for each logical value.
2. Open the **Trainer** workspace in `cw-gui.exe`.
3. Add the profiles, labels/defaults and optional layout/text blocks.
4. In **Visual**, configure colors and optionally choose or convert an image to `.ico`.
5. Save `trainer.cwtrainer`.
6. Build the single EXE:

```bat
cw-trainer-builder.exe build trainer.cwtrainer -o MyTrainer.exe
```

The generated trainer embeds its validated profiles and runtime; it does not require `cw.exe`, `cw-gui.exe`, JSON or external `.cwptr` files at runtime.

## CLI basics

Attach:

```text
cw> processes
cw> attach-name target.exe
```

Known value:

```text
cw> scan int32 100
cw> next 83
cw> next 61
cw> results 20
```

Unknown type/value:

```text
cw> scan all unknown
cw> next decreased
cw> next unchanged
cw> results 20
```

Verify and modify:

```text
cw> inspect #0
cw> set #0 250
cw> freeze #0 250
```

Raw resolved address:

```text
cw> read-at 0x12345678 int32
cw> write-at 0x12345678 int32 250
cw> freeze-at 0x12345678 int32 250
```

Pointer scan:

```text
cw> pointer-settings
cw> pointer-settings writable on
cw> pointer-settings private on
cw> pointer-settings branch 2048
cw> pointer-settings root target.exe
cw> pointer-scan #0 4 0x1000 10000
cw> pointer-results 20
cw> pointer-save candidate.cwchain
```

After restart/reacquiring the dynamic value:

```text
cw> pointer-load candidate.cwchain
cw> pointer-rescan #0
```

Pointer maps:

```text
cw> pmap-capture run1.cwmap #0
cw> pmap-load run1.cwmap
cw> pmap-load run2.cwmap
cw> pmap-compare 4 0x1000 10000
```

AOB/signature scan:

```text
cw> aob-module-code target.exe E8 ?? ?? ?? ??
cw> aob-results 20
cw> aob-decode #0
```

New saves use `.cwscan` for scan sessions, `.cwaob` for AOB sessions, `.cwchain` for pointer sets, `.cwmap` for pointer maps and `.cwptr` for stable trainer-oriented profiles. The corresponding MiniCE formats `.mces`, `.mcea`, `.mcep`, `.mcpm` and `.mcptr` remain readable for backward compatibility.
