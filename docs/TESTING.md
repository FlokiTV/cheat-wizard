# Testing

## Automated suites

Non-Windows builds produce four suites:

```text
cw_core_tests
cw_mock_scanner_tests
cw_mock_aob_tests
cw_mock_pointer_tests
```

`cw_core_tests` covers numeric parsing, scan comparisons, rel8/rel32 arithmetic, common relative-instruction decoding, `.cwaob` AOB session persistence, pointer-chain graph search, root-module filtering, signed offsets, `.cwchain` persistence, `.cwmap` persistence, in-memory multi-session comparison, and one-map-at-a-time file comparison.

`cw_mock_scanner_tests` executes the real `MemoryScanner.cpp` against mocked Win32 memory.

`cw_mock_aob_tests` executes the real `AobScanner.cpp` and covers exact/wildcard/nibble matching, range/executable filters, and chunk-boundary signatures.

`cw_mock_pointer_tests` executes the real `PointerScanner.cpp` and covers 32/64-bit pointer widths, index construction, chain resolution/rescan, pointer-slot alignment, writable-only filtering, and private-only filtering.

Run Release tests:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

## Sanitizers

```bash
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"
cmake --build build-asan
ctest --test-dir build-asan --output-on-failure
```

## Windows integration checklist

```bat
test-windows.bat
```

Then, against a process you control:

1. attach and perform a typed or mixed value scan;
2. refine and verify `set` / `freeze`;
3. run an AOB scan and verify `aob-results`;
4. save with `aob-save`, restart/re-attach, then verify `aob-rerun` finds fresh current-memory matches;
5. verify `aob-load` rebases module-contained results and treats absolute saved hits as potentially stale;
6. use known direct and RIP-relative instructions to verify `aob-resolve` and `aob-decode`;
7. compare pointer scans with default settings and with writable/private/root filters;
8. capture independent pointer maps and compare them both with `pmap-compare` and `pmap-compare-files`;
9. save/load `.cwchain` chains and rescan after restarting the target;
10. resolve a raw address and validate `read-at`, `write-at`, and `freeze-at`.

## v1.0 persistence/streaming coverage

Core tests round-trip `.cwscan`, `.cwaob`, `.cwchain`, and `.cwmap` files. Pointer-map tests verify both all-maps-in-memory comparison and the one-map-at-a-time file workflow used by `pmap-compare-files`.

## v1.7 pointer profile / trainer checks

Core tests include a `.cwptr` redundant-chain round trip. Before a release also run the native Trainer Builder smoke:

```powershell
.\tests\TrainerBuilderSmoke.ps1 -Builder .\build\Release\cw-trainer-builder.exe -WorkDir .\build\trainer-smoke
```

Windows integration additions:

1. validate a stable pointer set with restart/rescan;
2. save it as `.cwptr` from the GUI;
3. restart both Cheat Wizard and the target, attach, load the profile, and verify consensus;
4. add the profile to the Trainer Builder and save the trainer project;
5. build the project with `cw-trainer-builder.exe`, launch the generated standalone trainer, and verify current value, write and freeze behavior.
