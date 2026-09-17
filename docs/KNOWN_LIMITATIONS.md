# Known limitations

- The pointer scanner is bounded and is not a complete clone of Cheat Engine's pointer scanner.
- Pointer roots are static loaded-module addresses; arbitrary heap-only roots are not emitted as final chains.
- Negative offsets are disabled by default and bounded separately by `max_negative_offset`.
- Larger offset windows, byte alignment, or high branching caps can increase pointer-index/search cost substantially.
- `writable` and `private` pointer filters can reduce noise but can also remove a valid pointer source.
- Restricting `root` to the wrong module will produce false negatives.
- Full source defaults to a larger pointer-index/map capacity than the bundled portable executable.
- The bundled no-CRT executable caps pointer maps at 2,000,000 entries per map and four loaded maps.
- `pmap-compare-files` keeps only one `.cwmap` entry vector in RAM at a time. A single individual map still has to fit the configured per-map entry/RAM safety limit; there is no true per-entry on-disk index yet.
- Partial/cancelled/truncated pointer maps can cause false negatives.
- `scan all unknown` is expensive and capped at a 512 MiB raw snapshot.
- `.cwscan` persists materialized result lists, not raw Unknown Initial Value snapshots.
- `.cwscan` addresses are process-instance addresses. The default PID check is deliberate: after a target restart, heap addresses are usually stale. `force` bypasses this protection but does not make stale addresses valid.
- Supported numeric scan types are Byte, signed Int16/Int32/Int64, Float, and Double. Separate unsigned 16/32/64 scan modes are not exposed yet.
- AOB scanning is masked linear search and does not use SIMD/Boyer-Moore-style acceleration.
- The full AOB scanner caps stored matches at 1,000,000.
- `aob-resolve` is a generic rel32 decoder; the caller must provide the correct displacement offset and instruction size. It does not disassemble or validate the instruction opcode.
- No general debugger / “find what accesses this address” layer in v1.0.
- v1.5 GUI covers value scanning/address monitoring, pointer search/rescan, and `.cwptr` pointer-profile persistence. AOB and pointer-map workflows remain CLI-only.
- The v1.5 GUI browses at most the first 5,000 value-scan result rows even though refinement continues over the full in-memory result set.
- Value scans still show a busy state without detailed progress/cancellation. Pointer scans have cancellation but not byte/region progress.
- The portable no-CRT executable exposes fewer value-scan settings than the full C++ build.
- Cheat Wizard uses ordinary user-mode Win32 APIs and does not bypass protected-process restrictions, anti-cheat systems, kernel protections, or Windows access controls.

- `.cwptr` profiles are restart-stable only to the extent that at least one saved module-relative chain remains valid after target updates; game/software updates can invalidate offsets.
- The Trainer SDK is alpha. `trainer_basic.py` requires Python 3/Tkinter and currently drives the interactive CLI prompt rather than a versioned RPC protocol.
- In the alpha trainer transport, profile paths should be relative paths without spaces.
- `profile-freeze` freezes the address resolved at command time; the alpha trainer should reconnect/re-resolve after a target restart rather than assuming a freeze survives process replacement.
