# CW Engine Architecture

Status: **implemented**

This document defines the target architecture for separating Cheat Wizard frontends from process-memory access.

The change is an architectural refactor. It is **not** an antivirus-bypass mechanism. Builds must remain transparent, auditable and compatible with normal Microsoft Defender review/signing workflows.

## 1. Motivation

Today `cw.exe` and `Cheat Wizard.exe` both own live process-memory behavior. The CLI links `ProcessManager`, `MemoryScanner`, `MemoryWriter`, `FreezeManager` and `PointerScanner`; the GUI contains a separate native implementation of the same class of operations. Both therefore call target-process APIs directly.

Target state:

```text
Cheat Wizard.exe  ---- local IPC ---->  cw-engine.exe  ---- Win32 process APIs ----> target
cw.exe      ---- local IPC ---->  cw-engine.exe

Cheat-Wizard-Builder.exe -- local source/toolchain build --> Cheat Wizard.exe
                                                       +-> cw-engine.exe
                                                       +-> cw-trainer-builder.exe
                                                       +-> build manifests

GeneratedTrainer.exe remains self-contained.
```

## 2. Executable boundaries

### `Cheat Wizard.exe`

Owns window/rendering, input, locale/UI state, project/profile authoring UX and the IPC client. It must not directly call/import `OpenProcess`, `ReadProcessMemory`, `WriteProcessMemory` or use `VirtualQueryEx` for target traversal.

### `cw.exe`

Owns command parsing, terminal interaction, output formatting and the IPC client. It must not directly access target-process memory.

### `cw-engine.exe`

Owns process enumeration, attach/detach, module enumeration, pointer-width detection, typed memory access, scans, AOB, freezes, pointer discovery/rescan/profile resolution, cancellation/progress and engine-session state. It is the only interactive CW component allowed to perform target-memory operations.

### `Cheat-Wizard-Builder.exe`

Owns the end-user local build experience. It performs a real `source -> compile -> link -> validate` flow for the GUI, engine and Trainer Builder using an embedded pinned source/toolchain payload. It generates `cw-engine.exe` directly; a separate engine-builder executable is not required in the end-user folder.

## 3. Library boundaries

```text
cw_core
  deterministic algorithms + persistence
       ^
       |
cw_engine_core
  ProcessManager / MemoryScanner / AobScanner / MemoryWriter
  FreezeManager / PointerScanner
       ^
       |
cw-engine.exe + IPC server

cw_ipc
  protocol types + codec
      ^                 ^
      |                 |
cw_ipc_client       cw-engine.exe
      ^
      +-- cw.exe
      +-- Cheat Wizard.exe
```

`cw_core` stays focused on algorithms/formats where practical. A new Windows-only `cw_engine_core` owns live-process implementation. Frontend targets must never link `cw_engine_core`. `cw_ipc` contains serialization/protocol code only.

## 4. IPC transport

Transport: Windows Named Pipe. Default session model: one engine child owned by one frontend process. Each frontend instance uses a unique session pipe rather than a predictable global shared pipe.

Conceptual path:

```text
\\.\pipe\CheatWizard.Engine.<protocol-major>.<random-session-id>
```

Security requirements:

- DACL restricted to the current Windows user;
- reject remote pipe clients;
- validate the connecting client PID when supported;
- one owning frontend connection per engine session;
- random session identifier/token;
- strict maximum frame/payload sizes;
- validate every enum/count/offset/length;
- no generic shell/command-execution RPC;
- no arbitrary DLL-loading RPC;
- no service installation, startup persistence or elevation.

The engine runs with the same user token as the frontend. No admin/service architecture is required.

## 5. Lifecycle

Normal flow:

```text
frontend starts
  -> locate cw-engine.exe + cw-engine.build.json
  -> validate/start the local engine
  -> if the local product is missing/corrupt: instruct the user to rerun Cheat-Wizard-Builder.exe
  -> spawn cw-engine.exe --pipe <session> --owner-pid <pid>
  -> protocol handshake
  -> RPC
```

The engine terminates on explicit shutdown, owner disconnect/death, or frontend-owned Job Object close. The design must not intentionally leave an orphan/persistent engine.

## 6. Protocol

Protocol starts at version `1.0`. Messages use explicit serialization, never raw copies of native C++ structs.

Conceptual fixed frame header:

```text
magic           4 bytes  CWEP
protocol_major  u16
protocol_minor  u16
message_kind    u16
flags           u16
request_id      u64
payload_size    u32
reserved        u32
```

Rules: little-endian integers, bounded payloads before allocation, unknown message kinds rejected, responses echo request IDs, major mismatch fails handshake, minor compatibility is explicit.

Initial allowlisted RPC families:

- Session: `Hello`, `HelloAck`, `Ping`, `Shutdown`, `CancelOperation`;
- Processes: `ListProcesses`, `AttachProcess`, `DetachProcess`, `ListModules`, `GetTargetInfo`;
- Values: `ReadValue`, `WriteValue`;
- Scanner: `FirstScan`, `NextScan`, `NewScan`, `GetScanResults`, progress/completion events;
- Freeze: `SetFreeze`, `RemoveFreeze`, `ClearFreezes`, `ListFreezes`;
- AOB: scan/results/resolve;
- Pointers: discover/rescan/results/profile resolution.

No protocol message accepts an arbitrary command line to execute inside the engine.

## 7. Long-running work

Scans and pointer discovery run away from the GUI thread. IPC supports request IDs, progress events, completion and cancellation. Partial/cancelled work must not silently replace previously committed scan/pointer state.

## 8. File/persistence boundary

Frontends continue to own user-facing file selection and project authoring. Where practical, the engine receives validated profile/project bytes rather than arbitrary paths. Any large-file exception must be explicit and versioned rather than exposing generic filesystem access.

Existing `.cwptr`, `.cwchain`, `.cwmap`, `.cwscan`, `.cwaob` and `.cwtrainer` contracts remain supported. Legacy MiniCE formats remain compatibility/import boundaries as currently documented.

## 9. Portable local engine build

The release entry point is a single standalone builder:

```text
Cheat-Wizard-Builder.exe
        |
        +-- embedded pinned source
        +-- embedded dependency-pruned llvm-mingw
        |
        +-- Build & Launch
              |
              +-> Cheat-Wizard/
                    Cheat Wizard.exe
                    cw-engine.exe
                    cw-trainer-builder.exe
                    cw-engine.build.json
                    cw-build-manifest.json
                    locales/
                    LICENSE
                    NOTICE
```

The builder extracts only to a unique temporary workspace, compiles the product locally, validates the generated PE/protocol outputs, writes SHA-256 manifests, installs the completed folder atomically and removes the temporary workspace. It does not require Visual Studio, CMake, Git, Python or a network fetch on the client.

The toolchain is llvm-mingw 20260908 UCRT x64, pinned by upstream archive SHA-256 and dependency-pruned during payload preparation. Toolchain license/notices are preserved.

## 10. Engine manifest

`cw-engine.build.json` sits beside the generated engine. Logical schema:

```json
{
  "schema": 1,
  "engineVersion": "1.0.0",
  "protocolMajor": 1,
  "protocolMinor": 1,
  "architecture": "x64",
  "sourceRevision": "<revision>",
  "sourceDigest": "<sha256>",
  "toolchain": "<toolchain id/version>",
  "engineSha256": "<sha256>",
  "builtLocally": true
}
```

The frontend validates schema, protocol compatibility, architecture, engine existence and SHA-256. The manifest is metadata, not a standalone trust boundary.

## 11. Atomic rebuild

A failed rebuild must preserve the old engine:

```text
compile/link -> cw-engine.new.exe
              -> validate PE/protocol
              -> calculate SHA-256
              -> write manifest temp
              -> atomic replace engine
              -> atomic replace manifest
```

## 12. Trainer boundary

The new engine belongs to the interactive engineering application only. `cw-trainer-builder.exe` continues producing self-contained `GeneratedTrainer.exe` files. Trainers do not connect to `cw-engine.exe`, `cw.exe` or `Cheat Wizard.exe`.

## 13. Security / Defender posture

Do not alter the architecture to disguise behavior from security products. Requirements:

- conventional compiler/linker output and PE mitigations;
- clear VERSIONINFO;
- no packers/obfuscation/API hashing for detection avoidance;
- no instruction to disable or whitelist Defender;
- no silent executable download;
- engine source used for the local build is auditable;
- future Authenticode signing remains compatible.

A locally built engine can follow a different reputation path than a downloaded executable, but that is not a correctness criterion and must not be treated as an antivirus bypass.

## 14. Acceptance criteria

Migration is complete when:

1. `Cheat Wizard.exe` has no direct target-memory access path.
2. `cw.exe` has no direct target-memory access path.
3. PE/import audit confirms frontends do not import `OpenProcess`, `ReadProcessMemory` or `WriteProcessMemory`.
4. `cw-engine.exe` is the sole interactive CW component owning live target-memory operations.
5. GUI scanner/address-list/pointer behavior works over IPC.
6. CLI commands work over IPC.
7. write/readback/freeze semantics remain correct.
8. long operations never block the GUI message loop.
9. pipe is local/current-user restricted and all input is bounded.
10. no admin/service/persistence is introduced.
11. the standalone Product Builder genuinely compiles GUI/engine/trainer-builder source locally.
12. the Product Builder works on a supported clean Windows x64 machine without requiring Visual Studio/CMake/Git installation.
13. the generated application folder contains the locally built engine beside the GUI.
14. `cw-engine.build.json` is generated and validated.
15. failed rebuild preserves the prior engine.
16. generated Trainers remain standalone.
17. unit/IPC/E2E/regression tests pass.
18. normal Defender gates remain in CI/release.
19. stable release promotion still requires a normal manual browser-download validation.

## 15. Migration order

1. freeze architecture/protocol contract;
2. introduce protocol types/codecs + tests;
3. create `cw_engine_core` from current live-process implementation;
4. implement `cw-engine.exe` + Named Pipe server;
5. implement shared IPC client;
6. migrate `cw.exe`;
7. migrate `Cheat Wizard.exe` workspace by workspace;
8. remove duplicated direct-memory frontend code;
9. implement manifest/lifecycle;
10. implement the standalone Product Builder that generates the engine directly;
11. run regression, security and release gates.

During development a frontend may temporarily retain the old path, but the architecture is not accepted until both public frontends have lost direct target-memory imports.
