# CW Engine Builder

Status: **standalone builder implementation in progress**

`cw-engine-builder.exe` is the local compiler/bootstrap component for the interactive Cheat Wizard engine. It performs a genuine local source build and writes the resulting `cw-engine.exe` beside Cheat Wizard (or to an explicitly supplied output directory).

It does not download executable code at runtime and it does not contain a prebuilt `cw-engine.exe`.

## Build model

The official builder embeds one compressed payload as a Windows `RCDATA` resource. The payload contains:

- the auditable engine source files used by `cw-engine.exe`;
- the `include/cw` public headers;
- a pruned x64 llvm-mingw toolchain;
- a VERSIONINFO resource script;
- source/toolchain metadata;
- the upstream llvm-mingw license.

At runtime the builder:

1. extracts its embedded payload to a unique directory under `%TEMP%`;
2. compiles each engine translation unit to a separate object file;
3. compiles the VERSIONINFO resource;
4. links a static Windows x64 `cw-engine.exe`;
5. validates the PE architecture/subsystem and ASLR/NX/HighEntropyVA flags;
6. runs `cw-engine.exe --version` and checks protocol `1.0`;
7. calculates SHA-256 using Windows CNG;
8. writes `cw-engine.build.json`;
9. stages the engine and manifest beside Cheat Wizard;
10. replaces the previous engine/manifest with rollback backups;
11. deletes the build workspace.

A failed build or validation does not install the candidate.

## Toolchain pin

Current toolchain:

- project: `llvm-mingw`
- release: `20260908`
- variant: `ucrt-x86_64`
- upstream archive: `llvm-mingw-20260908-ucrt-x86_64.zip`
- pinned upstream SHA-256: `1bcf74d06b724aeecaa6412ca85f5b26fb1da770e7cdcefa9263c9c5c3ad34b6`
- runtime toolchain id: `llvm-mingw-20260908-ucrt-x86_64-minimal`

The complete upstream package is **not** embedded. `scripts/Prepare-EngineBuilderPayload.ps1` compiles the engine once with the verified upstream distribution using `-MD`, collects the exact system/C++ headers observed in the dependency files, adds the exact compiler/linker/runtime components required by the link contract, and then proves the pruned toolchain with another clean source -> object -> link build.

On the current engine source this reduces the unpacked toolchain to roughly 146 MiB. The compressed payload is roughly 58 MB; exact size/hash can change when source/header dependencies change.

## Preparing the payload

From a Windows development checkout:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Prepare-EngineBuilderPayload.ps1 ^
  -Output .\\build\\engine-builder-payload\\engine-builder-payload.zip
```

The script downloads the pinned archive only when absent from cache, verifies SHA-256, generates exact dependency files, constructs the minimal payload, validates the pruned compiler by building/executing the generated engine, and writes the compressed payload.

## Building the standalone builder

Configure CMake with the prepared payload:

```powershell
cmake -S . -B build\\engine-builder -G "Visual Studio 17 2022" -A x64 ^
  -DCW_ENGINE_BUILDER_PAYLOAD="$PWD\\build\\engine-builder-payload\\engine-builder-payload.zip"

cmake --build build\\engine-builder --config Release --target cw_engine_builder
```

If `CW_ENGINE_BUILDER_PAYLOAD` is not supplied, normal development builds skip `cw-engine-builder.exe` rather than downloading a compiler during CMake configuration.

## Builder CLI

Default behavior installs the locally compiled engine beside the builder:

```text
cw-engine-builder.exe
```

Tests and development can redirect installation:

```text
cw-engine-builder.exe --output-dir C:\\path\\to\\portable-folder
```

## Generated manifest

```json
{
  "schema": 1,
  "engineVersion": "1.7.3",
  "protocolMajor": 1,
  "protocolMinor": 0,
  "architecture": "x64",
  "sourceRevision": "<git revision>",
  "sourceDigest": "<sha256>",
  "toolchain": "llvm-mingw-20260908-ucrt-x86_64-minimal",
  "engineSha256": "<sha256>",
  "builtLocally": true
}
```

## Licensing

The embedded toolchain contains LLVM/Clang, LLD, libc++, libunwind and mingw-w64 components as distributed by llvm-mingw. The upstream package includes the Apache License 2.0 with LLVM Exceptions plus third-party license terms.

A verbatim copy is kept at `third_party/llvm-mingw/LICENSE.TXT` and is also included inside the payload as `TOOLCHAIN-LICENSE.txt`.

## Security posture

The local-build flow exists to make the application boundary explicit and keep engine source auditable. It is not an antivirus-evasion mechanism. The builder uses a conventional compiler/linker, performs a real source compilation, does not patch a prebuilt engine, does not fetch code at runtime, does not disable/whitelist Defender, validates the PE before installation, and preserves the prior engine on installation failure.
