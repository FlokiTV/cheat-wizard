# Standalone Product Builder

`Cheat-Wizard-Builder.exe` is the end-user distribution entry point for Cheat Wizard on Windows x64.

## Goal

The user downloads one executable, launches it, and clicks **Build & Launch**. The builder then compiles the application locally without requiring Visual Studio, CMake, Git, Python, package managers, or a network connection.

This is a source-first distribution model. It is not intended to bypass antivirus products or Windows security controls.

## Embedded payload

The builder embeds one ZIP payload as a Windows `RCDATA` resource. The payload contains:

- the Cheat Wizard source files required by the end-user product;
- public `include/cw` headers;
- GUI/trainer frontend sources;
- locale JSON files;
- `LICENSE` and `NOTICE`;
- a dependency-pruned llvm-mingw toolchain;
- build metadata with source revision, source digest, protocol version and toolchain identity.

The current toolchain is pinned to llvm-mingw 20260908 UCRT x64. The upstream archive SHA-256 is checked before a payload can be prepared.

## Local build sequence

The builder extracts the payload to a unique directory under `%TEMP%` and uses the embedded compiler directly. It does not invoke CMake on the client.

The build sequence is:

1. compile shared core / IPC sources;
2. build and validate `cw-engine.exe`;
3. build and validate `Cheat Wizard.exe`;
4. build the native trainer runtime template;
5. embed that runtime into and build `cw-trainer-builder.exe`;
6. generate SHA-256 build manifests;
7. stage the complete application folder beside the requested destination;
8. atomically replace the destination folder;
9. delete the temporary build workspace.

The generated folder contains:

```text
Cheat-Wizard/
  Cheat Wizard.exe
  cw-engine.exe
  cw-trainer-builder.exe
  cw-engine.build.json
  cw-build-manifest.json
  README.txt
  LICENSE
  NOTICE
  locales/
    en-US.json
    pt-BR.json
```

The CLI frontend remains available to source developers and CI but is not emitted by the end-user builder.

## User interface

Normal launch opens a small native Win32 window. The default output directory is a `Cheat-Wizard` folder beside the builder.

The primary action is **Build & Launch**. Compilation runs on a worker thread so the window remains responsive. The window cannot be closed while a build is active.

On success, the builder launches the locally compiled `Cheat Wizard.exe`.

## Headless mode

CI and reproducibility checks use the same executable:

```bat
Cheat-Wizard-Builder.exe --headless --output-dir C:\Temp\Cheat-Wizard
```

Optional `--launch` launches the generated GUI after a successful headless build.

A failed headless build returns a non-zero exit code and writes `Cheat-Wizard-Builder-error.txt` beside the builder.

## Integrity

`cw-build-manifest.json` records:

- product version;
- architecture;
- source revision;
- source digest;
- toolchain identity;
- `builtLocally: true`;
- SHA-256 hashes for the generated executables.

`cw-engine.build.json` separately records the engine protocol/source/toolchain contract and engine SHA-256.

The builder validates generated PE architecture/subsystem and required ASLR/NX/HighEntropyVA flags. It also executes the generated engine's `--version` self-check and requires the expected IPC protocol version.

## Build-time payload preparation

Developers prepare the embedded payload with:

```powershell
.\scripts\Prepare-ProductBuilderPayload.ps1 `
  -Output .\build\product-builder-payload\product-builder-payload.zip
```

Then configure CMake with:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 `
  -DCW_PRODUCT_BUILDER_PAYLOAD="...\product-builder-payload.zip"
```

The end-user product builder compiles `cw-engine.exe` directly; a separate engine-builder executable is not required in the generated application folder.

## Validation

`tests/ProductBuilderSmoke.ps1` runs the standalone builder in a clean directory and checks:

- required output files;
- engine protocol/version self-check;
- product manifest metadata;
- SHA-256 hashes of every generated executable.

Release CI additionally scans the distributed standalone builder and its locally generated application folder with Microsoft Defender before publishing.

## Security boundary

The standalone builder does not disable Defender, add exclusions, alter Windows security settings, hide processes, download code at runtime, or use obfuscation/packing as an antivirus workaround.

If a browser/Defender reputation service flags the distributed builder, that result is treated as a release-validation failure and should be handled through normal vendor review/signing/reputation channels rather than bypass instructions.
