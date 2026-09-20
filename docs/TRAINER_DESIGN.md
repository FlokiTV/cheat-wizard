# Cheat Wizard trainer architecture — v1.7.0

## Responsibility split

Cheat Wizard intentionally uses separate executables with separate responsibilities:

```text
cw.exe
  CLI only. Interactive memory-scanning/reverse-engineering commands.

Cheat Wizard.exe
  Visual engineering tool. Finds values and stable pointer chains, saves .cwptr
  profiles, and creates .cwtrainer projects.

cw-trainer-builder.exe
  Offline packager. Reads .cwtrainer + .cwptr profiles and produces one
  standalone trainer EXE.

MyTrainer.exe
  Standalone generated trainer. Directly attaches to the configured process,
  resolves embedded pointer profiles, reads/writes values and freezes them.
```

`MyTrainer.exe` never launches or talks to `cw.exe`. The CLI is not an RPC server and is not a trainer dependency.

## Build pipeline

```text
Cheat Wizard.exe
   |  save stable pointer profiles
   |  create trainer.cwtrainer
   v
trainer.cwtrainer + *.cwptr
   |
   v
cw-trainer-builder.exe
   |
   +-- validates schema/profile compatibility
   +-- embeds a native trainer runtime
   +-- embeds normalized config + profile bytes
   v
MyTrainer.exe
```

The builder appends a validated binary package to a precompiled native runtime template embedded inside `cw-trainer-builder.exe`. The generated EXE therefore needs no Python, JSON, external `.cwptr`, `cw.exe`, or other Cheat Wizard executable beside it.

## Generated trainer runtime

The native runtime:

- watches for the configured process by executable name;
- reattaches automatically after the process is restarted;
- discovers module bases again after each attach;
- resolves every chain in each embedded `.cwptr` profile;
- uses strict-majority consensus when a profile contains redundant chains;
- displays the current value;
- performs typed `WriteProcessMemory` writes;
- optionally freezes values using a 10 ms worker;
- refuses an ambiguous profile rather than choosing a random address.

The current builder limits a trainer project to 8 pointer-backed entries. The ordered Form Builder can additionally contain title/subtitle blocks.

## Pointer profile contract

`.cwptr` version 1 stores:

- magic/version;
- target pointer width (32/64 bit);
- numeric value type;
- source process-name metadata;
- redundant pointer-chain count;
- module-relative roots and signed offsets.

A profile contains no absolute heap address that is expected to survive a restart.

New `.cwptr` profiles use the `CWPROF01` magic. The loader and Builder also accept legacy `.mcptr` / `MCEPROF1` profiles from compatible MiniCE releases; the payload layout remains compatible.

## Single-EXE package

The generated executable layout is:

```text
[native trainer PE image]
[trainer package]
[fixed footer]
```

The package contains normalized trainer metadata and raw validated profile bytes. The footer stores package offset, package size and CRC32. On startup the runtime opens its own executable, validates the footer/package and parses only bounded fields.

New `.cwtrainer` projects use `"format": "cheat-wizard-trainer"` version 1. The Builder still accepts legacy `"format": "minice-trainer"` version 1 projects.

## Security / product boundaries

The trainer runtime uses ordinary user-mode Windows process APIs. It does not include kernel drivers, protected-process bypasses, anti-cheat bypasses, code injection or stealth mechanisms.
