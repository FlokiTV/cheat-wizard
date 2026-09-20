# Cheat Wizard roadmap

## Completed through v1.7.0

- public rebrand to **Cheat Wizard (CW)** with `cw.exe`, `Cheat Wizard.exe` and `cw-trainer-builder.exe`;
- UTF-8 JSON locale system with `en-US`, `pt-BR`, fallback, persistence and dynamic locale discovery;
- real Windows process attach and memory-region scanning;
- typed and mixed Exact/Unknown scans and refinements;
- live address monitoring, verified write and per-row freeze;
- Ranking V3 proximity signal for Address List candidates;
- AOB/signature scanning, relative-instruction helpers and persistence;
- pointer discovery, targeted deep search, restart rescan and pointer maps;
- `.cwptr` redundant stable pointer profiles with consensus resolution;
- native Zinc-style Windows GUI for Scanner / Pointers / Trainer project creation;
- native single-EXE Trainer Builder with ordered form blocks, live preview, theme colors and image-to-ICO conversion;
- self-contained trainer runtime with process auto-attach, profile resolution, read/write/freeze.

## Next product work

- persistent workspace/session projects that restore scan context, Address List, pointer profiles and Trainer association;
- scan/refinement history with navigable stages;
- more explainable Ranking V3 score breakdown;
- pointer-chain stability scoring across multiple target restarts/sessions;
- automatic target reattach and profile re-resolution;
- richer Address List organization (groups/tags/filter/batch actions);
- contextual memory inspector and short-term value graphing;
- automated clean-room release packaging and broader Windows-native regression coverage.

## Later reverse-engineering work

- GUI AOB workspace;
- debugger/watchpoint support comparable to "find out what accesses/writes this address";
- richer disassembly/structure analysis.
