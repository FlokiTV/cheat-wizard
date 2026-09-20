Cheat Wizard v1.7.3 Windows x64

Official releases:
  https://github.com/FlokiTV/cheat-wizard/releases

Executables in this public package:
  Cheat Wizard.exe              - visual Scanner + Pointers + Trainer project editor
  cw-trainer-builder.exe  - .cwtrainer + .cwptr profiles -> one standalone trainer EXE

CLI note:
  cw.exe remains available from source builds and CI, but is intentionally not
  shipped in the prebuilt v1.7.3 ZIP while a Microsoft Defender FastPath
  false-positive classification remains unresolved. Do not bypass or whitelist
  Defender to obtain the CLI; build it from the reviewed source if needed.

Locales:
  locales\en-US.json
  locales\pt-BR.json

The GUI stores the selected language in cw-settings.json at runtime. Missing or invalid
locale files fall back to compiled English strings.

Generated trainer EXEs are self-contained and do not depend on cw.exe, Cheat Wizard.exe,
cw-trainer-builder.exe, Python, JSON or external .cwptr files.

New persistence uses .cwptr/.cwchain/.cwmap/.cwscan/.cwaob and .cwtrainer. Legacy
.mcptr/.mcep/.mcpm/.mces/.mcea plus the minice-trainer identifier remain readable
for compatibility with existing projects/profiles.

License:
  Apache License 2.0. Redistributions and derivative works must preserve the
  applicable attribution notice from NOTICE. See LICENSE and NOTICE included
  with the release package.

See docs/TRAINER_BUILD.md and docs/BRANDING_LOCALES.md.
Use only with processes you are authorized to inspect and modify.
