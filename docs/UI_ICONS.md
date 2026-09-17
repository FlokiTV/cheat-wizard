# Cheat Wizard UI iconography

Cheat Wizard's native Win32 UI uses a small embedded subset of **Material Design Icons (MDI)** from **Pictogrammers**.

- Library: Material Design Icons (MDI)
- Website: https://pictogrammers.com/library/mdi/
- Distribution used to generate masks: `@mdi/font` 7.4.47
- License: Apache License 2.0
- Source project: https://github.com/Templarian/MaterialDesign

## Runtime integration

Cheat Wizard does **not** ship the MDI webfont, load SVG files, or depend on an icon framework at runtime.

The selected official glyphs are rasterized during development from the upstream MDI 7.4.47 font into small antialiased alpha masks stored in `portable_win/MdiIconMasks.hpp`. The no-CRT GUI tints and composites those masks with native Win32 GDI/`AlphaBlend`, keeping the final executable self-contained.

Current embedded glyphs:

- `mdi:magnify` — process search
- `mdi:refresh` — refresh process list/header
- `mdi:connection` — attach/connect to a process
- `mdi:check-circle-outline` — attached state
- `mdi:file-image-outline` — choose `.ico`
- `mdi:image-sync` — convert image to `.ico`
- `mdi:content-save-outline` — save an inline address value
- `mdi:source-branch` — open pointer tools for an address
- `mdi:trash-can-outline` — remove an address from the list
- `mdi:chevron-down` / `mdi:chevron-up` — dropdowns

The generated masks preserve the actual MDI glyph silhouettes instead of approximating them with hand-written GDI lines.

## License notice

Material Design Icons and the `@mdi/font` distribution are provided under the Apache License 2.0. See:

- https://pictogrammers.com/docs/general/license/
- https://www.apache.org/licenses/LICENSE-2.0

No Brand / Logo category icon is used by Cheat Wizard.
