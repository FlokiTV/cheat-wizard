# Trainer project schema — format version 1

The GUI writes a `.cwtrainer` JSON project consumed by `cw-trainer-builder.exe`. The public schema version is 1. New projects use the `cheat-wizard-trainer` format identifier; the builder also accepts legacy `minice-trainer` version 1 projects. Cheat Wizard v1.7 accepts the optional `visual` object and ordered `layout` array used by the visual Form Builder.

## Example

```json
{
  "format": "cheat-wizard-trainer",
  "version": 1,
  "trainer": {
    "name": "My Trainer",
    "process": "game.exe"
  },
  "window": {
    "width": 620,
    "height": 460
  },
  "visual": {
    "icon": "trainer.ico",
    "background": "#09090B",
    "panel": "#18181B",
    "surface": "#27272A",
    "accent": "#2563EB",
    "text": "#FAFAFA",
    "muted": "#A1A1AA"
  },
  "entries": [
    {
      "id": "money",
      "label": "Money",
      "profile": "profiles/money.cwptr",
      "defaultValue": "999999",
      "showCurrent": true,
      "allowWrite": true,
      "allowFreeze": true
    }
  ],
  "layout": [
    { "type": "title", "text": "Gameplay" },
    { "type": "subtitle", "text": "Economy controls" },
    { "type": "field", "entry": "money" }
  ]
}
```

## Required fields

- `format`: new projects use `cheat-wizard-trainer`; `minice-trainer` is accepted only as the legacy v1 alias.
- `version`: must be `1`.
- `trainer.name`: product/window name.
- `trainer.process`: target executable filename such as `game.exe`.
- `entries`: one to eight pointer-backed values.
- `entries[].id`: short unique project identifier.
- `entries[].label`: text shown for the field.
- `entries[].profile`: path to a Cheat Wizard `.cwptr` profile. Legacy `.mcptr` profiles are also accepted. Relative paths are resolved from the project directory; absolute paths are accepted.

## Optional entry fields

- `defaultValue`: initial text in the value input field.
- `showCurrent`: show the live value, default true.
- `allowWrite`: expose the editable value field and Apply action, default true.
- `allowFreeze`: expose Freeze, default true.

## Ordered Form Builder layout

`layout` is optional and may contain up to 32 elements. Array order is the final vertical render order in the generated trainer.

Supported elements:

- `{ "type": "title", "text": "..." }` — prominent content heading.
- `{ "type": "subtitle", "text": "..." }` — secondary explanatory heading.
- `{ "type": "field", "entry": "entry-id" }` — renders the pointer-backed field identified by `entries[].id`.

When `layout` is present, every entry must be referenced by exactly one `field` element; unknown or duplicate entry references are rejected. Title/subtitle text must be non-empty.

When `layout` is omitted, the builder keeps backward compatibility by synthesizing one `field` element for each entry in the original `entries` order. Existing trainer JSON files therefore keep the same behavior.

## Visual fields

All color fields use `#RRGGBB`. If `visual` is omitted, the Zinc-like defaults are used.

- `visual.icon`: `.ico` path. Relative paths are resolved from the JSON directory. The builder writes the icon into the generated EXE resource table.
- `visual.background`: trainer window background.
- `visual.panel`: pointer-field/card background.
- `visual.surface`: inputs and secondary controls.
- `visual.accent`: primary action/focus color.
- `visual.text`: primary text.
- `visual.muted`: secondary/help text.

## Window fields

`width` and `height` are initial-size hints. The native runtime enforces a minimum width/height large enough for the configured ordered elements.

## Builder validation

The builder rejects malformed JSON, unsupported schema versions, missing/malformed `.cwptr` or legacy `.mcptr` files, target-process metadata mismatches, invalid `#RRGGBB` colors, malformed `.ico` input, more than eight pointer entries, more than 32 layout elements, duplicate/missing field references, and malformed layout elements.
