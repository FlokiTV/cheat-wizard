# Cheat Wizard Design System

Version: 1.7.0

## Principles

1. **Dense, not cramped.** Memory tools contain tables and technical values, so space should be used efficiently without recreating legacy Win32 density.
2. **State must be visible.** Attached, scanning, frozen, write verified, unreadable, and error are visually distinct.
3. **One primary action per context.** Attach and First Scan use the accent color; destructive or secondary operations do not compete with them.
4. **Monospace where identity matters.** Addresses and numeric memory values use Consolas; labels and navigation use Segoe UI.
5. **No decoration without purpose.** Zinc is the structural palette; semantic colors only communicate state.

## Color tokens

| Token | Value | Use |
|---|---|---|
| `bg` | `#09090B` | application background |
| `panel` | `#18181B` | cards / major containers |
| `surface` | `#27272A` | fields / buttons / table header |
| `hover` | ~`#333338` | pointer hover |
| `selected` | `#3F3F46` | selected rows |
| `border` | `#27272A` | soft boundaries |
| `border-strong` | `#3F3F46` | popup / focus boundaries |
| `text` | `#F4F4F5` | primary content |
| `text-strong` | `#FAFAFA` | titles / selected content |
| `muted` | `#A1A1AA` | secondary labels |
| `subtle` | `#71717A` | hints / empty states |
| `primary` | `#2563EB` | primary button |
| `primary-hover` | `#3B82F6` | primary hover |
| `success` | `#34D399` | verified / active status |
| `warning` | `#FBBF24` | overwritten / partial status |
| `error` | `#F87171` | failed operation |

## Typography

- Window/title: Segoe UI Semibold, 23 px-ish native size.
- Section title / button: Segoe UI Semibold, 16 px-ish.
- Body: Segoe UI, 16 px-ish.
- Helper/table header: Segoe UI, 14 px-ish.
- Address/value cells: Consolas, 15 px-ish.

## Spacing

Base unit: approximately 4 px.

Common spacing:

- application margin: 18 px;
- card gap: 14 px;
- card inner padding: 16-18 px;
- control height: 34-40 px;
- table row: 30 px;
- popup row: 30 px;
- corner radius: 8-12 px.

## Components

### Card

- panel background;
- soft border;
- 12 px corner radius;
- title 18 px from left/top;
- optional muted subtitle.

### Field

- surface background;
- soft border;
- 8 px corner radius;
- focused/open state uses primary border;
- labels are uppercase muted helper text above the field.

### Button

Secondary:

- surface background;
- hover background one Zinc step lighter;
- soft border;
- strong text.

Primary:

- blue-600 background;
- blue-500 hover;
- white/near-white text.

Disabled:

- panel/surface background;
- zinc-600 text;
- click ignored.

### Table

- no OS list-box chrome;
- table header uses surface background;
- rows are transparent on panel;
- hover uses hover token;
- selection uses selected token;
- no full grid lines; alignment provides structure;
- thin custom scroll indicator on the right.

### Freeze cell

- empty square = not frozen;
- blue checked square = frozen and last write succeeded;
- amber `!` = frozen but last write failed.

### Footer status

Persistent rather than modal.

- gray dot/text: neutral;
- green: confirmed;
- amber: warning;
- red: failure.

## Copy conventions

User-visible GUI copy should be routed through locale keys when practical. `en-US` is the canonical fallback and `pt-BR` is the initial translated locale; new UI strings should be added to both shipped JSONs together.

Prefer concise operational language:

- `Anexar`
- `Primeiro Scan`
- `Next Scan`
- `Novo Scan`
- `+ Adicionar`
- `Escrever`
- `Congelar / Descongelar`
- `Remover`
- `Limpar`

Status text may explain technical behavior in one sentence, especially for write/readback mismatch.
