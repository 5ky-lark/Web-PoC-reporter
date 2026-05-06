# DESIGN — CyberSyc

## Scene

A pentester at 11pm, two monitors, terminal open in the other window. Cold coffee. They will look at this dashboard for the next 90 minutes and triage 40 findings. The room is dim.

That sentence forces the answer. Dim, terminal-adjacent, dense, mono-for-evidence. Not light, not cream, not Linear-purple.

## Color strategy: Restrained

Tinted neutrals plus **one** saturated alert hue. The alert hue is reserved for `critical`. Everything else, including warnings and high-severity, de-saturates *away* from it so critical actually steals attention.

### Tokens (OKLCH)

```css
--bg-deep:        oklch(15% 0.012 260);  /* deepest ink, slight cool tint */
--bg:             oklch(18% 0.014 260);  /* main canvas */
--bg-raised:      oklch(22% 0.014 260);  /* raised panels */
--bg-input:       oklch(14% 0.012 260);  /* input wells, code blocks */
--bg-hover:       oklch(25% 0.015 260);  /* row hover */
--border:         oklch(30% 0.015 260);  /* hairline dividers */
--border-strong:  oklch(42% 0.018 260);  /* active / selected outlines */
--text:           oklch(95% 0.005 260);  /* primary */
--text-muted:     oklch(72% 0.008 260);  /* secondary */
--text-faint:     oklch(54% 0.010 260);  /* captions, helpers, monospace meta */

/* the single saturated hue, used for critical only */
--alert:          oklch(64% 0.22 25);
--alert-bg:       oklch(30% 0.10 25);

/* a quiet jade accent for "go", "confirm", "running" — used sparingly */
--accent:         oklch(74% 0.11 175);
--accent-bg:      oklch(26% 0.04 175);

/* severity ladder, de-saturating away from alert */
--sev-critical:   var(--alert);
--sev-high:       oklch(72% 0.14 50);   /* amber, distinct from the red */
--sev-medium:     oklch(80% 0.09 90);   /* wheat */
--sev-low:        oklch(72% 0.06 230);  /* steel */
--sev-info:       oklch(65% 0.008 260); /* tinted neutral */
```

No `#000`, no `#fff`. Every neutral is tinted toward the cool 260° hue at chroma ~0.01.

## Type

- UI: **Inter** (already loaded). Body 13px / 1.45. Tabular numerals everywhere (`font-feature-settings: 'tnum', 'cv11'`).
- Mono: **JetBrains Mono** (already loaded). 12.5px / 1.55. Used for: payloads, evidence, IPs, hostnames, CVSS vectors, URLs, finding IDs.
- Scale: 11 / 12.5 / 13 / 14 / 16 / 20 / 24 / 32 px. Step ratio averages 1.2; ≥1.25 between display sizes.
- No `text-transform: uppercase` + `letter-spacing` decoration. Forbidden tic.

## Layout rules

- Max content width 1440px on the triage screen, 1200px on Run, 1100px on Engagements.
- 8px base unit. **Vary rhythm.** Tight 4px between row siblings, comfortable 16px between panel siblings, generous 32px between sections. Same padding everywhere is monotony.
- Hairline borders (`1px solid var(--border)`), no shadows on default panels. Shadow is reserved for the **detail drawer** and `critical` finding accent — earned visual weight.
- No nested panels. If something wants to nest, it becomes a row inside the parent.
- No `border-radius` over 8px. The aesthetic is precise, not friendly.

## Motion

- Single timing curve: `cubic-bezier(0.16, 1, 0.3, 1)` (ease-out-expo). Never bounce, never elastic.
- Three durations: 120ms (hover/state), 220ms (panel transitions), 380ms (severity-distribution sweep on initial render).
- New finding rows pulse the alert hue **once** on insert. Never loop animations. No infinite spinners; running modules show a hairline indeterminate progress strip.

## Severity encoding

Color **and** glyph:

- `C` critical — `--sev-critical` text on `--alert-bg`, mono
- `H` high — `--sev-high` text on tinted bg, mono
- `M` medium — `--sev-medium` text on tinted bg, mono
- `L` low — `--sev-low` text on tinted bg, mono
- `i` info — `--sev-info` text on tinted bg, mono

CVD-safe: glyph carries the meaning even at greyscale.

## Components

### Severity badge

Mono single letter, fixed width 18px, on a tinted background pill. Not a colored block of text on white.

### Finding row (triage queue)

Single dense row. Left: severity glyph. Then: tracking ID (mono `CYS-XSS-0007`), title, target host (mono), CVSS score (mono right-aligned, tabular), status (`new` / `triaging` / `confirmed` / `false_positive` / `accepted` / `fixed`), age. Click selects, doesn't expand. Detail goes to the right rail.

### Detail drawer

Right rail, 480px, scrollable. Tabs: `Description` / `Evidence` / `PoC` / `Remediation` / `Notes` / `History`. Evidence and PoC tabs are mono code blocks with copy buttons.

### Command bar

Top of every view. Single row. On Run: `[ target input ] [ profile pill row ] [ Start ]`. On Triage: `[ search ] [ severity filters ] [ status filters ] [ group: by host / module / cwe ] [ sort ]`.

### Module toggle (advanced disclosure)

Default-collapsed. When opened, two columns of compact rows (not a 17-tile grid). Each row: checkbox, module name, one-line description, last-run duration.

## Banned patterns

Direct prohibitions for this product:

- Purple→magenta gradients
- Gradient text (`background-clip: text`)
- `backdrop-filter` glassmorphism
- The hero-metric template (big-number cards as the dominant motif)
- Identical card grids
- Side-stripe colored borders > 1px
- Modal as first thought
- Decorative emoji as iconography
- Uppercase + letter-spaced labels as decoration

## Iconography

Inline SVG, 16px or 18px, single-stroke, 1.5px stroke width, currentColor. Lucide-style. No filled icons in the operator UI (filled = brand, outlined = product).

## Print / PDF

The PDF report uses the same dim palette inverted for paper:
- Background: `oklch(99% 0.005 260)` warm-white
- Text: `oklch(20% 0.014 260)`
- Severity badges: same OKLCH values, not RGB approximations

No purple gradient cover page. Cover is **black ink on warm white** with a single hairline rule and the engagement metadata block. Confidential watermark runs on every page header in 9px mono with the target hostname and scan ID.
