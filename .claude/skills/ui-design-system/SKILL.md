---
name: ui-design-system
description: UI design system toolkit for Senior UI Designer including design token generation, component documentation, responsive design calculations, and developer handoff tools. Use for creating design systems, maintaining visual consistency, and facilitating design-dev collaboration.
---

<!--
Adapted from davila7/claude-code-templates@1e4020dba64cfb0e65e0cb8d6bec97f532cb33d4 (MIT),
cli-tool/components/skills/creative-design/ui-design-system/ (SKILL.md and scripts/design_token_generator.py).
Changes (2026-10-27, T-UX-TOOLS): the source was a wrapper around a Python token generator. The script is not copied
(no commands in this folder); its method and default values are written out below as guidance, with two corrections
(semantic colour contrast; the script's "scss" export called a method that does not exist). Added "This repository".
-->

# UI Design System

Guidance for creating and maintaining a scalable design system: tokens, component sizing, responsive rules and
developer handoff. Produce tokens by reasoning and writing them out; there is no script to run.

## This repository

- Tokens already exist: `frontend/src/styles/tokens.css`, in three tiers: primitive `--p-*` (never used by
  components), semantic (`--color-text`, `--space-3`, …; dark mode is redefined here only) and component
  (`--button-*`, `--input-*`). Extend those tiers; do not start a parallel system.
- Every semantic colour pair must pass contrast in light and dark. `frontend/tests/styles/tokens.spec.ts` checks
  this (the tokens.css header still names it `contrast.spec.ts`), so add new pairs there.
- Breakpoints cannot be CSS variables inside `@media`. Use the em values documented in tokens.css.
- No third-party fonts or CDNs (CSP). Use system font stacks or self-hosted files.

## Token method (from the source generator)

**Colour**
- Primary scale 50–900 from the brand colour, in HSV: steps below 500 hold value at 0.95; from 500 up, value falls
  linearly to 0 at 1000; saturation rises with the step (`s × (0.3 + 0.7 × step/900)`). `DEFAULT` = the brand colour.
- Secondary = the brand hue rotated 180°, same scale.
- Neutral ramp 50–900 (the source used Tailwind gray: `#F9FAFB` … `#111827`).
- Semantic: success, warning, error, info, each with `base`, `light`, `dark` and a `contrast` text colour.
  **Correction:** the source paired white text with every base colour. White on amber `#F59E0B` (about 2.1:1) or green
  `#10B981` (about 2.5:1) fails 4.5:1. Pick the text colour per pair by measured contrast (often a dark text on
  warning and success), and use the `dark` shade for text on light surfaces.
- Surface: background, foreground, card, overlay (`rgba(0,0,0,.5)`), divider. Redefine all of them for dark mode.

**Typography**
- Base 16px; modular scale ratio 1.25 (major third): xs 10, sm 13, base 16, lg 20, xl 25, 2xl 31, 3xl 39, 4xl 49,
  5xl 61 (px, rounded). Do not use the 10px step for body text.
- Weights 100–900 named thin … black; line heights 1, 1.25, 1.375, 1.5 (body), 1.625, 2; letter spacing −0.05em to
  0.1em.
- Text styles: h1 48/700/1.2, h2 36/700/1.3, h3 28/600/1.4, h4 24/600/1.4, h5 20/600/1.5, h6 16/600/1.5,
  body 16/400/1.5, small 14/400/1.5, caption 12/400/1.5.

**Spacing and sizing**
- 8pt grid: multipliers 0, 0.5, 1, 1.5, 2 … 64 × 8px; semantic aliases xs 4, sm 8, md 16, lg 24, xl 32, 2xl 48,
  3xl 64.
- Containers 640 / 768 / 1024 / 1280 / 1536. Buttons and inputs: sm 32px high (padding 12), md 40 (16), lg 48 (20).
  Icons 16 / 20 / 24 / 32. Keep touch targets at least 24×24 CSS px (WCAG 2.5.8), 44×44 where possible.

**Borders, shadows, motion, layers**
- Radius: modern 4/8/12/16/24, classic 2/4/6/8/12, playful 8/16/20/24/32, plus `full` 9999px; widths 1, 2, 4px.
- Shadows: layered low-alpha black (`0 1px 3px rgba(0,0,0,.1), 0 1px 2px rgba(0,0,0,.06)` and up). In dark mode,
  express elevation with surface lightness, not shadow alone.
- Motion: durations 0 / 150 / 250 / 350 / 500ms; easings linear, ease-in/out, spring
  `cubic-bezier(0.68,-0.55,0.265,1.55)`; keyframes fadeIn, slideUp (10px), scale (0.95→1). Honour
  `prefers-reduced-motion: reduce` for all of them.
- Breakpoints xs 480, sm 640, md 768, lg 1024, xl 1280, 2xl 1536.
- z-index: dropdown 1000, sticky 1020, overlay 1030, modal 1040, popover 1050, tooltip 1060, notification 1070.

**Export**
- As CSS custom properties: flatten nested names with `-` (`--colors-primary-500`). Then map them to this repo's
  semantic names rather than shipping the flat set.
- JSON is fine for handoff documents. (The source's SCSS export was broken; write SCSS maps by hand if ever needed.)

## Handoff checklist

- Each component documents its tokens, states (default, hover, focus-visible, active, disabled, invalid), sizes and
  keyboard behaviour.
- Contrast is verified for every text/background pair in both themes.
- Responsive rules are stated as breakpoints in em, with a 320px minimum width that does not scroll horizontally.
