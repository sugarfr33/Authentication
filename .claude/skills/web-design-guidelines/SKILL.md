---
name: web-design-guidelines
description: Review UI code for Web Interface Guidelines compliance. Use when asked to "review my UI", "check accessibility", "audit design", "review UX", or "check my site against best practices".
argument-hint: <file-or-pattern>
---

<!--
Adapted from davila7/claude-code-templates@1e4020dba64cfb0e65e0cb8d6bec97f532cb33d4 (MIT),
cli-tool/components/skills/creative-design/web-design-guidelines/SKILL.md.
Changes (2026-10-27, T-UX-TOOLS): the source fetched the guidelines from GitHub on every run (WebFetch). This copy
makes no outbound call: it reads a pinned, vendored copy in guidelines.md (vercel-labs/web-interface-guidelines,
MIT, LICENSE.txt). Added the "This repository" notes. To update the rules, a person re-vendors guidelines.md.
-->

# Web Interface Guidelines

Review files for compliance with the Web Interface Guidelines.

## How It Works

1. Read the rules in [guidelines.md](guidelines.md) (this folder). Do not fetch anything.
2. Read the specified files (or ask the user which files or pattern to review).
3. Check them against every rule in guidelines.md.
4. Output findings in the terse `file:line` format that guidelines.md specifies.

## This repository

The guidelines are written for React. Apply their intent to Vue 3 single-file components:

- `onKeyDown`/`onClick` → `@keydown`/`@click`; `htmlFor` → `for`; `spellCheck={false}` → `spellcheck="false"`;
  `autoFocus` → `autofocus` or a focus call in `onMounted`.
- "Hydration safety" does not apply (the SPA is client-rendered).
- "URL reflects state" and "nuqs" map to Vue Router query parameters.
- Design tokens are in `frontend/src/styles/tokens.css`; components should use semantic tokens, never primitives.
- Auth pages deliberately keep generic error wording (account enumeration). Do not flag it as "error message lacks the
  fix", unless the next step can be named without revealing whether the account exists.

Review only: report findings, do not edit files unless the user asks for fixes.
