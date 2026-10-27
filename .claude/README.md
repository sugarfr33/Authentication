# Claude Code agents and skills

Curated prompts from [davila7/claude-code-templates](https://github.com/davila7/claude-code-templates) (MIT), with
other sources named in each file. They are prompts and markdown only. Nothing here runs a command, installs a package,
or uses hooks, MCP servers or outbound calls. Each file's header records its source commit and local changes.

## Agents (`agents/`)

| File | Use it when |
|---|---|
| api-documenter.md | writing or improving API reference docs and examples |
| api-security-audit.md | auditing REST endpoints for authentication, authorization and injection flaws |
| architect-reviewer.md | weighing a design or structural change at system level |
| code-reviewer.md | reviewing a diff for quality, security and maintainability |
| csharp-developer.md | building or optimising ASP.NET Core / EF Core code |
| penetration-tester.md | authorised, hands-on exploitation testing of this system |
| security-auditor.md | a control-by-control security or compliance review |
| sql-pro.md | SQL Server queries, indexes, migrations and schema design |
| test-automator.md | building or fixing automated test suites |
| typescript-pro.md | advanced TypeScript typing in the frontend |
| vue-expert.md | Vue 3 components, composables and reactivity |
| ui-ux-designer.md | critiquing screens, screenshots, layout, typography or colour with research-backed fixes (review only, T-UX-TOOLS) |
| accessibility-tester.md | a WCAG 2.2 AA audit with numbered findings and a scorecard, from source plus provided axe/Playwright results (read only, T-UX-TOOLS) |

## Skills (`skills/`)

| Folder | Use it when |
|---|---|
| architecture-decision-records | recording a significant technical decision as an ADR |
| broken-authentication | testing authentication and session management for weaknesses |
| dotnet-backend | ASP.NET Core backend patterns |
| security-threat-model | a repository-grounded threat model |
| systematic-debugging | any bug or test failure, before proposing a fix |
| test-driven-development | implementing a feature or fix test-first |
| accessibility-auditor | fixing or checking a component against WCAG patterns (labels, contrast, landmarks, dialogs, live regions) (T-UX-TOOLS) |
| ui-design-system | adding or changing design tokens, component sizes or handoff docs; builds on `frontend/src/styles/tokens.css` (T-UX-TOOLS) |
| web-design-guidelines | a terse `file:line` review of UI code against the vendored Vercel Web Interface Guidelines, adapted to Vue (T-UX-TOOLS) |
