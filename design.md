# REVLab UI Design

This is a compact workbench for repeatable PE and engine analysis. The interface favors evidence, current state, and recoverable actions over decorative panels.

## Genre

Modern-minimal operations workbench.

## Macrostructure

- App pages: Operations Workbench with a persistent header, visible run summary, evidence panels, and explicit status states.
- Workflow pages: Existing Vue Flow canvas and run panel remain the source of truth for graph execution.

## Theme

- Paper: `oklch(17% 0.018 250)`
- Panel: `oklch(22% 0.022 250)`
- Ink: `oklch(93% 0.018 220)`
- Muted ink: `oklch(70% 0.025 230)`
- Accent: `oklch(78% 0.14 205)`
- Success: `oklch(73% 0.16 145)`
- Warning: `oklch(78% 0.15 85)`
- Danger: `oklch(70% 0.18 25)`

## Typography and spacing

The static UI uses Segoe UI for readable labels and Cascadia Code for hashes, addresses, paths, and machine output. Spacing follows a 4-point scale from `--space-1` through `--space-8`. Cards and controls use a 5–7px radius so dense tables remain easy to scan.

## Interaction contract

Every API-backed action exposes loading, success, error, and empty states. Long-running work is represented by the real pipeline or engine status returned by the backend. Dynamic execution is labeled as blocked when the configured policy does not provide an isolated VM; the UI never turns a policy block into a fake success.

## Content voice

Use short, factual labels. Say what is available, what is missing, and what evidence was collected. Avoid claiming that an optional tool, AI model, network capture, or dynamic run succeeded until the backend reports it.
