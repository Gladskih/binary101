# Agent Instructions - binary101

Scope: the entire repository.

## Architecture

- Static browser app:
  - `index.html` + compiled `app.js` in `dist/` bootstraps the UI.
  - Source lives in `app.ts`, which calls `detectBinaryType(file)` and `parseForUi(file)` from `analyzers/index.ts`.
- Analyzers:
  - live under `analyzers/<format>/` (for example `pe`, `jpeg`, `png`, `mp3`, `zip`),
  - are responsible for reading bytes and returning plain JS objects (no DOM).
- Renderers:
  - live under `renderers/<format>/`,
  - each renderer takes its own parsed analyzer result and returns an HTML string,
  - renderer selection by `analyzer` is handled in `ui/render-analysis.ts`,
  - are wired through `renderers/index.ts`.
- Shared helpers:
  - `binary-utils.ts` - hex/size/time helpers,
  - `html-utils.ts` - HTML escaping and small rendering helpers.

## General Editing Guidelines

- Follow `CONTRIBUTING.md` as the authoritative source for coding, testing, and verification rules.
- Follow the detection-vs-parse policy from `CONTRIBUTING.md` ("Detection Pipeline Policy"); migration debt is tracked in `TODO.md`.

## When Adding or Modifying Analyzers

- Prefer creating a new directory `analyzers/<format>/` with an `index.ts` entry.
- For new format integration, follow `CONTRIBUTING.md` ("Adding a New Analyzer" and "Detection Pipeline Policy").
- Reuse existing analyzers (PE, PNG, MP3, ZIP, PDF) as reference for structure, warnings, and error handling.

## When Modifying Renderers

- Keep renderers pure:
  - no network access,
  - no direct DOM manipulation,
  - just return HTML strings.
- Escape all user-controlled values with `escapeHtml` / `safe` from `html-utils.ts`.

## Safety and Robustness

- All parsing must be resilient to malformed or truncated files:
  - always bounds-check offsets and sizes,
  - prefer collecting warnings over throwing exceptions,
  - never assume headers are present unless you have validated them.
- Do not add dependencies on external services; analysis must remain fully local in the browser.
- If you need to choose between being "fancy" and being "robust", choose robust and simple.

## External References and Uncertainty

- Do not rely solely on model intuition about binary formats, encodings, or specs.
- When behavior is subtle or ambiguous, prefer authoritative sources:
  - official specifications or standards for the format,
  - upstream project documentation and source code,
  - relevant GitHub issues or discussions for the tools in use.
- If network access or external lookup is unavailable, be explicit about uncertainty:
  - clearly separate what is known from what is guessed,
  - ask the user for clarification, references, or sample files when that can change the answer.
- Prefer a clearly documented "I am not sure because X" over a confident but incorrect guess.
