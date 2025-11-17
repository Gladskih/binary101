# Agent Instructions - binary101

These instructions are for automated code assistants (like this one).  
Scope: the entire repository.

## Architecture

- Static browser app:
  - `index.html` + `app.js` bootstraps the UI.
  - `app.js` calls `detectBinaryType(file)` and `parseForUi(file)` from `analyzers/index.js`.
- Analyzers:
  - live under `analyzers/<format>/` (for example `pe`, `jpeg`, `png`, `mp3`, `zip`),
  - are responsible for reading bytes and returning plain JS objects (no DOM).
- Renderers:
  - live under `renderers/<format>/`,
  - take `{ analyzer, parsed }` data and return HTML strings,
  - are wired through `renderers/index.js`.
- Shared helpers:
  - `binary-utils.js` - hex/size/time helpers,
  - `html-utils.js` - HTML escaping and small rendering helpers,
  - `hash.js` - hashing via Web Crypto.

## General Editing Guidelines

- Do not introduce a build step or bundler; keep plain ES modules loaded directly in the browser.
- Prefer small, focused changes over large refactors.
- Code should be self-documenting:
  - use clear, descriptive names for functions, variables, and modules,
  - keep control flow straightforward; avoid clever tricks when a simple construct is enough.
- Abbreviations:
  - avoid project-specific or obscure abbreviations,
  - only use common ones that are widely understood (for example `id`, `url`, `crc`, `pe`, `mp3`).
- Maintain the contract: `parseForUi(file)` -> `{ analyzer, parsed }` and update `app.js` plus renderers together if you change that shape.
- Keep analyzers and renderers separate:
  - analyzers: pure parsing, no DOM, no `console.log` (warnings go into result objects),
  - renderers: pure HTML formatting, no file I/O.
- Follow the style rules from `.github/copilot-instructions.md` and `.eslintrc.json`:
  - `const`/`let`, no `var`,
  - double quotes, semicolons, 1TBS brace style,
  - no unused variables.

## When Adding or Modifying Analyzers

- Prefer creating a new directory `analyzers/<format>/` with an `index.js` entry.
- Use slice-based I/O (`file.slice(...).arrayBuffer()`) and bounds checks; never read past the end of the file.
- For new formats:
  - add detection/probing in `analyzers/index.js`,
  - hook into `parseForUi` so the UI can render it,
  - add a matching renderer under `renderers/<format>/`.
- Reuse existing analyzers (PE, PNG, MP3, ZIP, PDF) as reference for structure, warnings, and error handling.

## When Modifying Renderers

- Keep renderers pure:
  - no network access,
  - no direct DOM manipulation,
  - just return HTML strings.
- Escape all user-controlled values with `escapeHtml` / `safe` from `html-utils.js`.
- Prefer small helper functions over large monolithic renderers.

## Testing and Verification

- Primary way to test changes:
  - run a simple static server from the repo root (for example `python -m http.server` or `npx http-server`),
  - open `index.html` in a modern browser,
  - drag-and-drop representative sample files (PE, JPEG, PNG, MP3, ZIP, etc.).
- If you add or change analyzers, verify:
  - detection label from `detectBinaryType(file)`,
  - structured output in the details pane,
  - warnings appear as non-blocking messages, not crashes.

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

