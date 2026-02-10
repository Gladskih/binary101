<!-- Copilot instructions for the binary101 project -->

# Repo Overview

This is a small client-side static web app for inspecting binary files (PE/COFF, images, audio, archives, etc.).
It runs entirely in the browser via ES modules. Source is written in TypeScript and compiled to JavaScript into the `dist/` folder; there is no server-side code.

Key entry points
- `index.html` - page shell that imports `app.js` from `dist/` as an ES module.
- `app.ts` - main UI wiring (drag/drop, paste, file input, hash buttons), compiled to `dist/app.js`.
- `analyzers/` - binary format detection and parsers:
  - orchestration in `analyzers/index.ts`,
  - PE in `analyzers/pe/`,
  - MP3 in `analyzers/mp3/`,
  - plus JPEG, GIF, PNG, PDF, WebP, ZIP, ELF, FB2, etc.
- `renderers/` - HTML renderers for parsed objects:
  - central export in `renderers/index.ts`,
  - PE view in `renderers/pe/index.ts`,
  - MP3 view in `renderers/mp3/index.ts`,
  - plus renderers for JPEG, GIF, PNG, PDF, WebP, ZIP, ELF, FB2.
- `binary-utils.ts`, `html-utils.ts` - shared helpers (human-readable sizes, hex, HTML escaping, Web Crypto wrapper).

# Architecture & Data Flow

- Browser-only app: user selects or pastes a `File`; `app.ts` calls `detectBinaryType(file)` and `parseForUi(file)` from `analyzers/index.ts`.
- `analyzers/index.ts` performs lightweight magic probes on a small prefix and delegates to format-specific parsers (PE, JPEG, PNG, MP3, etc.).
- Parsers operate on `file.slice(...).arrayBuffer()` and return plain JS objects (no DOM access).
  Renderers in `renderers/*` consume parser output and return HTML strings that `app.ts` inserts into the page.
- Hashing uses `crypto.subtle.digest` (called from `app.ts`); keep operations asynchronous and avoid re-reading whole files when possible.

Project-specific conventions and patterns
- ES modules with relative paths (for example `import { formatHumanSize } from "./binary-utils.js"` or `import { safe } from "./html-utils.js"`).
  Keep exports small and named.
- Parsers avoid loading entire files; they read small slices (`file.slice(off, off + len).arrayBuffer()`) and return serializable objects.
  Follow this pattern when adding new analyzers.
- UI rendering is string-based HTML in `renderers/*` (no JSX/templating).
  Renderers are pure functions from `{ analyzer, parsed }` to an HTML string.

# How to Extend the Repo

Adding a new analyzer
- Create `analyzers/<format>/index.ts` that exposes probe/parse functions accepting a `File` or `DataView`.
- Update `analyzers/index.ts`:
  - wire your probe into detection (either via `probeByMagic`, a dedicated function, or both),
  - update `parseForUi(file)` to return `{ analyzer: "<name>", parsed }` when your format is detected.
- Parsers should:
  - take care not to read beyond file bounds,
  - avoid loading the entire file into memory,
  - return plain JSON-serializable structures (no methods, no DOM nodes).

Adding a new renderer or UI section
- Add `renderers/<format>/index.ts` exporting a function like `renderFoo(parsed)` that returns an HTML string.
- Update `renderers/index.ts` to export your renderer.
- Update `app.ts` (or the relevant dispatch logic) so that when `parseForUi(file)` returns `{ analyzer: "<format>" }`, the correct renderer is called and the result is injected into the page.
- Reuse `safe(value)` and `escapeHtml` from `html-utils.ts` for all user-visible strings.

# Developer Workflows

- Build step: run `npm run build` to compile TypeScript sources into the `dist/` folder, then open `dist/index.html` in a modern browser.
- Recommended local server (serving files from `dist/`):
  - Node: `npx http-server dist`.
- Debugging:
  - use the browser DevTools Sources panel; modules are unbundled and mapped by filename,
  - add `debugger` statements in `app.ts`, `analyzers/*` or `renderers/*` where needed.

# Important Notes for AI Assistants (including Copilot)

- Target modern browsers only: the code uses `BigInt`, `DataView.getBigUint64`, `crypto.subtle`, `File`/`Blob` APIs and ES module imports.
  Avoid changes that would require transpilation or a bundler unless you also add and document the build setup.
- Parsers assume `file.slice(...).arrayBuffer()` calls; keep I/O patterns non-blocking and slice-based for memory efficiency.
- The UI expects `parseForUi(file)` to return `{ analyzer, parsed }` (see `analyzers/index.ts`).
  If you change that contract, update `app.ts` and any renderers that depend on it.
- Prefer extending analyzer/renderer modules over adding ad-hoc logic inside `app.ts`.
- Follow the lint rules defined in `eslint.config.mjs` and keep the codebase passing `npm run lint`.

# Examples from the Codebase

- Type detection and parsing:
  - `const { analyzer, parsed } = await parseForUi(file);`
  - `renderAnalysisIntoUi(analyzer, parsed);` (in `app.ts`).
- Rendering PE: `renderPe(pe)` in `renderers/pe/index.ts` shows how to break a complex view into smaller helpers.
- Rendering MP3: `renderMp3(mp3)` in `renderers/mp3/index.ts` shows how to stitch together summary, technical details, and warnings.
- Adding a new import-style renderer: reuse `safe(value)` from `html-utils.ts` to escape HTML, and follow the table/list patterns already used in `renderers/*`.

Files you will likely edit
- `app.ts` - glue code (update event handlers, status messages, integration calls here).
- `analyzers/index.ts` - format detection and dispatch to specific analyzers.
- `analyzers/pe/index.ts` - the largest parser; good reference for slice-based reading and complex binary structures.
- `analyzers/mp3/*` - example of a robust, warning-rich analyzer with multiple related files.
- `renderers/pe/index.ts` - UI generation for PE objects (examples of how parser output is presented).
- `renderers/mp3/index.ts` - UI generation for MP3 analysis.

If anything is missing or unclear
- Tell me which area you would like expanded (analysis patterns, adding a new analyzer, testing strategy, or run/debug commands) and I will update this file.

# Project Inspiration and Vision

This project draws inspiration from tools like [regex101](https://regex101.com/), the Linux `file` utility, VirusTotal, and browser-based IDEs.
The goal is to analyze files locally, without uploading them anywhere, ensuring privacy and security.
This makes it suitable for analyzing sensitive files, whether for work or personal use.

## Core Objectives

1. **File type detection** - support a wide variety of file signatures (executables, images, archives, audio, documents).
2. **Deep inspection where it matters** - high-value formats (PE, MP3, PNG, PDF, ZIP, ELF, etc.) get dedicated analyzers and rich views.
3. **Safety and privacy** - all parsing happens in the browser; no network calls for analysis.
4. **Usability** - clean, readable HTML output; sensible defaults; warnings instead of crashes for malformed files.

# Coding Guidelines

These mostly mirror the project's ESLint configuration and are here so assistants can stay in style.
When these guidelines conflict with ESLint, follow ESLint.

### JavaScript / TypeScript

- **Variable declarations**: use `const` by default; `let` only if reassignment is needed; never `var`.
- **Strings**: use double quotes (`"`); escape when necessary.
- **Semicolons**: required at the end of statements.
- **Brace style**: use 1TBS (`if (...) { ... }` on one line).
- **Minimize empty lines**: excessive empty lines usually indicate a function is doing too much; prefer extracting a helper.
- **Prefer expressions directly**: if a value is used once, prefer an in-place expression/early return over introducing an intermediate variable.
- **Avoid single-use constants**: do not introduce a named `const` that is referenced only once; keep the literal inline and add a short comment explaining where it comes from.
- **Magic values**: explain non-obvious literals with a comment (ideally citing the spec name/section or the file-format field it represents). Extract a named constant only when it is reused or substantially improves readability.
- **Unused variables**: not allowed (prefix with `_` if intentionally unused).
- **Console usage**: only `console.error()` and `console.warn()` in production code; remove `console.log()` from commits.
- **Side effects**:
  - analyzers should not touch the DOM,
  - renderers should not perform I/O or parsing.

### Async and Performance

- **Async operations**: functions doing I/O should return `Promise`; avoid callback-style APIs.
- **File I/O**: use `file.slice(...).arrayBuffer()` for memory efficiency; never load entire files unnecessarily.
- **Blocking work**: keep heavy computations chunked or behind `await` to avoid freezing the UI. Consider Web Workers if you need heavier processing in future changes.

### HTML

- Prefer semantic HTML (`<header>`, `<nav>`, `<main>`, `<article>`, `<footer>`) over generic `<div>`.
- Respect accessibility basics:
  - `alt` attributes for images,
  - proper `<label>` elements for form inputs,
  - ARIA attributes where appropriate.
- Keep HTML valid; you can use the W3C validator when in doubt.

### CSS

- Line length: aim for a maximum of about 100 characters.
- Selectors: avoid deep nesting (maximum 3 levels); prefer BEM-style naming for clarity.
- Colors and fonts: define as CSS variables where possible for consistency.
- Performance: minimize inline styles; keep CSS small and focused.

### Git

- Commit messages: use present tense, imperative mood (for example "Add MP3 analyzer", not "Added MP3 analyzer").
- Branch names: lowercase with hyphens (for example `pe-parser`, `mp3-analyzer`).
- Pull requests: prefer small, focused changes; ensure ESLint passes.

### Tools and Configuration

- **ESLint** (`eslint.config.mjs`) - uses the modern flat config and ESLint 9.
  Run `npm run lint` (or `npx eslint .`) from the repo root.
- **EditorConfig** (`.editorconfig`) - keeps indentation, line endings, and charset consistent.
- Pre-commit hooks (optional) - you can wire Husky + lint-staged if you want automatic checks before commits.

End of instructions.

