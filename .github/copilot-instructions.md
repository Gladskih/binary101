<!-- Copilot instructions for the binary101 project -->

# Repo Overview

This is a small client-side static web app for inspecting binary files (PE/COFF, images, audio, archives, etc.).  
It runs entirely in the browser via ES modules – there is no build step or server-side code in this repo.

Key entry points
- `index.html` – page shell that imports `app.js` as an ES module.
- `app.js` – main UI wiring (drag/drop, paste, file input, hash buttons).
- `analyzers/` – binary format detection + parsers:
  - orchestration in `analyzers/index.js`,
  - PE in `analyzers/pe/`,
  - MP3 in `analyzers/mp3/`,
  - plus JPEG, GIF, PNG, PDF, WebP, ZIP, ELF, FB2, etc.
- `renderers/` – HTML renderers for parsed objects:
  - central export in `renderers/index.js`,
  - PE view in `renderers/pe/index.js`,
  - MP3 view in `renderers/mp3/index.js`,
  - plus renderers for JPEG, GIF, PNG, PDF, WebP, ZIP, ELF, FB2.
- `binary-utils.js`, `html-utils.js`, `hash.js` – shared helpers (human-readable sizes, hex, HTML escaping, Web Crypto wrapper).

# Architecture & Data Flow

- Browser-only app: user selects or pastes a `File`; `app.js` calls `detectBinaryType(file)` and `parseForUi(file)` from `analyzers/index.js`.
- `analyzers/index.js` performs lightweight magic probes on a small prefix and delegates to format-specific parsers (PE, JPEG, PNG, MP3, etc.).
- Parsers operate on `File.slice(...).arrayBuffer()` and return plain JS objects (no DOM access).  
  Renderers in `renderers/*` consume parser output and return HTML strings that `app.js` inserts into the page.
- Hashing uses `crypto.subtle.digest` in `hash.js` (called from `app.js`); keep operations asynchronous and avoid re-reading whole files when possible.

Project-specific conventions and patterns
- ES modules with relative paths (for example `import { formatHumanSize } from "./binary-utils.js"` or `import { safe } from "./html-utils.js"`).  
  Keep exports small and named.
- Parsers avoid loading entire files; they read small slices (`file.slice(off, off + len).arrayBuffer()`) and return serializable objects.  
  Follow this pattern when adding new analyzers.
- UI rendering is string-based HTML in `renderers/*` (no JSX/templating).  
  Renderers are pure functions from `{ analyzer, parsed }` to HTML string.

# How to Extend the Repo

Adding a new analyzer
- Create `analyzers/<format>/index.js` that exposes probe/parse functions accepting a `File` or `DataView`.
- Update `analyzers/index.js`:
  - wire your probe into detection (either via `probeByMagic`, a dedicated function, or both),
  - update `parseForUi(file)` to return `{ analyzer: "<name>", parsed }` when your format is detected.
- Parsers should:
  - take care not to read beyond file bounds,
  - avoid loading the entire file into memory,
  - return plain JSON-serializable structures (no methods, no DOM nodes).

Adding a new renderer / UI section
- Add `renderers/<format>/index.js` exporting a function like `renderFoo(parsed)` that returns an HTML string.
- Update `renderers/index.js` to export your renderer.
- Update `app.js` (or the relevant dispatch logic) so that when `parseForUi(file)` returns `{ analyzer: "<format>" }`, the correct renderer is called and the result is injected into the page.
- Reuse `safe(value)` / `escapeHtml` from `html-utils.js` for all user-visible strings.

# Developer Workflows

- No build step. To run locally open `index.html` in a modern browser.
- Recommended local server (serving files from repo root):
  - Python: `python -m http.server` (run from repository root),
  - Node: `npx http-server` (run from repository root),
  - or VS Code: use the “Live Server” extension to serve `index.html`.
- Debugging:
  - use the browser DevTools Sources panel – modules are unbundled and mapped by filename,
  - add `debugger` statements in `app.js`, `analyzers/*` or `renderers/*` where needed.

# Important Notes for AI Assistants (including Copilot)

- Target modern browsers only: the code uses `BigInt`, `DataView.getBigUint64`, `crypto.subtle`, `File`/`Blob` APIs and ES module imports.  
  Avoid changes that would require transpilation or a bundler unless you also add and document the build setup.
- Parsers assume `file.slice(...).arrayBuffer()` calls; keep I/O patterns non-blocking and slice-based for memory efficiency.
- The UI expects `parseForUi(file)` to return `{ analyzer, parsed }` (see `analyzers/index.js`).  
  If you change that contract, update `app.js` and any renderers that depend on it.
- Prefer extending analyzers/renderer modules over adding ad-hoc logic inside `app.js`.
- Follow the lint rules defined in `eslint.config.mjs` and keep the codebase passing `npm run lint`.

# Examples from the Codebase

- Hashing: `await computeHashForFile(currentFile, "SHA-256")` – put expensive operations behind async functions and update UI state while running (see `computeAndDisplayHash` in `app.js`).
- Type detection and parsing:
  - `const { analyzer, parsed } = await parseForUi(file);`
  - `renderAnalysisIntoUi(analyzer, parsed);` (in `app.js`).
- Rendering PE: `renderPe(pe)` in `renderers/pe/index.js` shows how to break a complex view into smaller helpers.
- Rendering MP3: `renderMp3(mp3)` in `renderers/mp3/index.js` shows how to stitch together summary, technical details, and warnings.
- Adding a new import-style renderer: reuse `safe(value)` from `html-utils.js` to escape HTML, and follow the table/list patterns already used in `renderers/*`.

Files you will likely edit
- `app.js` – glue code (update event handlers, status messages, integration calls here).
- `analyzers/index.js` – format detection and dispatch to specific analyzers.
- `analyzers/pe/index.js` – the largest parser; good reference for slice-based reading and complex binary structures.
- `analyzers/mp3/*` – example of a robust, warning-rich analyzer with multiple related files.
- `renderers/pe/index.js` – UI generation for PE objects (examples of how parser output is presented).
- `renderers/mp3/index.js` – UI generation for MP3 analysis.

If anything is missing or unclear
- Tell me which area you would like expanded (analysis patterns, adding a new analyzer, testing strategy, or run/debug commands) and I will update this file.

# Project Inspiration and Vision

This project draws inspiration from tools like [regex101](https://regex101.com/), the Linux `file` utility, VirusTotal, and browser-based IDEs.  
The goal is to analyze files locally, without uploading them anywhere, ensuring privacy and security.  
This makes it suitable for analyzing sensitive files, whether for work or personal use.

## Core Objectives

1. **File type detection** – support a wide variety of file signatures (executables, images, archives, audio, documents).
2. **Deep inspection where it matters** – high-value formats (PE, MP3, PNG, PDF, ZIP, ELF, etc.) get dedicated analyzers and rich views.
3. **Safety and privacy** – all parsing happens in the browser; no network calls for analysis.
4. **Usability** – clean, readable HTML output; sensible defaults; warnings instead of crashes for malformed files.

# Coding Guidelines

These mirror the project’s ESLint configuration and are here so Copilot can stay in-style.

### JavaScript

- **Variable declarations**: use `const` by default; `let` if reassignment is needed; never `var`.
- **Equality checks**: always use `===` and `!==` (strict equality).
- **Strings**: use double quotes (`"`); escape when necessary.
- **Semicolons**: required at the end of statements.
- **Brace style**: use 1TBS (`if (...) { ... }` on one line).
- **Magic numbers**: avoid where possible; prefer named constants.
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

- Commit messages: use present tense, imperative mood (for example “Add MP3 analyzer”, not “Added MP3 analyzer”).
- Branch names: lowercase with hyphens (for example `pe-parser`, `mp3-analyzer`).
- Pull requests: prefer small, focused changes; ensure ESLint passes.

### Tools and Configuration

- **ESLint** (`eslint.config.mjs`) – uses the modern flat config and ESLint 9.  
  Run `npm run lint` (or `npx eslint .`) from the repo root.
- **EditorConfig** (`.editorconfig`) – keeps indentation, line endings, and charset consistent.
- Pre-commit hooks (optional) – you can wire Husky + lint-staged if you want automatic checks before commits.

End of instructions.

