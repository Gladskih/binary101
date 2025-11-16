<!-- Copilot instructions for the binary101 project -->
# Repo Overview

This is a small client-side static web app for inspecting binary files (primarily PE/COFF). It runs entirely in the browser via ES modules — there is no build step or server-side code in this repo.

Key entry points
- `index.html` — page shell that imports `app.js` as an ES module.
- `app.js` — main UI wiring (drag/drop, paste, file input, hash buttons).
- `analyzers/` — binary format detection + parsers (PE parser lives in `analyzers/pe.js`).
- `pe-render.js` — turns parsed PE objects into HTML snippets for the UI.
- `utils.js`, `hash.js` — shared helpers (human-readable sizes, hex, Web Crypto wrapper).

Big-picture architecture & data flow
- Browser-only app: user selects or pastes a `File` → `app.js` calls `detectBinaryType(file)` and `parseForUi(file)` from `analyzers/index.js`.
- `analyzers/index.js` performs lightweight magic probes then delegates to format-specific parsers (currently PE via `analyzers/pe.js`).
- Parsers operate on `File.slice(...).arrayBuffer()` and return plain JS objects (no DOM). `pe-render.js` consumes parser output and returns HTML strings that `app.js` inserts into the page.
- Hashing uses `crypto.subtle.digest` in `hash.js` (called from `app.js`) — keep operations asynchronous and avoid re-reading whole files when possible.

Project-specific conventions and patterns
- ES modules with relative paths (e.g. `import { foo } from "./utils.js"`). Keep exports named and small.
- Parsers avoid loading entire files; they read small slices (`file.slice(off, off+len).arrayBuffer()`) and return serializable objects. Follow this pattern when adding new analyzers.
- UI rendering is string-based HTML in `pe-render.js` (not JSX/templating).

How to extend the repo (typical tasks)
- Add a new analyzer: create `analyzers/<format>.js` that exposes probe/parse functions that accept a `File` or `DataView`; update `analyzers/index.js` to call your probe and return `{ analyzer: '<name>', parsed }` from `parseForUi`.
- Add a new UI section: return a plain object from the parser and update `pe-render.js` (or create a new renderer) to produce safe HTML strings.

Developer workflows (what actually works locally)
- No build step. To run locally open `index.html` in a modern browser.
- Recommended local server (serving files from repo root):
  - Python: `python -m http.server` (run from repository root)
  - Node: `npx http-server` (run from repository root)
  - or VS Code: Use the Live Server extension to serve `index.html`.
- Debugging: use the browser DevTools Sources panel — modules are unbundled and mappable by filename. Add `debugger` statements in `app.js` or `analyzers/pe.js` where needed.

Important compatibility notes for the AI agent
- Target modern browsers only — code uses `BigInt`, `DataView.getBigUint64`, `crypto.subtle`, `File`/`Blob` APIs and ES module imports. Avoid changes that would require transpilation unless you also add a bundler/config.
- Parsers assume `file.slice(...).arrayBuffer()` calls; keep I/O patterns non-blocking and slice-based for memory efficiency.
- The UI expects `parseForUi(file)` to return `{ analyzer, parsed }` (see `analyzers/index.js`). If you change that contract, update `app.js` accordingly.

Examples from codebase (use these as patterns)
- Hashing: `await computeHashForFile(currentFile, "SHA-256")` — put expensive operations behind async functions and update UI state while running (see `computeAndDisplayHash` in `app.js`).
- Type detection + parsing: `const { analyzer, parsed } = await parseForUi(file); renderAnalysisIntoUi(analyzer, parsed);` (in `app.js`).
- Adding a new import renderer: `pe-render.js` uses `safe(value)` from `utils.js` to escape HTML. Reuse `safe` for all user-facing strings.

Files you will likely edit
- `analyzers/pe.js` — the largest parser. Read it to learn RVA→file-offset mapping and slice-based reading.
- `pe-render.js` — UI generation for PE objects (examples of how parser output is presented).
- `app.js` — glue code (update event handlers, status messages, and integration calls here).

If anything is missing or unclear
- Tell me which area you'd like expanded (analysis patterns, adding new analyzer, testing strategy, or run/debug commands) and I will update this file.

# Project Inspiration and Vision

This project draws inspiration from tools like [regex101](https://regex101.com/), the Linux `file` utility, VirusTotal, and even browser-based IDEs. The goal is to create a website that analyzes files locally, without uploading them anywhere, ensuring privacy and security. This makes it suitable for analyzing sensitive files, whether for work or personal use.

## Core Objectives

1. **File Type Detection**: Expand the number of supported file signatures to identify a wide variety of file types. This is the "low-hanging fruit" and the first step in the project's development.
2. **File Format Parsing**: Provide detailed insights into file structures, explaining the purpose of each byte or field. The goal is not just to display the structure but to educate users by explaining:
   - Why a field exists
   - What values it can take
   - What those values mean
   - Common values and their significance

3. **Executable File Analysis**: Focus on executable formats like PE/COFF and ELF, starting with PE. These formats are of particular interest and will guide the project's structure and evolution.

## Development Philosophy

- **Self-Documenting Code**: Write code that is clear and expressive without requiring excessive comments.
- **Avoid Abbreviations**: Use full, descriptive names for identifiers, except for widely accepted abbreviations.
- **Keep It Manageable**: Ensure identifiers, strings, functions, classes, files, and folders remain concise and focused.
- **Best Practices**: Follow best practices in design, architecture, programming, and code style.
- **Minimize Empty Lines**: Excessive empty lines often indicate the need for refactoring (e.g., extracting a new function).
- **Comment Where Necessary**:
  - Explain literals and "magic values" (e.g., why a specific value is used).
  - Document workarounds and non-obvious solutions.
- **Modern JavaScript**:
  - Prefer `const` over `let`, and `let` over `var`.
  - Use expressions directly where possible, avoiding intermediate variables.

By adhering to these principles, the project aims to balance flexibility, rich UI/UX, and ease of future expansion.

# Additional Guidelines for Robustness and Testing

## Robustness in Parsing and Error Handling

- **Adhere to Standards**: Always rely on official documentation, specifications, standards, GitHub issues, and even source code when available. Avoid relying solely on prior knowledge or guessing.
- **Handle Edge Cases**: Anticipate and handle situations where file formats are violated or used in unexpected ways:
  - Pointers leading outside the file.
  - Invalid or undefined values in documentation.
  - Unusual element orders, identifiers, or oversized fields.
- **Error Reporting**: Do not suppress or ignore such anomalies. Instead, visibly report them to the user in the UI.
- **Avoid Silent Failures**: Avoid swallowing exceptions or converting them into boolean return values. Use proper error handling mechanisms to ensure issues are logged and surfaced appropriately.

## Automated Testing

- **Unit Testing**: Introduce unit tests for JavaScript functions, especially for parsers and utilities. Use a framework like [Jest](https://jestjs.io/) or [Mocha](https://mochajs.org/).
- **Integration Testing**: Test the entire flow from file input to UI rendering. Use tools like [Puppeteer](https://pptr.dev/) or [Playwright](https://playwright.dev/) for browser automation.
- **Error Scenarios**: Include tests for edge cases and invalid files to ensure robustness.
- **Test Coverage**: Aim for high test coverage, particularly for critical parsing logic.

## Debugging and MCP Integration

- **Chrome DevTools MCP**: Use Chrome DevTools MCP for debugging and automation. This can help simulate user interactions and validate UI behavior.
- **Additional Tools**: If MCP lacks functionality, consider integrating other tools or libraries. Communicate specific needs to the project maintainer for evaluation.

— End of instructions —
