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

## Core Testing Principles

Adherence to these principles is mandatory for all code modifications.

1.  **All Tests Must Pass:** Before committing, ensure that 100% of the test suite passes. No change that breaks an existing test will be accepted.
2.  **New Functionality Requires New Tests:** Every new feature, function, or analyzer must be accompanied by corresponding unit tests that validate its behavior.
3.  **Refactoring Must Preserve Tests:** When refactoring existing code without changing its external behavior (i.e., within its established contract), the existing tests for that code must not be changed. They serve as a guarantee that the refactoring was successful.
4.  **Coverage Must Not Decrease:** Test coverage is a critical quality metric. Before starting work, measure the current test coverage. After your changes and any new tests are complete, measure it again. The new coverage percentage must be greater than or equal to the original percentage.
5.  **Test the Tests (Red-Green-Refactor):** A test that has never failed cannot be trusted. When writing a new test, you must first see it fail. You can do this by running the test against the code before the feature is implemented, or by temporarily introducing a bug to ensure the test catches it. This "Red-Green" cycle ensures the test is genuinely validating the code's correctness.

## Testing and Verification

This project has both automated tests and relies on manual verification.

### Automated Testing

Before committing any changes, run the full test suite to ensure you haven't introduced any regressions.

-   **Run all tests (unit and e2e):**
    ```sh
    npm test
    ```
-   **Generate a coverage report:**
    ```sh
    npm run test:coverage
    ```

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

