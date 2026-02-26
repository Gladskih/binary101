# Contributing to Binary101

## Setting Up Your Development Environment

### Prerequisites
- Modern browser (Chrome, Firefox, Edge)
- Node.js and npm (for linting, tests, and the TypeScript build)
- Local web server for hosting static files

### Getting Started
1. Fork the repository.
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/binary101.git
   cd binary101
   ```
3. Install dependencies:
   ```bash
   npm install
   ```
4. Build the static assets (outputs to the `dist/` directory):
   ```bash
   npm run build
   ```
5. Start a local server from `dist/`:
   ```bash
   npx http-server dist
   ```
6. Open the app in your browser at `http://localhost:8080` (or the port specified by your server).

## Code Quality Standards

All contributions must adhere to the project's code quality metrics and best practices. These are enforced by `.editorconfig` and `eslint.config.mjs`.

### JavaScript Best Practices
- Follow ESLint as the source of truth; keep `npm run lint` passing.
- **Maximum file length**: Keep modules small; if a file grows large, prefer extracting cohesive helpers/modules.
- **Maximum line length**: Aim for 100 characters where practical.
- **Maximum function length**: Aim for 20-30 lines; refactor functions over 50 lines.
- **Cyclomatic complexity**: Keep below 10; use helper functions to reduce complexity.
- **No boolean control parameters**: Do not add boolean parameters that switch execution flow (`foo(..., true/false)` + `if`). Split behavior into separate functions and share common logic via composition.
- **Nested callbacks**: Maximum 3 levels.
- **Variable declarations**: Use `const` by default, `let` only if reassignment is needed.
- **String quotes**: Use double quotes (`"`).
- **Semicolons**: Required at the end of statements.
- **Minimize empty lines**: Excessive empty lines usually indicate a function is doing too much; prefer extracting a helper.
- **Prefer expressions directly**: If a value is used once, prefer an in-place expression/early return over introducing an intermediate variable.
- **Avoid single-use constants**: Do not introduce a named `const` that is referenced only once; keep the literal inline and add a short comment explaining where it comes from.
- **Magic values**: Explain non-obvious literals with a comment (ideally citing the spec name/section or the file-format field it represents). Extract a named constant only when it is reused or substantially improves readability.
- **Console usage**: Only `console.error()` and `console.warn()` are allowed in production code.
- **Identifiers**: Minimum 2 characters (except `_`, `i`, `j`, `k`, `x`, `y`).

### Module Design and Naming

- Prefer small, cohesive modules that have a single, clearly stated responsibility (“one reason to change”). 
- Do **not** introduce new generically named modules such as `helpers`, `utils`, `extra`, `extensions`, or similar grab-bag names. If you feel tempted to add `helpers.ts`, it usually means there are at least two more meaningful modules hiding in that file.
- When you need shared logic, group it by concept or section (for example `value-format`, `flags-view`, `semantics`, `signature`) rather than by the generic idea of “helping” another module.

### Repository Conventions

- Prefer small, focused changes over large refactors.
- Keep code self-documenting:
  - use clear, descriptive names for functions, variables, and modules,
  - keep control flow straightforward; avoid clever tricks when a simple construct is enough.
- Abbreviations:
  - avoid project-specific or obscure abbreviations,
  - only use common ones that are widely understood (for example `id`, `url`, `crc`, `pe`, `mp3`).
- Keep analyzers and renderers separate:
  - analyzers are pure parsing (no DOM, no direct UI code),
  - renderers are pure HTML formatting (no file I/O).
- Maintain the UI parse contract: `parseForUi(file)` must continue to return `{ analyzer, parsed }`.

### HTML Guidelines
- Use semantic elements (`<header>`, `<nav>`, `<main>`, `<article>`, `<footer>`).
- Include `alt` attributes for images and proper `<label>` elements for form inputs.
- Ensure HTML is valid.

### CSS Guidelines
- Maximum line length: 100 characters.
- Avoid deep nesting (max 3 levels); use BEM naming convention.
- Define colors and fonts as CSS variables for consistency.
- Use mobile-first approach for responsive design.

## Code Quality and Testing

Before submitting a pull request, please ensure your code adheres to the project's standards and that all tests pass.

### Linting

To check the code for style and quality issues, run:

```sh
npm run lint
```

### Testing

The project has both unit and end-to-end tests. To run all tests, use:

```sh
npm test
```

To generate a test coverage report for the unit tests, run:

```sh
npm run test:coverage
```

We encourage contributions that improve test coverage.

#### Test Layout and Depth

- Use **one test file per production module** whenever practical. 
- For every new public function or module:
  - write tests for the “happy paths” behavior, and
  - write tests for **all known unhappy paths and edge cases**: invalid inputs, truncated data, out-of-bounds offsets, negative or extreme values, and any other failure modes that are meaningful for that unit.
- When adding tests, follow a red–green cycle: make sure each new test fails at least once for the intended reason before making it pass.

## Project Structure

- `index.html`, `style.css`: Page shell and styling (copied into `dist/` on build).
- `app.ts`: Handles UI interactions, file selection, hashing, and calls analyzers/renderers (compiled to `dist/app.js`).
- `analyzers/`: Format-specific TypeScript parsers, compiled under `dist/analyzers/`.
- `renderers/`: TypeScript renderers that turn parsed objects into HTML, compiled under `dist/renderers/`.
- `binary-utils.ts`, `html-utils.ts`: Shared helpers for hashing, byte/hex formatting and safe HTML generation.

## Adding a New Analyzer

To add support for a new binary format:

1. Create a new file in the `analyzers/` directory (e.g., `analyzers/elf/index.ts`).
2. Implement `probe` and `parse` functions:
   - `probe(file)`: Returns `true` if the file matches the format.
   - `parse(file)`: Returns a parsed object with format details.
3. Update `analyzers/index.ts` to include your new analyzer.
4. Create a renderer module (e.g. `renderers/elf/index.ts`) that converts your parsed object into HTML, update `renderers/index.ts` to export it, and update `app.ts` to call it when the analyzer matches.

### Important Patterns
- **Memory efficiency**: Use `file.slice(...).arrayBuffer()` to read file segments; avoid loading entire files.
- **Error handling**: Report anomalies visibly in the UI instead of silently failing.
- **Return types**: Parsers should return plain JavaScript objects (no DOM).

### Detection Pipeline Policy

- Current default architecture is `probe+parse`: keep detection lightweight and run full parsing in `parseForUi`.
- Existing legacy exceptions are tracked in `TODO.md`.

## Git Conventions

- **Commit messages**: Use present tense, imperative mood (e.g., "Add PE parser" not "Added PE parser").
- **Branch names**: Use lowercase with hyphens (e.g., `pe-parser`, `hash-computation`).
- **Pull requests**: Provide a clear description of your changes. Ensure ESLint passes before submitting.

## Reporting Issues

If you encounter bugs or have feature suggestions, please open an issue with:
- A clear title and description.
- Steps to reproduce (for bugs).
- Expected vs. actual behavior.

## Getting Help

- Check existing issues and pull requests to avoid duplicates.
- Ask questions in a new issue or discussion thread.
