# Contributing to Binary101

## Setting Up Your Development Environment

### Prerequisites
- Modern browser (Chrome, Firefox, Edge)
- Local web server for hosting static files

### Getting Started
1. Fork the repository.
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/binary101.git
   cd binary101
   ```
3. Start a local server:
   - Using Python:
     ```bash
     python -m http.server
     ```
   - Using Node.js:
     ```bash
     npx http-server .
     ```
   - Using VS Code: Install the "Live Server" extension and open `index.html`.
4. Open the app in your browser at `http://localhost:8080` (or the port specified by your server).

## Code Quality Standards

All contributions must adhere to the project's code quality metrics and best practices. These are enforced by `.editorconfig` and `.eslintrc.json`.

### JavaScript Best Practices
- **Maximum file length**: 250 lines (including comments and blank lines).
- **Maximum line length**: 100 characters.
- **Maximum function length**: Aim for 20–30 lines; refactor functions over 50 lines.
- **Cyclomatic complexity**: Keep below 10; use helper functions to reduce complexity.
- **Nested callbacks**: Maximum 3 levels.
- **Variable declarations**: Use `const` by default, `let` only if reassignment is needed.
- **Equality**: Always use `===` and `!==`.
- **String quotes**: Use double quotes (`"`).
- **Semicolons**: Required at the end of statements.
- **Console usage**: Only `console.error()` and `console.warn()` are allowed in production code.
- **Magic numbers**: Define named constants instead of using literal numbers.
- **Identifiers**: Minimum 2 characters (except `_`, `i`, `j`, `k`, `x`, `y`).

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

## Project Structure

- `index.html`, `style.css`: Page shell and styling.
- `app.js`: Handles UI interactions, file selection, hashing, and calls analyzers/renderers.
- `analyzers/`: Format-specific parsers. PE/COFF logic is split across small modules under `analyzers/pe/` (e.g. `core.js`, `imports.js`, `exports.js`, `resources-*.js`, `tls.js`, `clr-security.js`, `reloc.js`, etc.).
- `renderers/`: Renderers that turn parsed objects into HTML. PE views live in `renderers/pe/` and are split into `headers.js`, `directories.js`, `resources.js`, `layout.js`, composed by `renderers/pe/index.js`.
- `binary-utils.js`, `html-utils.js`, `hash.js`: Shared helpers for hashing, byte/hex formatting and safe HTML generation.

## Adding a New Analyzer

To add support for a new binary format:

1. Create a new file in the `analyzers/` directory (e.g., `analyzers/elf.js`).
2. Implement `probe` and `parse` functions:
   - `probe(file)`: Returns `true` if the file matches the format.
   - `parse(file)`: Returns a parsed object with format details.
3. Update `analyzers/index.js` to include your new analyzer.
4. Create a renderer module (e.g. `elf-render.js`) that converts your parsed object into HTML, and update `app.js` to call it when the analyzer matches.

### Important Patterns
- **Memory efficiency**: Use `file.slice(...).arrayBuffer()` to read file segments; avoid loading entire files.
- **Error handling**: Report anomalies visibly in the UI instead of silently failing.
- **Return types**: Parsers should return plain JavaScript objects (no DOM).

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