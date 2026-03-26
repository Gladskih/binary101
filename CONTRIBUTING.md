# Code Quality Standards

- Follow ESLint as the source of truth; keep `npm run lint` passing
- **Maximum file length**: Keep modules small; if a file grows large, prefer extracting cohesive modules
- **Maximum line length**: Aim for 100 characters where practical
- **Maximum function length**: Aim for 20-30 lines; refactor functions over 50 lines
- **Cyclomatic complexity**: Keep below 10
- **No boolean control parameters**: Do not add boolean parameters that switch execution flow (`foo(..., true/false)` + `if`). Split behavior into separate functions and share common logic via composition.
- **No derived fields in returned results**: Prefer a single source of truth in parsed objects. Do not return multiple representations of the same data.
- **No argument-bag types**: Do not introduce a named `*Args`/`*Opts` type whose only purpose is to bundle positional parameters into an object. Prefer explicit parameters, or use an options object only when it models a real configuration surface.
- **No repeated expensive work within the same parse**: Don't rescan/redecode/rehash the same bytes multiple times while processing one file. Compute once and reuse when the result is used more than once.
- **Variable declarations**: Use `const` by default, `let` only if reassignment is needed.
- **String quotes**: Use double quotes (`"`).
- **No empty lines in a function except AAA test structure**: Excessive empty lines usually indicate a function is doing too much.
- **No single-use constants**: Do not introduce a named `const` that is referenced only once.
- **Prefer expressions directly**: If a value is used once, prefer an in-place expression/early return over introducing an intermediate variable.
- **Magic values**: Explain non-obvious literals with a comment, cites the authoritative source used (spec section, RFC section, or upstream source/header URL).
- **Console usage**: Only `console.error()` and `console.warn()` are allowed in production code.
- **Identifiers**: Minimum 2 characters (except `_`, `i`, `j`, `k`, `x`, `y`).
- Prefer small, cohesive modules that have a single, clearly stated responsibility (“one reason to change”). 
- Do **not** introduce new generically named modules such as `helpers`, `utils`, `extra`, `extensions`, or similar grab-bag names. If you feel tempted to add `helpers.ts`, it usually means there are at least two more meaningful modules hiding in that file.
- When you need shared logic, group it by concept rather than by the generic idea of “helping” another module.
- Prefer immutable over mutable
- Prefer stateless over stateful
- Prefer explicit over implicit
- Prefer declarative over imperative
- Prefer types over conventions
- If mutation is required for performance reasons, isolate it locally and document why (profiling).
- Keep code self-documenting:
  - use descriptive names
  - keep control flow straightforward;
- Abbreviations:
  - avoid project-specific or obscure abbreviations,
  - only use common ones that are widely understood
- Keep analyzers and renderers separate:
  - analyzers are pure parsing (no DOM, no direct UI code)
  - renderers are pure HTML formatting (no file I/O)
- Maintain the UI parse contract: `parseForUi(file)` must continue to return `{ analyzer, parsed }`.
- **Memory efficiency**: Use `file.slice(...).arrayBuffer()` to read file segments; avoid loading entire files.
- **Error handling**: Report anomalies visibly in the UI instead of silently failing or bypassing.
- **Return types**: Parsers should return plain JavaScript objects (no DOM).
- Current default architecture is `probe+parse`: keep detection lightweight and run full parsing in `parseForUi`.
- Existing legacy exceptions are tracked in `TODO.md`.
- **Commit messages**: Use present tense, imperative mood

## HTML
- Use semantic elements (`<header>`, `<nav>`, `<main>`, `<article>`, `<footer>`).
- Include `alt` attributes for images and proper `<label>` elements for form inputs.
- Ensure HTML is valid.

## CSS
- Maximum line length: 100 characters.
- Avoid deep nesting (max 3 levels); use BEM naming convention.
- Define colors and fonts as CSS variables for consistency.
- Use mobile-first approach for responsive design.

## Tests

- Before submitting a pull request, ensure your code adheres to the project's standards and that all tests pass.
- Run the coverage report before and after your change; coverage must not go down.
- Use **one test file per production module** whenever practical. 
- For every new public function or module:
  - write tests for the “happy paths” behavior, and
  - write tests for **all known unhappy paths and edge cases**: invalid inputs, truncated data, out-of-bounds offsets, negative or extreme values, and any other failure modes that are meaningful for that unit.
- When adding tests, follow a red–green cycle: make sure each new test fails at least once for the intended reason before making it pass.
- Keep individual tests flat: avoid branching and non-trivial control flow in the test body; if setup needs logic, move it into a small, domain-specific fixture builder so the test itself stays easy to scan.
- use mutation testing to evaluate test quality
- Do not scatter arbitrary literals through tests when the specific value is not important.
- If a value is significant, add a short comment that explains why the exact literal matters and cite the authoritative source when relevant.
- If a value is incidental, generate it by fixture builders.
- Do not use neighboring production constants as the oracle in a unit test; encode the checked value in the test itself and comment any special literal.
