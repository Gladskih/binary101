# TODO

Current status notes:

- PE Authenticode support currently parses certificates and can verify the embedded file digest, but it does not build a full trust chain or enforce a trust policy yet.

## P0 - Architecture, Detection Breadth, Performance

- Remove detection pipeline debt: migrate legacy `detectBinaryType` paths that still call full `parse*` to lightweight `probe*` + one full parse in `parseForUi`.
- Introduce a single format registry that defines, per format: probe, human label builder, parser, renderer, preview support, and nested-analysis support.
- Concrete plan for the routing refactor: first introduce typed `FormatDescriptor` entries plus factory entrypoints like `createParseForUi(registry)` and `createDetectBinaryType(registry)` without changing public behavior; then migrate `parseForUi` to registry-driven routing; then migrate `detectBinaryType` and label enrichment to the same registry so probe order and format guards live in one place; finally split tests so routing logic is covered by registry-level unit/component tests and keep only a small set of real seam cases in broader integration/e2e coverage.
- Make "unknown binary type" rare for files larger than 1 KiB: expand cheap magic/container/text probes until unidentified files are exceptions rather than the norm.
- Add an "unknown sample triage" workflow: keep a local corpus of unidentified real-world files, classify them, and turn them into probes/tests.
- Audit analyzers for unnecessary `file.arrayBuffer()` reads and switch to bounded `file.slice(...).arrayBuffer()` reads where possible.
- Reduce startup bundle size with code-splitting/lazy-loading for heavy analyzers and renderers.
- Add performance budgets for large local files so detection stays cheap and deep parsing remains opt-in or progressive where needed.

## P1 - Flagship Analyzers

- Extend PE educational field explanations.
- Upgrade PE Authenticode from digest checking to full offline signature validation: CMS/PKCS#7 sanity checks, signer/certificate chain building, time validity, EKU/purpose checks, and explicit trust verdicts.
- Add an optional built-in CA trust bundle/profile for offline Authenticode validation, with clear UI that distinguishes cryptographic validity from trust policy.
- Continue deepening ELF: more relocation/linking/debug metadata, better explanation of loader behavior, and more complete security/sanity analysis.
- Deepen Mach-O load-command coverage: replace more "listed only" commands with command-specific parsing and explanations where the format is well-specified.
- Extend Mach-O loader/linkedit analysis: exports trie, chained fixups, relocations, and richer dyld binding/rebasing semantics.
- Expand Mach-O code-signing analysis beyond blob metadata: parse more embedded payloads and separate structural validity from trust/policy where practical.

## P2 - Depth For Supported Formats

- Deepen PDF beyond the current surface pass: xref streams, object streams, incremental updates, encryption dictionaries, page tree, embedded files, and stream-level structure.
- Add nested object labeling inside containers and archives so users can immediately see likely inner file types.
- Add "analyze embedded file" actions for archive entries and other nested objects, not just "download/extract".
- Support recursive navigation across nested structures where this is safe and understandable: archive entry -> inner document -> inner media/resource.
- Add better format-specific warnings for malformed, suspicious, or polyglot files.

## P2 - Product UX, Education, Mobile

- Redesign the UI; the current layout is serviceable but weak as an educational tool and poor on phones.
- Make tables readable on mobile: preserve horizontal scrolling where needed, but also add responsive views for dense data instead of crushing columns into unreadable slivers.
- Fix visual hierarchy problems: section spacing, heading grouping, labels vs values, and clearer summaries before detail dumps.
- Push the educational goal harder: every important field should have an explanation of what it is, why it exists, and when it matters.
- Add stronger links between bytes and meaning: offsets, sizes, raw values, decoded values, and spec-oriented hints should be easy to connect.
- Improve the summary-first experience so users see the important facts, warnings, and interpretations before long tables.
- Expand test coverage for `app.ts` and UI orchestration paths such as paste, drag/drop, preview fallback, hashing, and action buttons.

## P3 - Workspace And Persistence

- Add multi-file workflows with explicit switching, likely as tabs or a file workspace.
- Design nested-analysis and multi-file navigation together so embedded-file inspection does not become confusing.
- Add optional easy to wipe local persistence for workspace state and UI preferences.

## P3 - Visualizations

- Add audio visualizations for supported audio files: e.g. waterfall spectrogram.
- Add image visualizations where they teach something useful: histograms, channel views, palette/entropy summaries, and other structure-aware views.

## P3 - Quality And Validation

- Raise branch coverage.
- Increase mutation score.
- Add more external fixture corpora and differential tests for flagship analyzers and tricky formats.
