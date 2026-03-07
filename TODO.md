# TODO

Current status notes:

- Mach-O now has a deep analyzer/renderer for thin and FAT binaries; remaining work is about deeper loader/linkedit and code-signing semantics.
- PCAP-NG is detected/labeled today, but only classic PCAP has a deep analyzer/renderer.
- PE Authenticode support currently parses certificates and can verify the embedded file digest, but it does not build a full trust chain or enforce a trust policy yet.

## P0 - Architecture, Detection Breadth, Performance

- [ ] Remove detection pipeline debt: migrate legacy `detectBinaryType` paths that still call full `parse*` to lightweight `probe*` + one full parse in `parseForUi`.
- [ ] Introduce a single format registry that defines, per format: probe, human label builder, parser, renderer, preview support, and nested-analysis support.
- [ ] Make "unknown binary type" rare for files larger than 1 KiB: expand cheap magic/container/text probes until unidentified files are exceptions rather than the norm.
- [ ] Add an "unknown sample triage" workflow: keep a local corpus of unidentified real-world files, classify them, and turn them into probes/tests.
- [ ] Audit analyzers for unnecessary `file.arrayBuffer()` reads and switch to bounded `file.slice(...).arrayBuffer()` reads where possible.
- [ ] Reduce startup bundle size with code-splitting/lazy-loading for heavy analyzers and renderers.
- [ ] Add performance budgets for large local files so detection stays cheap and deep parsing remains opt-in or progressive where needed.

## P1 - Flagship Analyzers

- [ ] Continue treating PE as the flagship analyzer and push it toward "best in class" local inspection.
- [ ] Extend PE coverage where gaps remain: more directories, richer loader/security semantics, stronger resource decoding, and more educational field explanations.
- [ ] Upgrade PE Authenticode from digest checking to full offline signature validation: CMS/PKCS#7 sanity checks, signer/certificate chain building, time validity, EKU/purpose checks, and explicit trust verdicts.
- [ ] Add an optional built-in CA trust bundle/profile for offline Authenticode validation, with clear UI that distinguishes cryptographic validity from trust policy.
- [ ] Continue deepening ELF: more relocation/linking/debug metadata, better explanation of loader behavior, and more complete security/sanity analysis.
- [ ] Deepen Mach-O load-command coverage: replace more "listed only" commands with command-specific parsing and explanations where the format is well-specified.
- [ ] Extend Mach-O loader/linkedit analysis: exports trie, chained fixups, relocations, and richer dyld binding/rebasing semantics.
- [ ] Expand Mach-O code-signing analysis beyond blob metadata: parse more embedded payloads and separate structural validity from trust/policy where practical.
- [ ] Add a real PCAP-NG analyzer and renderer instead of detection-only labeling.

## P2 - Depth For Supported Formats

- [ ] Deepen PDF beyond the current surface pass: xref streams, object streams, incremental updates, encryption dictionaries, page tree, embedded files, and stream-level structure.
- [ ] Strengthen existing media/container analyzers instead of only adding new formats: MP4, WebM/Matroska, ASF, ZIP, RAR, 7z, TAR, ISO-9660, SQLite, and others should keep gaining depth.
- [ ] Add nested object labeling inside containers and archives so users can immediately see likely inner file types.
- [ ] Add "analyze embedded file" actions for archive entries and other nested objects, not just "download/extract".
- [ ] Support recursive navigation across nested structures where this is safe and understandable: archive entry -> inner document -> inner media/resource.
- [ ] Add better format-specific warnings for malformed, suspicious, or polyglot files.

## P2 - Product UX, Education, Mobile

- [ ] Redesign the UI; the current layout is serviceable but weak as an educational tool and poor on phones.
- [ ] Make tables readable on mobile: preserve horizontal scrolling where needed, but also add responsive views for dense data instead of crushing columns into unreadable slivers.
- [ ] Fix visual hierarchy problems: section spacing, heading grouping, labels vs values, and clearer summaries before detail dumps.
- [ ] Push the educational goal harder: every important field should have an explanation of what it is, why it exists, and when it matters.
- [ ] Add stronger links between bytes and meaning: offsets, sizes, raw values, decoded values, and spec-oriented hints should be easy to connect.
- [ ] Improve the summary-first experience so users see the important facts, warnings, and interpretations before long tables.
- [ ] Expand test coverage for `app.ts` and UI orchestration paths such as paste, drag/drop, preview fallback, hashing, and action buttons.

## P3 - Workspace And Persistence

- [ ] Add multi-file workflows with explicit switching, likely as tabs or a file workspace, instead of the current single-file-only model.
- [ ] Design nested-analysis and multi-file navigation together so embedded-file inspection does not become confusing.
- [ ] Add optional local persistence for workspace state and UI preferences.
- [ ] Do not store raw file bytes in `localStorage` by default.
- [ ] If persistence is added, prefer opt-in behavior and store only low-risk state by default: selected tab, open sections, analyzer settings, and maybe derived metadata.
- [ ] If richer persistence is added later, make it explicit, reversible, and easy to wipe.

## P3 - Visualizations

- [ ] Add audio visualizations for supported audio files: waveform, spectrum, and waterfall spectrogram.
- [ ] Add image visualizations where they teach something useful: histograms, channel views, palette/entropy summaries, and other structure-aware views.
- [ ] Add format-aware visual summaries where they help interpretation instead of just looking impressive.

## P3 - Quality And Validation

- [ ] Raise branch coverage in weak spots, especially UI glue and uncommon unhappy paths.
- [ ] Add more external fixture corpora and differential tests for flagship analyzers and tricky formats.
- [ ] Add parser stress tests for malformed/truncated inputs and keep favoring warnings over crashes.
