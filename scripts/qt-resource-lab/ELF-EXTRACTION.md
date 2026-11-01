# RCC extraction using existing ELF metadata

This investigation keeps production detection unchanged. The objective is to
discover resource content without needing correct names or bundle ownership,
while separately retaining strict path/offset/bundle evaluation.

## Reproducible counterexamples

The counterexample batch produces ordinary rcc C++, links actual Qt, verifies
contents with Qt, strips a twin and validates retained bytes. No registration
stubs, array padding edits, output alignment assumptions or file-extension
filters are used. The November 1, 2026 run contains:

- 176 completed builds, 352 distinct image SHA-256, all labels verified;
- 256 positive inputs, 96 negative inputs; 59 distinct expected content SHA-256;
- 29 expanded payload sizes, from zero/one byte through 4095/4096/4097;
- 32 positive inputs retaining the unrelated payload-decoy array;
- ELF Qt 5.15.18/6.10.2 and PE Qt 5.15.19/6.11.0, GCC/Clang, O3/LTO,
  shared Qt, executable targets, before/after stripping;
- all final baseline scanner processes completed successfully.

These are correlated compiler variants and eight positive source families,
not hundreds of independent source programs. The negative-size fixture now
destroys payload bytes inside its broken qres, rather than relying on a damaged
container header as proof that no raw arrays remain valid.

## Candidate algorithm for ELF

An independent structural prototype receives only input id/path. An adapter
runs the existing full ELF parser and gives the prototype numeric ranges and
metadata occupancy. It never gives the prototype expected contents, rcc source,
symbol names, production resource results or disassembly.

1. Restrict raw table search to allocated, file-backed `SHT_PROGBITS` sections
   that are not executable, TLS or compressed. Keep writable data eligible;
   write permissions alone do not establish resource validity.
2. Subtract understood structures: decoded unwind sections, `PT_GNU_EH_FRAME`,
   sections referenced by valid decoded LSDA descriptors, and known 64-bit
   relocation slots. Do not reject resources because a payload contains `GNU`,
   `GCC: ` or a supposedly wrong file extension.
3. Recognize the Qt 5 version-tag section structurally. Check its version fields
   and that its GOT-relative target is an actual relocation site, using
   `DT_PLTGOT`; no symbol-name lookup is needed. Merely seeing `.qtversion`
   is insufficient. This is an additional research check, not an existing
   production decoder.
4. Find a whole canonical RCC tree, validate all referenced names and their
   hashes, then test data arrays against every referenced payload offset and
   length. Reject the whole candidate on invalid links or truncated content.
5. Measure a stronger local association: names/data must be adjacent except
   for zero padding. No fixed distance or alignment threshold is used. This
   condition supplies more evidence than independently picking unrelated
   compatible byte ranges; it is not known to be a universal RCC invariant.
6. Deduplicate by expanded SHA-256 for content discovery. Keep physical offsets,
   candidate ownership and empty-content ambiguity separately visible in metrics.

The metadata sources are already available from the ELF parse. Qt 5 tag layout
is documented in [qversiontagging.h](https://github.com/qt/qtbase/blob/v5.15.2/src/corelib/global/qversiontagging.h).
Itanium exception data is reached through decoded FDE/LSDA pointers, not a
blind section-name blacklist.

## Measurements and limits

On 176 ELF inputs (128 positive and 48 negative):

| Method | Expected physical content found | Extra unique contents, summed per input |
|---|---:|---:|
| Structural search inside known metadata boundaries | 992/992 | 48 |
| Also require names/data adjacency with zero padding | 992/992 | 24 |

The second row has **944/944 nonempty physical content instances and zero extra
nonempty contents**. Its 24 extra contents are empty byte strings: 16 one-byte
cases and eight one-byte-plus-decoy cases also admit zero-length data records.
The 48 negative ELF inputs produce no candidates. A zero observed count is not
proof of zero FP; all policies were examined on this corpus, so these numbers
are exploratory rather than an untouched holdout estimate.

The positive `payload-decoy` controls demonstrate why subtracting metadata is
not a complete answer: unrelated read-only application data can have the same
length-prefix shape as RCC. The adjacency condition rejects its nonempty decoy
on this particular matrix, but could reject a true set if a linker separates
the arrays. Earlier closest-table selection already missed real bundles.

Zero-length records expose the remaining missing information. Four zero bytes
in ordinary data and an intentional empty RCC file have the same byte encoding.
Knowing the tree and names does not supply the data-table base address. Existing
metadata cannot automatically assign exclusive semantic ownership to all
ordinary program bytes.

Consequently this is a useful candidate path for ELF, not a complete precision
guarantee. A conservative production implementation would need to preserve
ambiguous results as unconfirmed, use stronger linkage evidence when present,
and keep the existing confirmed qres/symbol routes. Dropping empty files,
requiring 4-byte alignment or blacklisting compiler-looking text would make
the counterexample tests fail rather than solve the ambiguity.

The experiment also does not cover arbitrary noncanonical layouts, other
architectures, sectionless ELF or Qt built with LTO. Raw table discovery alone
must not be advertised as a universal replacement for all evidence sources.

## Saved evidence

Output directory (outside Git):
`C:/Users/glads/source/worktree-artifacts/qt-rcc-counterexamples-20261101`.

It contains SDK fingerprints and commands, immutable job manifests, Qt oracle
responses, image/retained-control hashes, baseline JSONL, content evaluation,
`integrity-current.json`, and research sources/results in `research/`:

- `elf-knowledge.mts`: full-parser range adapter;
- `structural_scan.py`, `image_regions.py`: blind candidate search;
- `elf-experiment.py`: independent scoring;
- `elf-adjacency.py`: the measured association policy;
- `elf-summary.json`, `adjacency-summary.json`, per-input predictions/evaluation.

The input SHA-256 inventory is checked against every published file, and every
completed job must match the current generator recipe before it can resume or
enter the exported corpus. Binaries, maps and results remain outside Git.
