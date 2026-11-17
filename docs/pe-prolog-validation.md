# AMD64 PE prolog validation

The Exception Directory includes an automatic, browser-local comparison of AMD64
machine instructions with version 1/2 `UNWIND_INFO`. It reports one row per
`.pdata` range with discrepancies, the metadata RVA, the instruction offset,
the unwind assertion and the observed state. The function RVA opens disassembly.
The table supports paging, sorting and search.

## Meaning of a result

At each supported instruction boundary in `SizeOfProlog`, a small symbolic machine
tracks the entry stack address, constants, original register values and stack
saves. The checker applies the active unwind operations to that state. A mismatch
means an asserted entry stack pointer or saved register cannot be recovered, or
that a recorded operation does not end at an instruction boundary. A home-area
store can precede the instruction whose offset describes it.

The three summary counts are mutually exclusive and count matching, discrepancies and
unverified. A discrepancy can also contain an explicit partial-check limitation.
Only registers asserted by active metadata are checked. The guarantee covers the
supported straight-line prolog path and its specific unwind assertions. Runtime
reachability and the cause of a discrepancy require separate analysis. On-disk
bytes can deliberately differ from a runtime's unwind description.

Unknown values remain unknown. Chained records, machine-frame entries, inherited
entry state, unsupported versions, unresolved stack adjustments and control-flow
changes are visible limitations. A recorded prolog ending inside an instruction
is inconclusive. The `.pdata` end is exclusive.
Decoder failures also remain unverified because newer ISA encodings can exceed
the installed decoder's coverage. Operation offsets beyond `SizeOfProlog`,
including synthetic zero-sized prologs, remain outside the supported model.
Bounded epilog lookahead avoids claiming metadata disagreement at a position where
Windows recognizes an epilog or tail transfer. Full exit validation remains a
separate analysis.

## Implementation and resource bounds

The existing unwind scan supplies decoded operations once. Code reads use the
shared file-range reader. Batches retain at most approximately 8192 operation and
description records (one record can overshoot the budget), then merge existing
owner arrays in RVA order with one cursor per description for read locality.
A batch-wide memo contains at most 4096 fully matching prolog prefixes. Partial
results depend on the function range and suffix and are never memoized.
Code lookahead is capped at 64 bytes beyond the recorded prolog and never crosses
the function range. Exhausting this budget produces an unverified result.
WASM decoder, instruction, usage and factory objects are explicitly released.

## Validation

Focused unit tests exercise malformed/truncated input, aliases, partial writes,
stack save overlap, calls, frame bases, vector saves, resource budgets and epilog
boundaries. Integration tests use a complete synthetic PE with shared unwind data
and an altered stack allocation. Browser tests cover both themes, narrow/wide
viewports, 200% zoom, paging, search and keyboard navigation to disassembly.

[Compiler and Windows reference sources](../tests/external/pe-prolog-reference/README.md)
provide controls independent of the TypeScript implementation. The Windows oracle
uses `RtlVirtualUnwind` with constructed contexts. Its general image reader maps
samples read-only with `SEC_IMAGE_NO_EXECUTE`. Synthetic context results describe
recovery from the supplied state. Reachability and intent require other evidence.
Machine-specific inventories, binaries, timings and scan evidence stay outside Git
under the ignored `scan-results/pe-prologs/` directory.

## References

- [Microsoft x64 exception handling](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64)
- [Microsoft x64 prolog and epilog](https://learn.microsoft.com/en-us/cpp/build/prolog-and-epilog)
- [MASM .SAVEREG](https://learn.microsoft.com/en-us/cpp/assembler/masm/dot-savereg)
- [CoreCLR's Windows-derived AMD64 unwinder](https://github.com/dotnet/runtime/blob/main/src/coreclr/unwinder/amd64/unwinder.cpp)
- [V8's intentionally artificial Windows unwind prologs](https://github.com/v8/v8/blob/main/src/snapshot/embedded/platform-embedded-file-writer-win.cc)

The Windows compiler and assembly controls were also compared with PPEE 2.0.0-pre.
Detailed outputs and Windows-oracle checks of additional PPEE diagnostics are
retained in the ignored artifact directory. A broad comparative false-positive-rate
measurement remains future work.
