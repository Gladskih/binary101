# Go runtime metadata support

The Go runtime analyzer is format-independent. It accepts an abstract mapped address space and
requires a format adapter to locate `pcHeader` and `moduledata`. The current PE adapter scans
readable, initialized, non-executable mapped sections for `pcHeader` magic values and then scans
writable mapped data for the preferred-VA pointer to that header.

Detection is deliberately strict. A magic match is only a candidate. The analyzer returns a result
only after it cross-validates the `pcHeader`, `moduledata` prefix, all six relevant slice descriptors,
table offsets and alignment, file and compilation-unit tables, `pclntable`, `functab`, `_func`
records, names, `findfunctab`, `minpc`/`maxpc`, `text`/`etext`, and executable ranges. Any
incomplete, ambiguous, truncated, or inconsistent candidate returns `null` and produces no Go UI.

## Supported layouts

| Reported layout | pcHeader magic | functab entries | Official source |
|---|---:|---|---|
| Go 1.16–1.17 | `0xfffffffa` | pointer-sized absolute PCs and offsets | [Go 1.16 runtime](https://github.com/golang/go/blob/go1.16.15/src/runtime/symtab.go) |
| Go 1.18–1.19 | `0xfffffff0` | 32-bit offsets relative to `moduledata.text` | [Go 1.18 runtime](https://github.com/golang/go/blob/go1.18.10/src/runtime/symtab.go) |
| Go 1.20+ | `0xfffffff1` | 32-bit offsets relative to `moduledata.text` | [Go 1.20 runtime](https://github.com/golang/go/blob/go1.20.14/src/runtime/symtab.go), [current Go 1.26 runtime](https://github.com/golang/go/blob/go1.26.4/src/runtime/symtab.go) |

The `go1.20+` label is intentionally a layout family, not an inferred compiler version: the magic
does not distinguish individual releases in that family. The analyzer does not claim support for
the older Go 1.2 layout (`0xfffffffb`).
