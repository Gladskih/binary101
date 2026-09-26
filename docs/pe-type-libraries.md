# PE type libraries

Embedded `TYPELIB` resources are parsed once during resource analysis. Resources shows a summary
and a link; **Type libraries (COM)** displays the contracts in a separate lazy section. Every
resource ID/name and language remains distinct, including malformed and MUI placeholder entries.

The parser is based on Wine's [binary layouts](https://github.com/wine-mirror/wine/blob/master/dlls/oleaut32/typelib.h)
and [MSFT/SLTG reader](https://github.com/wine-mirror/wine/blob/master/dlls/oleaut32/typelib.c).
In particular, MSFT function control masks follow `MSFT_DoFuncs`, rather than the reversed bit
numbering in the `MSFT_FuncRecord` header comment.

MSFT analysis follows the segment directory into names, strings, GUIDs, imported libraries and
types, type bases, member blocks, implemented-interface chains, type descriptors, array bounds,
constant/default variants and custom-data chains. It resolves local and imported type references
in displayed signatures. Library/type/member help contexts and optional DLL entries are retained.

SLTG analysis follows the block chain, variable-length library/type metadata, name table, type
headers/tails, linked functions/variables/interfaces, imported references, type expressions and
compressed help strings. The help decoder uses the prefix tree and MSB-first stream described by
Wine's `lookup_code` and `decode_string`.

All byte ranges are bounded to their resource, segment, member block or SLTG block. Cycles,
truncated data and invalid references produce visible warnings while preserving recoverable
records. Traversal is bounded by actual record ranges, validated counts, visited offsets and
input/output progress. There are no artificial ceilings on record count, type nesting or array
rank. MSFT descriptors use an iterative traversal, so deeply nested valid types do not exhaust
the JavaScript call stack. Array dimensions must fit their segment/block; compressed help must
fit its declared output length and input bitstream. Decoded tables, descriptor nodes, member
blocks, values, custom data and help streams/tree words are reused within a parse.
Every distinct diagnostic is retained; repeated messages are deduplicated.

TYPELIB ANSI text does not declare the original machine's ANSI codepage. The decoder infers one
from LCID, with Windows-1252 as fallback; the UI states this uncertainty. External libraries are
described from embedded import records and are never loaded or fetched. Stored variant types
without a verified portable representation (including pointer-valued variants and DECIMAL) remain
undecoded with a warning. SLTG encoded member help-context values are not interpreted, since Wine
does not resolve them either; the UI displays an unavailable value. Undocumented flag bits remain
visible as hexadecimal values rather than receiving invented meanings.

Validation includes synthetic binary fixtures, malformed offsets/lengths and chains, mutation
testing of the bounds/descriptor/value/help parsers, and browser navigation/remount tests. Manual
local checks include Windows `stdole2.tlb`, `stdole32.tlb`, `scrrun.dll` and `msxml6.dll`; proprietary
bytes are not included in the test suite.
