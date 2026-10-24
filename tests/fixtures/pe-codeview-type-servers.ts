import { legacyU16, legacyU32, legacyPascal, createLegacyCodeView } from "./pe-legacy-codeview.js";
import { codeViewTextRecord, codeViewUtf8 } from "./pe-codeview-type-strings.js";
import { createPeWithDebugPayloads } from "./pe-debug-file.js";

/** lfTypeServer2 GUID, plus both ST and UTF-8 forms of lfTypeServer. */
export const createPeWithCodeViewTypeServers = () => createPeWithDebugPayloads([{ type: 2,
  data: createLegacyCodeView([{ type: 0x121, module: 1, data: Uint8Array.from([
    ...legacyU32(4),
    ...codeViewTextRecord(0x1515, 4, [...legacyU32(0x12345678), ...legacyU16(0x9abc), ...legacyU16(0xdef0),
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, ...legacyU32(3), ...codeViewUtf8("<types>&amp;.pdb")]),
    ...codeViewTextRecord(0x16, 4, [...legacyU32(0x87654321), ...legacyU32(7), ...legacyPascal("old.pdb")]),
    ...codeViewTextRecord(0x1501, 4, [...legacyU32(0x12345678), ...legacyU32(1), ...codeViewUtf8("utf8.pdb")])
  ]) }]) }]);
