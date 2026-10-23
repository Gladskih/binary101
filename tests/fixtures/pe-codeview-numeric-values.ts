import { legacyU16, legacyU32, createLegacyCodeView } from "./pe-legacy-codeview.js";
import { codeViewField, codeViewFieldList } from "./pe-codeview-fields.js";
import { createPeWithDebugPayloads } from "./pe-debug-file.js";
import { codeViewTextRecord } from "./pe-codeview-type-strings.js";

// Microsoft cvinfo.h numeric leaves store integers in little-endian byte order.
export const codeViewInteger = (leaf: number, value: bigint, width: number): number[] => [
  ...legacyU16(leaf), ...Array.from({ length: width }, (_, index) =>
    Number(BigInt.asUintN(width * 8, value) >> BigInt(index * 8) & 255n))
];

export const createPeWithCodeViewMemberValues = () => createPeWithDebugPayloads([{ type: 2,
  data: createLegacyCodeView([{ type: 0x121, module: 1, data: Uint8Array.from([
    ...legacyU32(4), ...codeViewFieldList([
      ...codeViewField(0x1502, [...legacyU16(3), ...codeViewInteger(0x800a, (1n << 64n) - 1n, 8)], "largest"),
      ...codeViewField(0x1502, [...legacyU16(3), ...codeViewInteger(0x800a, (1n << 64n) - 2n, 8)], "previous"),
      ...codeViewField(0x150d, [...legacyU16(1), ...legacyU32(0x74), ...legacyU16(12)], "<count>&amp;"),
      ...codeViewField(0x150d, [...legacyU16(3), ...legacyU32(0x1001), ...legacyU16(16)], "mode")
    ], 0x1203),
    ...codeViewTextRecord(0x1205, 4, [...legacyU32(0x75), 3, 1])
  ]) }])
}]);
