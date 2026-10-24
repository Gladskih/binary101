import { legacyU16, legacyU32, createLegacyCodeView } from "./pe-legacy-codeview.js";
import { codeViewTextRecord, codeViewUtf8 } from "./pe-codeview-type-strings.js";
import { createPeWithDebugPayloads } from "./pe-debug-file.js";

export const codeViewFixedInteger = (value: bigint, width: number): number[] => {
  const encoded = BigInt.asUintN(width * 8, value);
  return Array.from({ length: width }, (_, index) => Number(encoded >> BigInt(index * 8) & 255n));
};

/** lfDimCon_16t and lfDimCon swap the index-type and rank fields. */
export const codeViewConstantDimensions = (leaf: number, indexType: number, rank: number,
  bytes: readonly number[]): number[] => codeViewTextRecord(leaf, 4, [
  ...(leaf < 0x1000 ? [...legacyU16(rank), ...legacyU16(indexType)]
    : [...legacyU32(indexType), ...legacyU16(rank)]), ...bytes
]);

export const codeViewVariableDimensions = (leaf: number, indexType: number, rank: number,
  indices: readonly number[]): number[] => {
  const index = leaf < 0x1000 ? legacyU16 : legacyU32;
  return codeViewTextRecord(leaf, 4, [...index(rank), ...index(indexType), ...indices.flatMap(index)]);
};

export const createPeWithCodeViewDimensions = () => createPeWithDebugPayloads([{ type: 2,
  data: createLegacyCodeView([{ type: 0x121, module: 1, data: Uint8Array.from([
    ...legacyU32(4),
    ...codeViewConstantDimensions(0x209, 0x74, 2, [-1n, 3n, 2n, 5n].flatMap(value => codeViewFixedInteger(value, 4))),
    ...codeViewTextRecord(0x1508, 4, [...legacyU32(0x74), ...legacyU32(0x1000), ...codeViewUtf8("<Grid>&amp;")]),
    ...codeViewTextRecord(0x20c, 4, codeViewTextRecord(0x1107, 4,
      [...legacyU32(0x74), ...legacyU16(7), ...codeViewUtf8("<limit>&amp;")])),
    ...codeViewVariableDimensions(0x120a, 0x74, 1, [3, 0x1002]),
    ...codeViewTextRecord(0x1508, 4, [...legacyU32(0x74), ...legacyU32(0x1003), ...codeViewUtf8("Dynamic")]),
    ...codeViewConstantDimensions(0x1207, 0x77, 1, codeViewFixedInteger((1n << 64n) - 1n, 8))
  ]) }]) }]);
