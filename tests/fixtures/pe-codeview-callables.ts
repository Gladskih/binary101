import { legacyU16, legacyU32, createLegacyCodeView } from "./pe-legacy-codeview.js";
import { codeViewTextRecord, codeViewUtf8 } from "./pe-codeview-type-strings.js";
import { createPeWithDebugPayloads } from "./pe-debug-file.js";
import type { LegacyCodeViewTypeRecord } from "../../analyzers/pe/debug/legacy-codeview-type-records.js";
import type { PeLegacyCodeViewInfo } from "../../analyzers/pe/debug/legacy-codeview.js";

export const codeViewInfoWithTypes = (records: LegacyCodeViewTypeRecord[]): PeLegacyCodeViewInfo => ({
  signature: "NB09", directories: [{ flags: 0, subsections: [{ type: 0x121, module: 1,
    offset: 0, size: 0, data: { kind: "types", records } }] }]
});

// Packed lfProc/lfMFunc/lfArgList layouts, including record length and leaf.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h
export const codeViewProcedure = (leaf = 0x1008): number[] => leaf === 8
  ? codeViewTextRecord(leaf, 4, [...legacyU16(0x74), 7, 1, ...legacyU16(2), ...legacyU16(0x1000)])
  : codeViewTextRecord(leaf, 4, [...legacyU32(0x74), 7, 1, ...legacyU16(2), ...legacyU32(0x1000)]);

export const codeViewMemberFunction = (leaf = 0x1009): number[] => {
  const index = leaf === 9 ? legacyU16 : legacyU32;
  return codeViewTextRecord(leaf, 4, [...index(0x74), ...index(0x1002), ...index(0x1003),
    11, 2, ...legacyU16(2), ...index(0x1000), ...legacyU32(-8)]);
};

export const codeViewArguments = (indices: readonly number[] = [0x74, 0x41], leaf = 0x1201): number[] => {
  const index = leaf === 0x201 ? legacyU16 : legacyU32;
  return codeViewTextRecord(leaf, 4, [...index(indices.length), ...indices.flatMap(index)]);
};

export const codeViewCallableStream = (): Uint8Array => Uint8Array.from([
  ...legacyU32(4), ...codeViewArguments(), ...codeViewProcedure(),
  ...codeViewTextRecord(0x1601, 4, [...legacyU32(0), ...legacyU32(0x1001), ...codeViewUtf8("<convert>")])
]);

export const createPeWithCodeViewCallables = () => createPeWithDebugPayloads([{ type: 2,
  data: createLegacyCodeView([{ type: 0x121, module: 1, data: codeViewCallableStream() }]) }]);
