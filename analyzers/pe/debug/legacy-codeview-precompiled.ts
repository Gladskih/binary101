import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";

export type CodeViewPrecompiledType =
  | { kind: "precompiled"; start: number; count: number; signature: number }
  | { kind: "endPrecompiled"; signature: number };

// lfPreComp[_16t] and lfEndPreComp, including the record length and leaf.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h
export const readCodeViewPrecompiledType = async (reader: LegacyCodeViewReader,
  leaf: number): Promise<CodeViewPrecompiledType | undefined> => {
  if (leaf === 0x14) return { kind: "endPrecompiled", signature: await reader.uint32(4) };
  if (leaf !== 0x13 && leaf !== 0x100e && leaf !== 0x1509) return undefined;
  const width = leaf === 0x13 ? 2 : 4;
  const header = await reader.view(4, width * 2 + 4);
  return { kind: "precompiled",
    start: width === 2 ? header.getUint16(0, true) : header.getUint32(0, true),
    count: width === 2 ? header.getUint16(width, true) : header.getUint32(width, true),
    signature: header.getUint32(width * 2, true) };
};
