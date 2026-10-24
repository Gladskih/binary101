import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";

export type CodeViewBoundKind = "upper" | "lowerUpper";
export type CodeViewConstantBounds = { kind: "encoded"; bytes: Uint8Array }
  | { kind: "integers"; values: string[] };
export type CodeViewDimensions =
  | { kind: "dimensionedArray"; underlyingType: number; dimensionsType: number }
  | { kind: "constantDimensions"; indexType: number; rank: number; boundKind: CodeViewBoundKind;
      bounds: CodeViewConstantBounds }
  | { kind: "variableDimensions"; indexType: number; rank: number; boundKind: CodeViewBoundKind; bounds: number[] };

// lfDimArray/lfDimCon/lfDimVar and their 16t layouts.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h
const ARRAY_LEAVES = new Set([0x11, 0x100c, 0x1508]);
const CONSTANT_LEAVES = new Set([0x208, 0x209, 0x1207, 0x1208]);
const VARIABLE_LEAVES = new Set([0x20a, 0x20b, 0x1209, 0x120a]);
const LOWER_UPPER_LEAVES = new Set([0x209, 0x1208, 0x20b, 0x120a]);

const boundKind = (leaf: number): CodeViewBoundKind => LOWER_UPPER_LEAVES.has(leaf) ? "lowerUpper" : "upper";
const indexValue = (data: DataView, offset: number, width: 2 | 4): number =>
  width === 2 ? data.getUint16(offset, true) : data.getUint32(offset, true);

const readArray = async (reader: LegacyCodeViewReader, leaf: number): Promise<CodeViewDimensions> => {
  const width = leaf < 0x1000 ? 2 : 4;
  const header = await reader.view(4, width * 2);
  return { kind: "dimensionedArray", underlyingType: indexValue(header, 0, width),
    dimensionsType: indexValue(header, width, width) };
};

const readConstant = async (reader: LegacyCodeViewReader, leaf: number): Promise<CodeViewDimensions> => {
  const width = leaf < 0x1000 ? 2 : 4;
  const header = await reader.view(4, width + 2);
  const body = await reader.view(width + 6, reader.size - width - 6);
  return { kind: "constantDimensions", indexType: indexValue(header, width === 2 ? 2 : 0, width),
    rank: header.getUint16(width === 2 ? 0 : 4, true), boundKind: boundKind(leaf),
    bounds: { kind: "encoded", bytes: new Uint8Array(body.buffer, body.byteOffset, body.byteLength).slice() } };
};

const readVariable = async (reader: LegacyCodeViewReader, leaf: number): Promise<CodeViewDimensions> => {
  const width = leaf < 0x1000 ? 2 : 4;
  const header = await reader.view(4, width * 2);
  const rank = indexValue(header, 0, width);
  const kind = boundKind(leaf);
  const declared = rank * (kind === "lowerUpper" ? 2 : 1);
  const count = Math.min(declared, Math.floor((reader.size - 4 - width * 2) / width));
  const data = await reader.view(4 + width * 2, count * width);
  if (count < declared) reader.warn("CodeView variable array dimensions have truncated bound references.");
  return { kind: "variableDimensions", indexType: indexValue(header, width, width), rank, boundKind: kind,
    bounds: Array.from({ length: count }, (_, index) => indexValue(data, index * width, width)) };
};

export const readCodeViewDimensions = async (reader: LegacyCodeViewReader,
  leaf: number): Promise<CodeViewDimensions | undefined> => {
  if (ARRAY_LEAVES.has(leaf)) return readArray(reader, leaf);
  if (CONSTANT_LEAVES.has(leaf)) return readConstant(reader, leaf);
  return VARIABLE_LEAVES.has(leaf) ? readVariable(reader, leaf) : undefined;
};
