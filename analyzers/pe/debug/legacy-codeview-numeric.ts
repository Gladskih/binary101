import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";

// Numeric leaves have a two-byte immediate or a leaf tag followed by the payload.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h
const NUMERIC_SIZES = new Map([
  [0x8000, 1], [0x8001, 2], [0x8002, 2], [0x8003, 4], [0x8004, 4],
  [0x8005, 4], [0x8006, 8], [0x8007, 10], [0x8008, 16], [0x8009, 8],
  [0x800a, 8], [0x800b, 6], [0x800c, 8], [0x800d, 16], [0x800e, 20], [0x800f, 32],
  [0x8017, 16], [0x8018, 16], [0x8019, 16], [0x801a, 8], [0x801c, 2]
]);

export const skipLegacyCodeViewNumeric = async (reader: LegacyCodeViewReader, offset: number): Promise<number> => {
  const type = await reader.uint16(offset);
  if (type < 0x8000) return offset + 2;
  if (type === 0x801b) return offset + 3 + new TextEncoder().encode(await reader.utf8(offset + 2)).length;
  const size = type === 0x8010 ? 2 + await reader.uint16(offset + 2) : NUMERIC_SIZES.get(type);
  if (size == null) throw new Error(`Unknown CodeView numeric leaf ${type}.`);
  await reader.view(offset + 2, size);
  return offset + 2 + size;
};
