import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";

// IBM HLL "Name Length Formats" and Symbol Scope Table general format:
// bit 7 selects a second byte, with the first byte supplying the high 7 bits.
// https://www.os2site.com/sw/dev/openwatcom/docs/ibmhll.htm
export const readHllLength = async (reader: LegacyCodeViewReader, offset: number) => {
  const first = (await reader.view(offset, 1)).getUint8(0);
  if (!(first & 0x80)) return { size: first, end: offset + 1 };
  return { size: ((first & 0x7f) << 8) | (await reader.view(offset + 1, 1)).getUint8(0), end: offset + 2 };
};

export const readHllName = async (reader: LegacyCodeViewReader, offset: number) => {
  const length = await readHllLength(reader, offset);
  return { name: await reader.ansiBytes(length.end, length.size), end: length.end + length.size };
};
