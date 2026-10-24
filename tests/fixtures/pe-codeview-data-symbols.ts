import { legacyU16, legacyU32 } from "./pe-legacy-codeview.js";

const NARROW_DATA_SYMBOLS = new Set([0x0201, 0x0202, 0x0203]);
const TYPED_DATA_SYMBOLS = new Set([0x1007, 0x1008, 0x110c, 0x110d]);
const PUBLIC_SYMBOLS = new Set([0x1009, 0x110e]);
const BLOCK_SYMBOLS = new Set([0x0207, 0x1103]);
const LABEL_SYMBOLS = new Set([0x0209, 0x1105]);

/** Build bounded C7 data, public, block, and label records from cvinfo.h layouts. */
export const codeViewDataSymbol = (type: number, name: readonly number[], publicFlags = 0xd5,
  typeIndex = 0x12345678, offset = 0x1234, segment = 9): number[] => {
  let fields: number[];
  if (NARROW_DATA_SYMBOLS.has(type)) {
    fields = [...legacyU32(offset), ...legacyU16(segment), ...legacyU16(typeIndex)];
  } else if (TYPED_DATA_SYMBOLS.has(type)) {
    fields = [...legacyU32(typeIndex), ...legacyU32(offset), ...legacyU16(segment)];
  } else if (PUBLIC_SYMBOLS.has(type)) {
    fields = [...legacyU32(publicFlags), ...legacyU32(offset), ...legacyU16(segment)];
  } else if (BLOCK_SYMBOLS.has(type)) {
    fields = [...legacyU32(16), ...legacyU32(32), ...legacyU32(160),
      ...legacyU32(offset), ...legacyU16(segment)];
  } else if (LABEL_SYMBOLS.has(type)) {
    fields = [...legacyU32(offset), ...legacyU16(segment), 0xd5];
  } else {
    throw new Error(`Unsupported C7 data symbol fixture kind ${type}.`);
  }
  const body = [...legacyU16(type), ...fields, ...name];
  return [...legacyU16(body.length), ...body];
};
