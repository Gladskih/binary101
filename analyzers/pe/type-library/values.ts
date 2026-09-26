import type { TypeLibraryCustomData, TypeLibraryValue } from "./types.js";
import type { TypeLibraryReader } from "./reader.js";

// Wine MSFT_ReadValue / MSFT_CustData: inline variants, or a VARTYPE + payload.
// https://github.com/wine-mirror/wine/blob/master/dlls/oleaut32/typelib.c
const readStringValue = (reader: TypeLibraryReader, offset: number): string | null => {
  const start = reader.at("CustData", offset + 2, 4);
  if (start === null) return null;
  const length = reader.view.getInt32(start, true);
  if (length === -1) return null;
  const bytes = reader.at("CustData", offset + 6, length);
  return bytes === null ? null : reader.text(bytes, length);
};

const readNumericValue = (
  reader: TypeLibraryReader, offset: number, type: number
): string | number | null => {
  const start = reader.at("CustData", offset + 2, [5, 6, 7, 20, 21, 64].includes(type) ? 8 : 4);
  if (start === null) return null;
  if (!(type in NUMERIC_READERS)) {
    reader.warn(`TYPELIB variant VARTYPE ${type} is unsupported; its value is not decoded.`);
    return null;
  }
  return NUMERIC_READERS[type]!(reader.view, start);
};

const readInt32 = (view: DataView, offset: number): number => view.getInt32(offset, true);
const readUint32 = (view: DataView, offset: number): number => view.getUint32(offset, true);
const readFloat64 = (view: DataView, offset: number): number => view.getFloat64(offset, true);
const readUint64 = (view: DataView, offset: number): string => String(view.getBigUint64(offset, true));
const NUMERIC_READERS: Record<number, (view: DataView, offset: number) => string | number | null> = {
  0: () => null, 1: () => null, 24: () => null,
  2: (view, offset) => view.getInt16(offset, true),
  3: readInt32, 10: readInt32, 22: readInt32, 25: readInt32,
  4: (view, offset) => view.getFloat32(offset, true),
  5: readFloat64, 7: readFloat64,
  6: (view, offset) => `${view.getBigInt64(offset, true)} / 10000`,
  11: (view, offset) => view.getInt16(offset, true) === 0 ? "false" : "true",
  16: (view, offset) => view.getInt8(offset), 17: (view, offset) => view.getUint8(offset),
  18: (view, offset) => view.getUint16(offset, true),
  19: readUint32, 23: readUint32,
  20: (view, offset) => String(view.getBigInt64(offset, true)),
  21: readUint64, 64: readUint64
};

export const readValue = (reader: TypeLibraryReader, offset: number): TypeLibraryValue | null => {
  if (offset < 0) return readPackedValue(offset);
  if (reader.values.has(offset)) return reader.values.get(offset) ?? null;
  const start = reader.at("CustData", offset, 2);
  if (start === null) return null;
  const type = reader.view.getUint16(start, true);
  const result = { type, value: type === 8
    ? readStringValue(reader, offset) : readNumericValue(reader, offset, type) };
  reader.values.set(offset, result);
  return result;
};

const readPackedValue = (offset: number): TypeLibraryValue => {
  // Wine WMSFT_encode_variant packs small integers and BOOL; interpret their VARTYPE,
  // including sign extension for I1/I2, rather than displaying the unsigned storage bits.
  const type = (offset >>> 26) & 31;
  const value = offset & 0x3ffffff;
  switch (type) {
    case 16: return { type, value: (value << 24) >> 24 };
    case 2: return { type, value: (value << 16) >> 16 };
    case 11: return { type, value: value === 0 ? "false" : "true" };
    default: return { type, value };
  }
};

export const readCustomData = (
  reader: TypeLibraryReader, first: number
): TypeLibraryCustomData[] => {
  const cached = reader.customData.get(first);
  if (cached) return cached;
  const result: TypeLibraryCustomData[] = [];
  const seen = new Set<number>();
  for (let offset = first; offset !== -1;) {
    if (seen.has(offset)) {
      reader.warn("TYPELIB custom data chain contains a cycle.");
      break;
    }
    seen.add(offset);
    const start = reader.at("CDGuids", offset, 12);
    if (start === null) break;
    result.push({
      guid: reader.lookup(reader.guids, reader.view.getInt32(start, true), "GUID"),
      value: readValue(reader, reader.view.getInt32(start + 4, true))
    });
    offset = reader.view.getInt32(start + 8, true);
  }
  reader.customData.set(first, result);
  return result;
};
