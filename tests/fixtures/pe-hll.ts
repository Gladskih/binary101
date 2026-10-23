import { legacyU16, legacyU32, legacyPascal } from "./pe-legacy-codeview.js";
import { createPeWithDebugPayloads } from "./pe-debug-file.js";

export const hllLength = (size: number): number[] => size < 128 ? [size] : [0x80 | size >>> 8, size & 255];
export const hllName = (name: string): number[] => [...hllLength(name.length), ...new TextEncoder().encode(name)];
export const hllSymbol = (type: number, body: readonly number[] = []): number[] =>
  [...hllLength(body.length + 1), type, ...body];
export const hllType = (type: number, qualifier: number, body: readonly number[] = []): number[] =>
  [...legacyU16(body.length + 2), type, qualifier, ...body];
export const hllModule = (style = "HL", version = 0x400, name = "hll.obj"): Uint8Array => Uint8Array.from([
  ...legacyU16(1), ...legacyU32(16), ...legacyU32(32), ...legacyU16(0), ...legacyU16(1), ...legacyU16(1),
  ...new TextEncoder().encode(style), ...legacyU16(version), ...legacyPascal(name)
]);

export const createHll = (entries = [
  { type: 0x101, module: 1, data: hllModule() },
  { type: 0x106, module: 0xffff, data: Uint8Array.from([...legacyPascal(""), ...legacyPascal("hll.lib")]) },
  { type: 0x104, module: 1, data: Uint8Array.from(hllSymbol(4, [...legacyU32(4), ...legacyU16(512),
    ...legacyPascal("<variable>")])) },
  { type: 0x103, module: 1, data: Uint8Array.from(hllType(0x5d, 0, [131, ...legacyU16(512),
    130, ...legacyPascal("<Alias>")])) }
]): Uint8Array => {
  const directoryOffset = 8 + entries.reduce((size, entry) => size + entry.data.length, 0);
  const bytes = new Uint8Array(directoryOffset + 8 + entries.length * 12 + 8);
  bytes.set([78, 66, 48, 52, ...legacyU32(directoryOffset)]);
  bytes.set([...legacyU16(8), ...legacyU16(12), ...legacyU32(entries.length)], directoryOffset);
  let offset = 8;
  entries.forEach((entry, index) => {
    bytes.set([...legacyU16(entry.type), ...legacyU16(entry.module), ...legacyU32(offset),
      ...legacyU32(entry.data.length)], directoryOffset + 8 + index * 12);
    bytes.set(entry.data, offset);
    offset += entry.data.length;
  });
  bytes.set([78, 66, 48, 52, ...legacyU32(bytes.length)], bytes.length - 8);
  return bytes;
};

export const createPeWithHll = () => createPeWithDebugPayloads([{ type: 2, data: createHll() }]);

export const createHllInspection = (): Uint8Array => {
  const fileNames = [...legacyU32(0), ...legacyU32(0), ...legacyU32(1), ...legacyPascal("<source.c>")];
  return createHll([
    { type: 0x101, module: 1, data: hllModule() },
    { type: 0x104, module: 1, data: Uint8Array.from(Array.from({ length: 101 }, (_, index) =>
      hllSymbol(4, [...legacyU32(index), ...legacyU16(512), ...legacyPascal(`<variable_${index}>`)])).flat()) },
    { type: 0x103, module: 1, data: Uint8Array.from([
      ...hllType(0x5d, 0, [131, ...legacyU16(512), 130, ...legacyPascal("<Alias>")]),
      ...hllType(0x7f, 2, [130, ...legacyPascal("<field>"), 133, 0, 0]),
      ...hllType(0x59, 0, [139, 3, 65, 43, 66])
    ]) },
    { type: 0x10b, module: 1, data: Uint8Array.from([
      0, 0, 3, 0, 0, 0, 0, 0, ...legacyU32(fileNames.length), ...fileNames,
      0, 0, 0, 0, ...legacyU16(2), ...legacyU16(1), ...legacyU32(0),
      ...legacyU16(7), ...legacyU16(1), ...legacyU32(16), ...legacyU16(7), ...legacyU16(1), ...legacyU32(24)
    ]) }
  ]);
};
