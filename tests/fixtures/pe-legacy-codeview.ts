import { LegacyCodeViewReader } from "../../analyzers/pe/debug/legacy-codeview-reader.js";

export const legacyU16 = (value: number): number[] => [value & 255, value >>> 8 & 255];
export const legacyU32 = (value: number): number[] => [...legacyU16(value), ...legacyU16(value >>> 16)];
export const legacyPascal = (name: string): number[] => [name.length, ...new TextEncoder().encode(name)];
export const legacyReader = (data: ArrayLike<number>, warnings: string[] = []): LegacyCodeViewReader => {
  const bytes = Uint8Array.from(data);
  return new LegacyCodeViewReader(bytes.length, async (offset, size) =>
    new DataView(bytes.slice(offset, offset + size).buffer), warning => warnings.push(warning));
};

export const legacyModule = (name = "module.obj"): Uint8Array => Uint8Array.from([
  ...legacyU16(0), ...legacyU16(1), ...legacyU16(1), 67, 86,
  ...legacyU16(2), 0, 0, ...legacyU32(16), ...legacyU32(8), ...legacyPascal(name)
]);

export const legacySymbol = (type = 0x203, name = "public_name", offset = 12): number[] => {
  const text = type >= 0x1100 ? [...new TextEncoder().encode(name), 0] : legacyPascal(name);
  const bytes = new Uint8Array(offset + text.length);
  bytes.set(legacyU16(bytes.length - 2));
  bytes.set(legacyU16(type), 2);
  bytes.set(text, offset);
  return [...bytes];
};

export const legacySource = (): Uint8Array => Uint8Array.from([
  ...legacyU16(1), ...legacyU16(1), ...legacyU32(20), ...legacyU32(16), ...legacyU32(24), ...legacyU16(2), 0, 0,
  ...legacyU16(1), 0, 0, ...legacyU32(48), ...legacyU32(16), ...legacyU32(24), ...legacyPascal("source.c"), 0, 0, 0,
  ...legacyU16(2), ...legacyU16(2), ...legacyU32(16), ...legacyU32(24), ...legacyU16(7), ...legacyU16(9)
]);

export const createLegacyCodeView = (
  entries: readonly { type: number; module: number; data: Uint8Array }[] = [
    { type: 0x120, module: 1, data: legacyModule() },
    { type: 0x128, module: 0xffff, data: Uint8Array.from([...legacyPascal(""), ...legacyPascal("library.lib")]) },
    { type: 0x125, module: 1, data: Uint8Array.from([...legacyU32(1), ...legacySymbol()]) },
    { type: 0x127, module: 1, data: legacySource() }
  ], signature = "NB09"
): Uint8Array => {
  const bytes = new Uint8Array(24 + entries.length * 12 +
    entries.reduce((size, entry) => size + entry.data.length, 0));
  bytes.set(new TextEncoder().encode(signature));
  bytes.set(legacyU32(8), 4);
  bytes.set([...legacyU16(16), ...legacyU16(12), ...legacyU32(entries.length)], 8);
  let offset = 24 + entries.length * 12;
  entries.forEach((entry, index) => {
    bytes.set([...legacyU16(entry.type), ...legacyU16(entry.module),
      ...legacyU32(offset), ...legacyU32(entry.data.length)], 24 + index * 12);
    bytes.set(entry.data, offset);
    offset += entry.data.length;
  });
  return bytes;
};
