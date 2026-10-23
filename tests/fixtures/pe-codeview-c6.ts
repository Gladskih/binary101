import { legacyU16, legacyU32, legacyPascal } from "./pe-legacy-codeview.js";
import { createPeWithDebugPayloads } from "./pe-debug-file.js";

export const c6Symbol = (type: number, body: readonly number[] = []): number[] =>
  [body.length + 1, type, ...body];

export const c6Type = (type: number, body: readonly number[] = []): number[] =>
  [0, ...legacyU16(body.length + 1), type, ...body];

export const c6Name = (name: string): number[] => [130, ...legacyPascal(name)];
export const c6Index = (index = 512): number[] => [131, ...legacyU16(index)];

export const c6Module = (name = "legacy.obj", segments = 1): Uint8Array => Uint8Array.from([
  ...legacyU16(1), ...legacyU16(16), ...legacyU16(32), ...legacyU16(0), ...legacyU16(1),
  segments, 0, ...legacyPascal(name),
  ...Array.from({ length: Math.max(0, segments - 1) }, (_, index) =>
    [...legacyU16(index + 2), ...legacyU16(48), ...legacyU16(64)]).flat()
]);

export const c6Sections = () => [
  { type: 0x101, module: 1, data: c6Module() },
  { type: 0x102, module: 1, data: Uint8Array.from([...legacyU32(16), ...legacyU16(1),
    ...legacyU16(512), ...legacyPascal("public_name")]) },
  { type: 0x103, module: 1, data: Uint8Array.from(c6Type(93, [...c6Index(), ...c6Name("Alias")])) },
  { type: 0x104, module: 1, data: Uint8Array.from(c6Symbol(0x84, [...legacyU32(16),
    ...legacyU16(512), ...legacyPascal("stack_name")])) },
  { type: 0x106, module: 0xffff, data: Uint8Array.from([...legacyPascal(""), ...legacyPascal("legacy.lib")]) },
  { type: 0x109, module: 1, data: Uint8Array.from([...legacyPascal("legacy.c"), ...legacyU16(1),
    ...legacyU16(2), ...legacyU16(7), ...legacyU32(16), ...legacyU16(9), ...legacyU32(24)]) }
];

export const createC6CodeView = (entries = c6Sections()): Uint8Array => {
  const bytes = new Uint8Array(10 + entries.length * 10 +
    entries.reduce((size, entry) => size + entry.data.length, 0));
  bytes.set([78, 66, 48, 50, ...legacyU32(8), ...legacyU16(entries.length)]);
  let offset = 10 + entries.length * 10;
  entries.forEach((entry, index) => {
    bytes.set([...legacyU16(entry.type), ...legacyU16(entry.module),
      ...legacyU32(offset), ...legacyU16(entry.data.length)], 10 + index * 10);
    bytes.set(entry.data, offset);
    offset += entry.data.length;
  });
  return bytes;
};

export const createPeWithC6CodeView = () => {
  const sections = c6Sections();
  sections[3]!.data = Uint8Array.from(Array.from({ length: 101 }, (_, index) =>
    c6Symbol(0x84, [...legacyU32(index), ...legacyU16(512), ...legacyPascal(`<stack_${index}>`)])).flat());
  sections[2]!.data = Uint8Array.from([
    ...c6Type(93, [...c6Index(), ...c6Name("<Alias>")]),
    ...c6Type(127, [...c6Name("<member>"), 0]),
    ...c6Type(142, [5, ...c6Name("lower"), ...c6Name("upper")])
  ]);
  return createPeWithDebugPayloads([{ type: 2, data: createC6CodeView(sections) }]);
};
