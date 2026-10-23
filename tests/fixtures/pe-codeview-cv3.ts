import { legacyU16, legacyU32, legacyPascal } from "./pe-legacy-codeview.js";
import { createC6CodeView, c6Sections } from "./pe-codeview-c6.js";

export const cv3Module32 = (name = "wide.obj", segments = 1): Uint8Array => Uint8Array.from([
  ...legacyU16(2), ...legacyU32(0x10020), ...legacyU32(0x20040), ...legacyU16(3), ...legacyU16(4),
  segments, 0, ...legacyPascal(name),
  ...Array.from({ length: Math.max(0, segments - 1) }, (_, index) =>
    [...legacyU16(index + 3), ...legacyU32(0x30060), ...legacyU32(0x40080)]).flat()
]);

export const cv3SourceLines = (name = "old.c") => [
  ...legacyPascal(name), ...legacyU16(2), ...legacyU16(7), ...legacyU16(16), ...legacyU16(9), ...legacyU16(24)
];

export const createCv3CodeView = (): Uint8Array => {
  const entries = c6Sections();
  entries[0]!.data = cv3Module32();
  entries.push({ type: 0x105, module: 1, data: Uint8Array.from(cv3SourceLines()) });
  const bytes = createC6CodeView(entries);
  bytes[3] = 48; // NB00: Open Watcom's PE path selects cv3_module_32.
  return bytes;
};

export const cv3Trailer = (bytes: Uint8Array): Uint8Array => Uint8Array.from([
  ...bytes, ...bytes.slice(0, 4), ...legacyU32(bytes.length + 8)
]);
