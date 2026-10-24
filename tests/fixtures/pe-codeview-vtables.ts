import { legacyU16, legacyU32, createLegacyCodeView } from "./pe-legacy-codeview.js";
import { codeViewTextRecord, codeViewUtf8 } from "./pe-codeview-type-strings.js";
import { createPeWithDebugPayloads } from "./pe-debug-file.js";

const classRecord = (name: string) => codeViewTextRecord(0x1505, 4,
  [...legacyU16(0), ...legacyU16(0), ...legacyU32(0), ...legacyU32(0), ...legacyU32(0),
    ...legacyU16(16), ...codeViewUtf8(name)]);

const vtableRecord = (owner: number, base: number, pointerOffset: number, names: readonly string[]) => {
  const text = names.flatMap(codeViewUtf8);
  return codeViewTextRecord(0x151d, 4, [...legacyU32(owner), ...legacyU32(base),
    ...legacyU32(pointerOffset), ...legacyU32(text.length), ...text]);
};

/** Controlled cvinfo.h layouts, with real class/table/method strings and both path index widths. */
export const codeViewVtableRecords = (): number[][] => [
  classRecord("Base"), classRecord("<Derived>&amp;"),
  vtableRecord(0x1000, 0, 0, ["Base::table", "read"]),
  vtableRecord(0x1001, 0x1002, 8, ["<Derived>&amp;::table", "read", "<write>&amp;"]),
  codeViewTextRecord(0x12, 4, [...legacyU16(2), ...legacyU16(0x1001), ...legacyU16(0x1000)]),
  codeViewTextRecord(0x100d, 4, [...legacyU32(2), ...legacyU32(0x1001), ...legacyU32(0x1000)])
];

export const createPeWithCodeViewVtables = () => createPeWithDebugPayloads([{ type: 2,
  data: createLegacyCodeView([{ type: 0x121, module: 1,
    data: Uint8Array.from([...legacyU32(4), ...codeViewVtableRecords().flat()]) }]) }]);
