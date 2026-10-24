import { legacyU16, legacyU32, legacyPascal, createLegacyCodeView } from "./pe-legacy-codeview.js";
import { codeViewTextRecord, codeViewUtf8 } from "./pe-codeview-type-strings.js";
import { codeViewField, codeViewFieldList } from "./pe-codeview-fields.js";
import { createPeWithDebugPayloads } from "./pe-debug-file.js";

export const codeViewInlineTypeName = (type: number, name: string): number[] =>
  type < 0x1500 ? legacyPascal(name) : codeViewUtf8(name);

export const codeViewCompositeText = (type: number, name: string): number[] => type < 0x1500
  ? legacyPascal(name) : [...codeViewUtf8(name), ...codeViewUtf8(`${type === 0x1507 ? ".?AW4" : ".?AU"}${name}@@`)];

export const createPeWithCodeViewComposites = (declaredMethods = 2) => createPeWithDebugPayloads([{ type: 2,
  data: createLegacyCodeView([{ type: 0x121, module: 1, data: Uint8Array.from([
    ...legacyU32(4),
    ...codeViewFieldList([
      ...codeViewField(0x150d, [...legacyU16(3), ...legacyU32(0x74), ...legacyU16(0)], "count"),
      ...codeViewField(0x150d, [...legacyU16(3), ...legacyU32(0x1002), ...legacyU16(4)], "values"),
      ...codeViewField(0x150f, [...legacyU16(declaredMethods), ...legacyU32(0x100a)], "read")
    ], 0x1203),
    ...codeViewTextRecord(0x1505, 4, [...legacyU16(2 + declaredMethods), ...legacyU16(0x201), ...legacyU32(0x1000),
      ...legacyU32(0), ...legacyU32(0), ...legacyU16(16), ...codeViewCompositeText(0x1505, "<Packet>&amp;")]),
    ...codeViewTextRecord(0x1503, 4, [...legacyU32(0x74), ...legacyU32(0x75), ...legacyU16(12), 0]),
    ...codeViewFieldList([
      ...codeViewField(0x1502, [...legacyU16(3), ...legacyU16(1)], "idle"),
      ...codeViewField(0x1502, [...legacyU16(3), ...legacyU16(7)], "ready")
    ], 0x1203),
    ...codeViewTextRecord(0x1507, 4, [...legacyU16(2), ...legacyU16(0x300), ...legacyU32(0x75),
      ...legacyU32(0x1003), ...codeViewCompositeText(0x1507, "State")]),
    ...codeViewTextRecord(0x1201, 4, legacyU32(0)),
    ...codeViewTextRecord(0x1201, 4, [...legacyU32(1), ...legacyU32(0x74)]),
    ...codeViewTextRecord(0x1002, 4, [...legacyU32(0x1001), ...legacyU32(0x0c)]),
    ...codeViewTextRecord(0x1009, 4, [...legacyU32(0x74), ...legacyU32(0x1001), ...legacyU32(0x1007),
      0, 0, ...legacyU16(0), ...legacyU32(0x1005), ...legacyU32(0)]),
    ...codeViewTextRecord(0x1009, 4, [...legacyU32(0x74), ...legacyU32(0x1001), ...legacyU32(0x1007),
      0, 0, ...legacyU16(1), ...legacyU32(0x1006), ...legacyU32(0)]),
    ...codeViewTextRecord(0x1206, 4, [...legacyU16(3), ...legacyU16(0), ...legacyU32(0x1008),
      ...legacyU16(7), ...legacyU16(0), ...legacyU32(0x1009)]),
    ...codeViewTextRecord(10, 4, [...legacyU16(3), 0x55, 0x50])
  ]) }])
}]);
