import { legacyPascal, legacySymbol, legacyU16, legacyU32 } from "./pe-legacy-codeview.js";

export const codeViewUniqueType = (type: number, offset: number, name: string,
  identity: readonly number[]): number[] => {
  const bytes = [...legacySymbol(type, name, offset), ...identity];
  bytes.splice(0, 2, ...legacyU16(bytes.length - 2));
  bytes.splice(6, 2, 0, 2); // CV_prop_t.hasuniquename is bit 9.
  return bytes;
};

// Microsoft cvinfo.h field-list subrecords have ST names before 0x1500 and
// UTF-8 NUL-terminated names afterwards. Emit the conventional LF_PADn countdown.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h
export const codeViewField = (type: number, body: readonly number[], name: string): number[] => {
  const text = type >= 0x1500 ? [...new TextEncoder().encode(name), 0] : legacyPascal(name);
  const bytes = [...legacyU16(type), ...body, ...text];
  const padding = (4 - bytes.length % 4) % 4;
  return [...bytes, ...Array.from({ length: padding }, (_, index) => 0xf0 + padding - index)];
};

export const codeViewFieldList = (fields: number[], type = 0x204): number[] =>
  [...legacyU16(fields.length + 2), ...legacyU16(type), ...fields];

export const codeViewMethodField = (type: number, property: number, name: string): number[] =>
  codeViewField(type, [...legacyU16(3 | property << 2),
    ...new Array<number>(type === 0x40c ? 2 : 4).fill(0),
    ...([4, 6].includes(property) ? legacyU32(32) : [])], name);

export const codeViewBaseField = (type: number, offset: number): number[] =>
  [...legacyU16(type), ...new Array<number>(offset - 2).fill(0),
    ...legacyU16(0x8004), ...legacyU32(65536),
    ...([0x401, 0x402, 0x1401, 0x1402].includes(type) ? legacyU16(8) : [])];
