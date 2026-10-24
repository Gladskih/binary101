import { legacyU16, legacyU32 } from "./pe-legacy-codeview.js";
import type { LegacyCodeViewTypeRecord } from "../../analyzers/pe/debug/legacy-codeview-type-records.js";
import { codeViewStoredFieldNames } from "./pe-codeview-fields.js";

/** Existing text tests check stored text independently of newly decoded type relationships. */
export const codeViewStoredTypeText = (records: readonly LegacyCodeViewTypeRecord[]) => records.map(
  record => ({ ...Object.fromEntries(Object.entries(record).filter(([key]) => key !== "index" && key !== "shape")),
    ...(record.members === undefined ? {} : { members: codeViewStoredFieldNames(record.members) }) }));

// Offsets include the two-byte record length, as in cvinfo.h's packed layouts.
export const codeViewTextRecord = (type: number, offset: number, text: readonly number[]): number[] => {
  const bytes = new Array<number>(offset).fill(0);
  bytes.splice(0, 4, ...legacyU16(offset + text.length - 2), ...legacyU16(type));
  return [...bytes, ...text];
};

/** String-focused fixtures still need a valid empty PRECOMP import range. */
export const codeViewStoredTextRecord = (type: number, offset: number, text: readonly number[]): number[] => {
  const record = codeViewTextRecord(type, offset, text);
  if ([0x13, 0x100e, 0x1509].includes(type)) {
    const width = type === 0x13 ? 2 : 4;
    record.splice(4, width, ...legacyU32(0x1000).slice(0, width));
  }
  return record;
};

export const codeViewVtableRecord = (text: readonly number[], declaredLength = text.length): number[] => {
  const bytes = codeViewTextRecord(0x151d, 20, text);
  bytes.splice(16, 4, ...legacyU32(declaredLength));
  return bytes;
};

export const codeViewUtf8 = (text: string): number[] => [...new TextEncoder().encode(text), 0];
