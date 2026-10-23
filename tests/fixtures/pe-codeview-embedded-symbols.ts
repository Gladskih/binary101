import { legacyU16, legacySymbol } from "./pe-legacy-codeview.js";
import { codeViewTextRecord } from "./pe-codeview-type-strings.js";
import type { LegacyCodeViewSymbol } from "../../analyzers/pe/debug/legacy-codeview-symbol-records.js";
import { createPeWithDebugPayloads } from "./pe-debug-file.js";
import { createLegacyCodeView, legacyU32, legacyPascal } from "./pe-legacy-codeview.js";
import { codeViewAnnotations } from "./pe-codeview-symbol-strings.js";
import { codeViewUtf8 } from "./pe-codeview-type-strings.js";

export const codeViewEntryThis = (records: readonly number[]): number[] => codeViewTextRecord(0xe, 4, records);
export const codeViewDiscarded = (records: readonly number[]): number[] => {
  const bytes = codeViewTextRecord(0x113b, 16, records);
  bytes.splice(8, 4, 255, 255, 255, 255); // cvinfo.h: absent FILEID is 0xffffffff.
  return bytes;
};

export const codeViewDeepThis = (depth: number): number[] => {
  let bytes = legacySymbol(0x110e, "deep", 14);
  for (let index = 0; index < depth; index++) bytes = codeViewEntryThis(bytes);
  return bytes;
};

export const codeViewSymbolChain = (record: LegacyCodeViewSymbol): LegacyCodeViewSymbol[] => {
  const chain: LegacyCodeViewSymbol[] = [];
  for (let current: LegacyCodeViewSymbol | undefined = record; current; current = current.children?.[0]) {
    chain.push(current);
  }
  return chain;
};

export const codeViewSymbolTree = (depth: number): LegacyCodeViewSymbol => {
  let record: LegacyCodeViewSymbol = { type: 0x110e, name: "deep" };
  for (let index = 0; index < depth; index++) record = { type: 0xe, children: [record] };
  return record;
};

export const codeViewPointerBase = (type: number, attributes: number, payload: readonly number[]): number[] => {
  const bytes = codeViewTextRecord(type, type === 2 ? 8 : 12, payload);
  bytes.splice(type === 2 ? 4 : 8, 2, ...legacyU16(attributes));
  return bytes;
};

export const createPeWithEmbeddedCodeView = () => {
  const discarded = codeViewDiscarded([
    ...Array.from({ length: 101 }, (_, index) => legacySymbol(0x110d, `<discarded_${index}>`, 14)).flat(),
    ...codeViewAnnotations(codeViewUtf8("<annotation>"), 1)
  ]);
  discarded.splice(4, 12, ...legacyU32(2), ...legacyU32(7), ...legacyU32(42));
  const second = codeViewDiscarded([]);
  second.splice(4, 12, ...legacyU32(2), ...legacyU32(8), ...legacyU32(90));
  return createPeWithDebugPayloads([{ type: 2, data: createLegacyCodeView([
    { type: 0x125, module: 1, data: Uint8Array.from([...legacyU32(4), ...discarded, ...second,
      ...codeViewEntryThis(legacySymbol(0x110e, "thisAlias", 14))]) },
    { type: 0x121, module: 1, data: Uint8Array.from([...legacyU32(4),
      ...codeViewTextRecord(0x20c, 4, legacySymbol(0x110e, "referenced", 14)),
      ...codeViewPointerBase(2, 8, [0, 0, ...legacyPascal("BaseType")]),
      ...codeViewPointerBase(0x1002, 4, legacySymbol(0x110d, "basedValue", 14))]) }
  ]) }]);
};
