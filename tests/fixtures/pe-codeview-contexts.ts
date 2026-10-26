import { legacyU16, legacyU32, createLegacyCodeView } from "./pe-legacy-codeview.js";
import { codeViewProcedure } from "./pe-codeview-procedures.js";
import { localName, localRecord, localVariableRecord } from "./pe-codeview-locals.js";
import { createPeWithDebugPayloads } from "./pe-debug-file.js";

/** Explicit physical links make this a controlled lexical-scope fixture, not a claimed compiler artifact. */
export const codeViewContextModule = (): Uint8Array => {
  const records = [codeViewProcedure(0x1110, localName("outer"), 64, 0, 64, 0, 32, 1),
    localRecord(0x114d, [...[4, 0, 0x1004].flatMap(legacyU32), 3, 4, 4, 12]),
    localVariableRecord("inlined"), localRecord(0x114e, []),
    localRecord(0x1104, [...[4, 0, 16, 32].flatMap(legacyU32), ...legacyU16(1), ...localName("object.member")]),
    localVariableRecord("withLocal"), localRecord(6, []), localRecord(6, []),
    localRecord(0x1102, [...[0, 0, 0, 96].flatMap(legacyU32), ...legacyU16(1), ...legacyU16(8),
      1, ...localName("adjustor"), ...legacyU16(0xfff8), ...localName("target")]),
    localVariableRecord("thunkLocal"), localRecord(6, [])];
  const offsets: number[] = [];
  let offset = 4;
  for (const record of records) { offsets.push(offset); offset += record.length; }
  const bytes = Uint8Array.from([...legacyU32(1), ...records.flat()]);
  const view = new DataView(bytes.buffer);
  view.setUint32(offsets[0]! + 4, 0, true);
  for (const [start, end] of [[0, 7], [1, 3], [4, 6], [8, 10]]) {
    view.setUint32(offsets[start!]! + 8, offsets[end!]!, true);
  }
  view.setUint32(offsets[0]! + 12, offsets[8]!, true);
  return bytes;
};

export const createPeWithCodeViewContexts = () => createPeWithDebugPayloads([{ type: 2,
  data: createLegacyCodeView([{ type: 0x125, module: 1, data: codeViewContextModule() }]) }]);
