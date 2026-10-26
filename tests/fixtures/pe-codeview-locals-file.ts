import { createPeWithDebugPayloads } from "./pe-debug-file.js";
import { createLegacyCodeView, legacyU16, legacyU32 } from "./pe-legacy-codeview.js";
import { codeViewProcedure } from "./pe-codeview-procedures.js";
import { frameRecord, localName, localRecord, localRangeBytes, localVariableRecord } from "./pe-codeview-locals.js";

/** Controlled packed C7 scope links, not claimed to be compiler-generated NB09. */
export const codeViewLocalModule = (): Uint8Array => {
  const procedure = codeViewProcedure(0x1110, localName("<inspect>&amp;"), 64, 0, 64, 0, 16, 1);
  const body = [frameRecord(0x154000), localVariableRecord("seed"),
    localRecord(0x1141, [...legacyU16(330), ...legacyU16(0), ...localRangeBytes(16, 64)]),
    localVariableRecord("temporary", 0), localRecord(0x1142,
      [...legacyU32(0xfffffff8), ...localRangeBytes(16, 32), ...legacyU16(4), ...legacyU16(8)]),
    localVariableRecord("gone", 0x100), localVariableRecord("entire", 0),
    localRecord(0x1144, legacyU32(0xfffffff0))].flat();
  const bytes = Uint8Array.from([...legacyU32(1), ...procedure, ...body, ...localRecord(6, [])]);
  const view = new DataView(bytes.buffer);
  view.setUint32(8, 0, true); // pParent: root procedure; offsets include the signature DWORD.
  view.setUint32(12, 4 + procedure.length + body.length, true); // pEnd.
  view.setUint32(16, 0, true); // pNext.
  return bytes;
};

export const createPeWithCodeViewLocals = () => createPeWithDebugPayloads([{ type: 2,
  data: createLegacyCodeView([{ type: 0x125, module: 1, data: codeViewLocalModule() }]) }]);
