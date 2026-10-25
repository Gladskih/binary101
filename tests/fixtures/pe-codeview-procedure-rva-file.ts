import { createPeWithDebugPayloads } from "./pe-debug-file.js";
import { createLegacyCodeView, legacyU16, legacyU32 } from "./pe-legacy-codeview.js";
import { codeViewProcedure } from "./pe-codeview-procedures.js";

/** Controlled NB09 records in a PE image, not compiler-generated embedded debug data. */
export const createPeWithProcedureRvas = () => {
  const map = new Uint8Array(24);
  const view = new DataView(map.buffer);
  view.setUint16(0, 1, true);
  view.setUint16(2, 1, true);
  view.setUint16(4, 0x10d, true); // 32-bit selector, readable and executable (TIS 7.4).
  view.setUint16(10, 1, true); // Physical section 1.
  view.setUint16(12, 0xffff, true);
  view.setUint16(14, 0xffff, true);
  view.setUint32(16, 32, true);
  view.setUint32(20, 64, true);
  const name = (value: string): number[] => [...new TextEncoder().encode(value), 0];
  const removed = codeViewProcedure(0x1110, name("removed_function"), 16, 0, 16, 0, 16, 1);
  const symbols = Uint8Array.from([...legacyU32(1),
    ...codeViewProcedure(0x1110, name("<mapped>&amp;"), 16, 0, 16, 0, 16, 1),
    ...codeViewProcedure(0x110f, name("outside_segment"), 64, 0, 64, 0, 16, 1),
    ...legacyU16(14 + removed.length), ...legacyU16(0x113b),
    ...legacyU32(0), ...legacyU32(0), ...legacyU32(0), ...removed]);
  return createPeWithDebugPayloads([{ type: 2, data: createLegacyCodeView([
    { type: 0x12d, module: 0xffff, data: map }, { type: 0x125, module: 1, data: symbols }
  ]) }]);
};
