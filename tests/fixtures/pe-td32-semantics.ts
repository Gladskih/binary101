import { createTd32, td32Names, td32Symbol } from "./pe-td32.js";
import { legacyU16, legacyU32 } from "./pe-legacy-codeview.js";
import { localRecord } from "./pe-codeview-locals.js";
import { createPeWithDebugPayloads } from "./pe-debug-file.js";

/** Controlled TD32 packed fields; independent external tests use a real unchanged FB0A. */
export const createPeWithTd32Semantics = () => {
  const procedure = td32Symbol(0x205, 1);
  const variable = td32Symbol(0x200, 2, 12);
  const symbols = Uint8Array.from([...legacyU32(1), ...procedure, ...variable, ...localRecord(6, [])]);
  const fields = new DataView(symbols.buffer);
  fields.setUint32(12, 4 + procedure.length + variable.length, true);
  fields.setUint32(20, 64, true);
  fields.setUint32(24, 4, true);
  fields.setUint32(28, 60, true);
  fields.setUint32(32, 32, true);
  fields.setUint16(36, 1, true);
  fields.setInt32(4 + procedure.length + 4, -8, true);
  const records = [localRecord(5, [...legacyU16(3), ...legacyU32(0), ...legacyU16(3),
    ...[0, 0, 0, 3].flatMap(legacyU32), ...legacyU16(24)]),
  localRecord(1, [...legacyU16(1), ...legacyU32(0x1000)])];
  const types = Uint8Array.from([...legacyU32(1), ...legacyU32(2), ...legacyU32(16),
    ...legacyU32(16 + records[0]!.length), ...records.flat()]);
  return createPeWithDebugPayloads([{ type: 0, data: createTd32([
    { type: 0x130, module: 0, data: td32Names(["<worker>", "value", "Widget"]) },
    { type: 0x125, module: 1, data: symbols }, { type: 0x12b, module: 0, data: types }
  ], "FB0A") }]);
};
