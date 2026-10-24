import { legacyU16, legacyU32, legacyPascal, createLegacyCodeView } from "./pe-legacy-codeview.js";
import { codeViewTextRecord, codeViewUtf8 } from "./pe-codeview-type-strings.js";
import { createPeWithDebugPayloads } from "./pe-debug-file.js";

/** TIS 3.3 LF_PRECOMP imports [start, start + count); its marker is not an imported type. */
export const codeViewPrecompiledRecord = (leaf = 0x1509, start = 0x1000, count = 3): number[] => {
  const index = leaf === 0x13 ? legacyU16 : legacyU32;
  return codeViewTextRecord(leaf, 4, [...index(start), ...index(count), ...legacyU32(0x12345678),
    ...(leaf < 0x1500 ? legacyPascal("precompiled.obj") : codeViewUtf8("precompiled.obj"))]);
};

export const createPeWithCodeViewPrecompiledTypes = () => createPeWithDebugPayloads([{ type: 2,
  data: createLegacyCodeView([{ type: 0x121, module: 1, data: Uint8Array.from([
    ...legacyU32(4), ...codeViewPrecompiledRecord(),
    ...codeViewTextRecord(0x1203, 4, [...legacyU16(0x150d), ...legacyU16(3), ...legacyU32(0x74),
      ...legacyU16(0), ...codeViewUtf8("count")]),
    ...codeViewTextRecord(0x1505, 4, [...legacyU16(1), ...legacyU16(0), ...legacyU32(0x1003),
      ...legacyU32(0), ...legacyU32(0), ...legacyU16(4), ...codeViewUtf8("PchLocal")]),
    ...codeViewTextRecord(0x1605, 4, [...legacyU32(0), ...codeViewUtf8("PchConsumer.cpp")]),
    ...codeViewTextRecord(0x1606, 4, [...legacyU32(0x1004), ...legacyU32(0x1005), ...legacyU32(2)])
  ]) }]) }]);
