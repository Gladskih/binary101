import { createPeWithDebugPayloads } from "./pe-debug-file.js";
import { createLegacyCodeView, legacyU16, legacyU32 } from "./pe-legacy-codeview.js";
import { codeViewTextRecord, codeViewUtf8 } from "./pe-codeview-type-strings.js";

const aggregate = (name: string, derived: number) => codeViewTextRecord(0x1505, 4,
  [...legacyU16(0), ...legacyU16(0), ...legacyU32(0), ...legacyU32(derived), ...legacyU32(0),
    ...legacyU16(0), ...codeViewUtf8(name)]);

const storedString = (text: string) => codeViewTextRecord(0x1605, 4,
  [...legacyU32(0), ...codeViewUtf8(text)]);

/** Controlled packed records from cvinfo.h, including explicit module string offsets. */
export const createPeWithCodeViewBuildInfo = () => createPeWithDebugPayloads([{ type: 2,
  data: createLegacyCodeView([{ type: 0x121, module: 1, data: Uint8Array.from([
    ...legacyU32(4),
    ...aggregate("Base", 0x1002), ...aggregate("<Derived>&amp;", 0),
    ...codeViewTextRecord(0x205, 4, [...legacyU16(2), ...legacyU16(0x1001), ...legacyU16(7)]),
    ...storedString("<source>&amp;.cpp"),
    ...codeViewTextRecord(0x1606, 4, [...legacyU32(0x1000), ...legacyU32(0x1003), ...legacyU32(123)]),
    ...storedString("cl.exe"), ...storedString("/c /DNAME=<value>&amp;"),
    ...codeViewTextRecord(0x1603, 4, [...legacyU16(5), ...legacyU32(0), ...legacyU32(0x1005),
      ...legacyU32(0x1003), ...legacyU32(0), ...legacyU32(0x1006)]),
    ...codeViewTextRecord(0x1604, 4, [...legacyU32(2), ...legacyU32(0x1005), ...legacyU32(0x1003)]),
    ...codeViewTextRecord(0x1605, 4, [...legacyU32(0x1008), ...codeViewUtf8("suffix")]),
    ...codeViewTextRecord(0x1607, 4,
      [...legacyU32(0x1001), ...legacyU32(32), ...legacyU32(456), ...legacyU16(2)])
  ]) }]) }]);
