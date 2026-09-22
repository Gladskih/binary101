import { createExtraDebugPayloadSubject } from "./pe-debug-extra-payloads.js";

// OMAP is two little-endian DWORDs, without a header.
// https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/ns-dbghelp-omap
export const createOmapPayload = (records: readonly (readonly [number, number])[]): Uint8Array => {
  const bytes = new Uint8Array(records.length * 8);
  const view = new DataView(bytes.buffer);
  records.forEach(([rva, rvaTo], index) => {
    view.setUint32(index * 8, rva, true);
    view.setUint32(index * 8 + 4, rvaTo, true);
  });
  return bytes;
};

export const createOmapSubject = () => createExtraDebugPayloadSubject(
  createOmapPayload([[0, 0], [0x12345678, 0xfedcba98], [0xffffffff, 0]])
);
