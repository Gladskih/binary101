"use strict";

import { MockFile } from "../helpers/mock-file.js";

const encoder = new TextEncoder();

export const createDosMzExe = () => {
  const bytes = new Uint8Array(128).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint16(0x00, 0x5a4d, true); // MZ
  dv.setUint16(0x02, 128, true); // bytes in last page
  dv.setUint16(0x04, 1, true); // pages
  dv.setUint16(0x08, 4, true); // header size in paragraphs
  dv.setUint16(0x0a, 0, true); // min extra paragraphs
  dv.setUint16(0x0c, 0xffff, true); // max extra paragraphs
  dv.setUint16(0x0e, 0, true); // ss
  dv.setUint16(0x10, 0x00b8, true); // sp
  dv.setUint16(0x18, 0x0040, true); // relocation table offset
  dv.setUint32(0x3c, 0, true); // no extended header
  const stub = encoder.encode("DOS stub - no PE header");
  bytes.set(stub.slice(0, bytes.length - 64), 64);
  return new MockFile(bytes, "dos-stub.exe", "application/x-msdos-program");
};
