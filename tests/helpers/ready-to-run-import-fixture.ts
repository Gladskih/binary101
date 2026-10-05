import { MockFile } from "./mock-file.js";

// READYTORUN_IMPORT_SECTION (readytorun.h): RVA, size, ushort flags, byte type,
// byte cell width, RVA of signatures, RVA of auxiliary data.
export const createReadyToRunImportFixture = () => {
  const bytes = new Uint8Array(128);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 64, true);
  view.setUint32(4, 16, true);
  view.setUint16(8, 1, true);
  view.setUint8(10, 2);
  view.setUint8(11, 8);
  view.setUint32(12, 96, true);
  view.setUint32(16, 112, true);
  view.setBigUint64(64, 0x1122334455667788n, true);
  view.setBigUint64(72, 0xaabbccddeeff0011n, true);
  view.setUint32(96, 112, true);
  view.setUint32(100, 116, true);
  return { bytes, view, header: new DataView(bytes.buffer, 0, 20),
    reader: new MockFile(bytes) };
};
