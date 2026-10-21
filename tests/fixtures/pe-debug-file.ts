import { createPePlusWithSection } from "./sample-files-pe.js";
import { createEmbeddedPdbPayload, createPortablePdbRoot, createPortablePdbStreams } from "./portable-pdb.js";
import { createPogoPayload } from "./pe-debug-payload-subject.js";
import { MockFile } from "../helpers/mock-file.js";

const miscPaths = (paths: string[]): Uint8Array => Uint8Array.from(paths.flatMap(path => {
  const text = new TextEncoder().encode(`${path}\0`);
  const record = new Uint8Array(Math.ceil((12 + text.length) / 4) * 4);
  const view = new DataView(record.buffer);
  view.setUint32(0, 1, true); // IMAGE_DEBUG_MISC_EXENAME.
  view.setUint32(4, record.length, true);
  record.set(text, 12);
  return [...record];
}));

export const createPeDebugFile = (regionCount = 2): MockFile => {
  const fpo = new Uint8Array(26 * 16);
  const fpoView = new DataView(fpo.buffer);
  for (let index = 0; index < 26; index++) {
    fpoView.setUint32(index * 16, 0x1000 + index * 32, true);
    fpoView.setUint32(index * 16 + 4, 32, true);
    fpoView.setUint16(index * 16 + 14, 0x1800, true); // FPO_DATA: SEH and BP.
  }
  const omap = new Uint8Array(24);
  const omapView = new DataView(omap.buffer);
  [0x1000, 0x2000, 0x1100, 0, 0x1200, 0x1200].forEach((value, index) =>
    omapView.setUint32(index * 4, value, true));
  const payloads = [
    { type: 17, data: createEmbeddedPdbPayload(createPortablePdbRoot(createPortablePdbStreams())) },
    { type: 3, data: fpo }, { type: 7, data: omap },
    { type: 13, data: createPogoPayload(0x4c544347, Array.from(
      { length: regionCount }, (_, index) => ({ startRva: 0x1000 + index * 16,
        size: (index + 1) * 16, name: index === 0 ? ".text$first"
          : index === regionCount - 1 ? ".text$largest" : `.text$region_${index}` }))) },
    { type: 4, data: miscPaths(["first.dbg", "second.dbg"]) }
  ];
  return createPeWithDebugPayloads(payloads);
};

export const createPeWithDebugPayloads = (
  payloads: readonly { type: number; data: Uint8Array }[]
): MockFile => {
  const base = createPePlusWithSection();
  const bytes = new Uint8Array(Math.ceil((1024 + payloads.reduce(
    (size, payload) => size + payload.data.length, 0)) / 512) * 512);
  bytes.set(base);
  const view = new DataView(bytes.buffer);
  // PE32+ optional header, DEBUG data directory index 6; fixture's .text RVA/raw = 0x1000/0x200.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
  const optional = view.getUint32(0x3c, true) + 24;
  view.setUint32(optional + 112 + 6 * 8, 0x1100, true);
  view.setUint32(optional + 112 + 6 * 8 + 4, payloads.length * 28, true);
  view.setBigUint64(optional + 112 + 12 * 8, 0n, true); // Clear incidental fixture IAT.
  view.setUint32(optional + 240 + 8, bytes.length - 512, true);
  view.setUint32(optional + 240 + 16, bytes.length - 512, true);
  view.setUint32(optional + 56, Math.ceil((0x1000 + bytes.length - 512) / 0x1000) * 0x1000, true);
  let offset = 1024;
  payloads.forEach((payload, index) => {
    const directory = 0x300 + index * 28;
    view.setUint32(directory + 12, payload.type, true);
    view.setUint32(directory + 16, payload.data.length, true);
    view.setUint32(directory + 20, offset - 512 + 0x1000, true);
    view.setUint32(directory + 24, offset, true);
    if (payload.type === 17) view.setUint16(directory + 10, 0x0100, true);
    bytes.set(payload.data, offset);
    offset += payload.data.length;
  });
  bytes[512] = 0xc3; // RET keeps entry point analysis bounded in this UI fixture.
  return new MockFile(bytes, "debug-statistics.exe");
};

export const createPeWithExceptionCopy = (): MockFile => {
  const payload = new Uint8Array(24);
  const rows = new DataView(payload.buffer);
  // Two AMD64 rows, first referencing the second via RUNTIME_FUNCTION_INDIRECT.
  [0x1000, 0x1004, 0x108d, 0x1004, 0x1008, 0x10c0]
    .forEach((value, index) => rows.setUint32(index * 4, value, true));
  const bytes = createPeWithDebugPayloads([{ type: 5, data: payload }]).data.slice();
  const view = new DataView(bytes.buffer);
  const optional = view.getUint32(0x3c, true) + 24;
  view.setUint32(optional + 112 + 3 * 8, 0x1080, true);
  view.setUint32(optional + 112 + 3 * 8 + 4, payload.length, true);
  view.setUint32(optional + 240 + 8, 512, true);
  view.setUint32(optional + 240 + 16, 512, true);
  view.setUint32(optional + 56, 0x2000, true);
  view.setUint32(0x300 + 20, 0, true); // Raw-only copy at 0x400, outside .text.
  bytes.set(payload, 0x280);
  bytes[0x2c0] = 1; // Version-1 UNWIND_INFO without codes or handler.
  return new MockFile(bytes, "debug-exception-copy.exe");
};
