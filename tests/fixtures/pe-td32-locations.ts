import { createPeWithDebugPayloads } from "./pe-debug-file.js";
import { createTd32 } from "./pe-td32.js";
import { MockFile } from "../helpers/mock-file.js";

const image = (): Uint8Array => {
  const bytes = createPeWithDebugPayloads([]).data.slice();
  const view = new DataView(bytes.buffer);
  // PE32+ DEBUG directory, without an incidental nonzero RVA / zero size.
  view.setUint32(view.getUint32(0x3c, true) + 24 + 112 + 6 * 8, 0, true);
  return bytes;
};

export const createPeTd32Overlay = (payload = createTd32()): MockFile =>
  new MockFile(Uint8Array.from([...image(), ...payload]), "td32-overlay.exe");

export const createPeTd32Section = (payload = createTd32()): MockFile => {
  // FileAlignment is 512 in this PE fixture. Put padding before the container,
  // leaving its trailer at the physical end of the new .debug section.
  const size = Math.ceil(payload.length / 512) * 512;
  const base = image();
  const bytes = new Uint8Array(base.length + size);
  bytes.set(base);
  bytes.set(payload, bytes.length - payload.length);
  const view = new DataView(bytes.buffer);
  const pe = view.getUint32(0x3c, true);
  const section = pe + 24 + 240 + 40;
  view.setUint16(pe + 6, 2, true);
  view.setUint32(pe + 24 + 56, Math.ceil((0x2000 + size) / 0x1000) * 0x1000, true);
  bytes.set(new TextEncoder().encode(".debug"), section);
  [size, 0x2000, size, base.length].forEach((value, index) =>
    view.setUint32(section + 8 + index * 4, value, true));
  view.setUint32(section + 36, 0x42000040, true);
  return new MockFile(bytes, "td32-section.exe");
};
