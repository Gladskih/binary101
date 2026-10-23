import { createPeWithDebugPayloads } from "./pe-debug-file.js";
import { MockFile } from "../helpers/mock-file.js";
import { createHll } from "./pe-hll.js";

export const createPeCodeViewOverlay = (payload = createHll()): MockFile => {
  const image = createPeWithDebugPayloads([]).data.slice();
  new DataView(image.buffer).setUint32(new DataView(image.buffer).getUint32(0x3c, true) + 24 + 112 + 6 * 8, 0, true);
  return new MockFile(Uint8Array.from([...image, ...payload]), "codeview-overlay.exe");
};

export const createPeDirectHll = (payload = createHll()): MockFile => {
  const bytes = createPeWithDebugPayloads([{ type: 2, data: payload }]).data.slice();
  const view = new DataView(bytes.buffer);
  const debug = view.getUint32(0x3c, true) + 24 + 112 + 6 * 8;
  view.setUint32(debug, 0x1200, true); // Raw NB04 header at the DEBUG RVA, no IMAGE_DEBUG_DIRECTORY.
  view.setUint32(debug + 4, payload.length, true);
  return new MockFile(bytes, "hll-direct.exe");
};
