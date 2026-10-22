import { createPeWithSectionAndIat } from "./sample-files-pe.js";
import { armntPackedWord } from "./pe-armnt-unwind.js";
import { MockFile } from "../helpers/mock-file.js";

export const createPeWithRawArmntExceptionCopy = (): MockFile => {
  const bytes = new Uint8Array(1536);
  bytes.set(createPeWithSectionAndIat());
  const view = new DataView(bytes.buffer);
  const pe = view.getUint32(0x3c, true);
  const optional = pe + 24;
  // PE32, ARMNT Thumb-2; DEBUG directory index6. The .text RVA/raw are 0x1000/0x200.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
  view.setUint16(pe + 4, 0x1c4, true);
  view.setUint16(pe + 22, 0x0102, true);
  view.setUint32(optional + 16, 0x1001, true);
  view.setBigUint64(optional + 96 + 12 * 8, 0n, true);
  view.setUint32(optional + 96 + 6 * 8, 0x1100, true);
  view.setUint32(optional + 96 + 6 * 8 + 4, 28, true);
  view.setUint16(0x200, 0x4770, true); // Thumb BX LR.
  view.setUint32(0x300 + 12, 5, true);
  view.setUint32(0x300 + 16, 16, true);
  view.setUint32(0x300 + 24, 0x400, true); // Copy is stored outside mapped sections, without its table RVA.
  [0x1001, armntPackedWord(64) | (1 << 15) | (1 << 20) | (1 << 21) | (0x3ff << 22),
    0x1041, armntPackedWord(64, 2)].forEach((word, index) => view.setUint32(0x400 + index * 4, word, true));
  return new MockFile(bytes, "debug-raw-armnt-exception-copy.exe");
};
