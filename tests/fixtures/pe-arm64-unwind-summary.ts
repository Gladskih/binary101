import { MockFile } from "../helpers/mock-file.js";
import { createPeWithRawArm64ExceptionCopy } from "./pe-debug-file.js";

export const createArm64UnwindSummaryPe = (): MockFile => {
  const bytes = createPeWithRawArm64ExceptionCopy().data.slice();
  const view = new DataView(bytes.buffer);
  // One .xdata-backed function and one packed frame, both eight-byte pdata rows.
  [0x1000, 0x10c0, 0x1040, 5 | (1 << 13) | (2 << 16) | (2 << 21) | (8 << 23)]
    .forEach((word, index) => view.setUint32(0x400 + index * 4, word, true));
  // FunctionLength=64, E=1, shared epilog starts at set_fp's successor byte 1.
  // set_fp, save_fregp D8/D9+48, save_next X21/X22+32,
  // save_regp X19/X20+16, save_fplr_x 96, end.
  // https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling#unwind-codes
  view.setUint32(0x2c0, 16 | (1 << 21) | (1 << 22) | (2 << 27), true);
  bytes.set([0xe1, 0xd8, 6, 0xe6, 0xc8, 2, 0x8b, 0xe4], 0x2c4);
  return new MockFile(bytes, "arm64-unwind-summary.exe");
};
