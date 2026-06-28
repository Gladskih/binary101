"use strict";

import { MockFile } from "../helpers/mock-file.js";
import { createPePlusWithSection } from "./sample-files-pe.js";

export const createPePlusLongEntrypointFile = (): MockFile => {
  const bytes = createPePlusWithSection();
  const textRawOffset = 0x200;
  // Intel SDM opcode reference: 0x90 is NOP, and 0xc3 is near RET.
  // https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
  bytes.fill(0x90, textRawOffset, textRawOffset + 120);
  bytes[textRawOffset + 120] = 0xc3;
  return new MockFile(
    bytes,
    "sample-x64-long-entrypoint.exe",
    "application/vnd.microsoft.portable-executable"
  );
};
