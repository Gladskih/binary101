"use strict";

import { MockFile } from "../helpers/mock-file.js";
import { writeRuntimeFunction } from "../helpers/pe-amd64-unwind-fixture.js";
import { createPePlusWithSection } from "./sample-files-pe.js";

export const createPePdataRangeFile = (): MockFile => {
  const bytes = createPePlusWithSection();
  const view = new DataView(bytes.buffer);
  // PE32+ layout: e_lfanew at 0x3c; signature 4 bytes; COFF header 20 bytes;
  // data directories start 112 bytes into the optional header, EXCEPTION index 3.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
  const directories = view.getUint32(0x3c, true) + 4 + 20 + 112;
  // Incidental layout in .text (RVA 0x1000, raw 0x200): table at RVA 0x1100/raw 0x300,
  // unwind header at RVA 0x1180/raw 0x380.
  const lengths = [1, 2, 3, 8, 16];
  // AMD64 RUNTIME_FUNCTION rows contain three 32-bit RVAs; UNWIND_INFO version 1.
  // https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
  view.setUint32(directories + 3 * 8, 0x1100, true);
  view.setUint32(directories + 3 * 8 + 4, lengths.length * 12, true);
  // Remove the base fixture's incidental IAT directory, which shares the chosen table space.
  view.setUint32(directories + 12 * 8, 0, true);
  view.setUint32(directories + 12 * 8 + 4, 0, true);
  bytes[0x380] = 1;
  let beginRva = 0x1000;
  for (const [index, length] of lengths.entries()) {
    writeRuntimeFunction(view, 0x300 + index * 12, beginRva, beginRva + length, 0x1180);
    beginRva += length;
  }
  return new MockFile(bytes, "pdata-ranges.exe", "application/vnd.microsoft.portable-executable");
};
