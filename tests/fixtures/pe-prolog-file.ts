import { createPePlusWithSection } from "./sample-files-pe.js";
import { MockFile } from "../helpers/mock-file.js";
import { writeRuntimeFunction } from "../helpers/pe-amd64-unwind-fixture.js";

export const createPePrologFile = (allocations = [40, 56]): MockFile => {
  const bytes = new Uint8Array(0x1200);
  bytes.set(createPePlusWithSection());
  const view = new DataView(bytes.buffer);
  // PE32+: optional header follows signature + COFF header; directory array is
  // at +112, .pdata is directory 3. Section header VirtualSize/RawSize are +8/+16.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
  const optional = view.getUint32(0x3c, true) + 24;
  const section = optional + 240;
  view.setUint32(section + 8, 0x1000, true);
  view.setUint32(section + 16, 0x1000, true);
  view.setUint32(optional + 56, 0x2000, true);
  view.setUint32(optional + 112 + 3 * 8, 0x1800, true);
  view.setUint32(optional + 112 + 3 * 8 + 4, allocations.length * 12, true);
  view.setUint32(optional + 112 + 12 * 8, 0, true);
  view.setUint32(optional + 112 + 12 * 8 + 4, 0, true);
  // Incidental placement: .text RVA 0x1000/raw 0x200; .pdata at 0x1800/raw 0xa00,
  // xdata at 0x1f00/raw 0x1100. UWOP_ALLOC_SMALL info 4 represents 40 bytes.
  // https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
  bytes.set([1, 4, 1, 0, 4, 0x42, 0, 0], 0x1100);
  allocations.forEach((size, index) => {
    const begin = 0x1000 + index * 8;
    bytes.set([0x48, 0x83, 0xec, size, 0x90, 0xc3], 0x200 + index * 8);
    writeRuntimeFunction(view, 0xa00 + index * 12, begin, begin + 6, 0x1f00);
  });
  return new MockFile(bytes, "prolog-validation.exe", "application/vnd.microsoft.portable-executable");
};
