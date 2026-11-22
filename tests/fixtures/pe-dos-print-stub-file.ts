import { MockFile } from "../helpers/mock-file.js";
import { createPePlusWithSection } from "./sample-files-pe.js";

export const createPeWithDosPrintStubFile = (): MockFile => {
  const bytes = createPePlusWithSection();
  const header = new DataView(bytes.buffer);
  // PE/COFF e_lfanew moves the PE signature after the stub. Move only the
  // headers and their padding, leaving the first section's raw bytes at 0x200.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#ms-dos-stub-image-only
  bytes.copyWithin(0x80, 0x40, 0x1c0);
  bytes.fill(0, 0x40, 0x80);
  header.setUint32(0x3c, 0x80, true);
  header.setUint16(8, 4, true); // e_cparhdr: four 16-byte paragraphs before code.
  // x86 instructions: push cs; pop ds; mov dx,14; print DS:DX; exit.
  bytes.set([0x0e, 0x1f, 0xba, 14, 0, 0xb4, 9, 0xcd, 0x21,
    0xb8, 1, 0x4c, 0xcd, 0x21], 0x40);
  bytes.set(new TextEncoder().encode("This program cannot be run in DOS mode.\r\n$"), 0x40 + 14);
  return new MockFile(bytes, "dos-print-stub.exe", "application/vnd.microsoft.portable-executable");
};
