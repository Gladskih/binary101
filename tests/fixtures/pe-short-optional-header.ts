export const createPeWithShortOptionalHeader = (): Uint8Array => {
  const bytes = new Uint8Array(0x180);
  const view = new DataView(bytes.buffer);
  // Microsoft PE format: PE signature at e_lfanew, followed by the 20-byte COFF header.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-image-only
  view.setUint16(0, 0x5a4d, true);
  view.setUint32(0x3c, 0x40, true);
  bytes.set([0x50, 0x45, 0, 0], 0x40);
  view.setUint16(0x44, 0x14c, true); // x86
  view.setUint16(0x54, 8, true); // SizeOfOptionalHeader ends before AddressOfEntryPoint.
  view.setUint16(0x56, 2, true); // IMAGE_FILE_EXECUTABLE_IMAGE
  view.setUint16(0x58, 0x10b, true); // PE32
  view.setUint32(0x68, 0x100, true); // AddressOfEntryPoint
  view.setUint32(0x74, 0x400000, true); // ImageBase
  view.setUint32(0x78, 4, true); // SectionAlignment below the page size.
  view.setUint32(0x7c, 4, true); // FileAlignment matches SectionAlignment.
  view.setUint32(0x90, bytes.length, true); // SizeOfImage
  view.setUint32(0x94, 0x80, true); // SizeOfHeaders, below the code at the entry RVA.
  bytes[0x100] = 0xc3; // x86 near RET; the fixture is provided to the disassembler as data.
  return bytes;
};
