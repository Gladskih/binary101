import { createHeadersOnlyPeWithAlignedImageSize } from "./minimal-pe-headers.js";

export const createCoffLanguageSymbolTable = (
  name: string, ending: "terminated" | "truncated" = "terminated"
): Uint8Array<ArrayBuffer> => {
  // PE/COFF: 18-byte symbol record; long name at string-table offset 4.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-symbol-table
  const encoded = new TextEncoder().encode(name + (ending === "terminated" ? "\0" : ""));
  const bytes = new Uint8Array(18 + 4 + encoded.length);
  const view = new DataView(bytes.buffer);
  view.setUint32(4, 4, true);
  view.setInt16(12, 1, true);
  bytes[16] = 2; // IMAGE_SYM_CLASS_EXTERNAL.
  view.setUint32(18, 4 + encoded.length, true);
  bytes.set(encoded, 22);
  return bytes;
};

export const createPeCoffLanguageFile = (name: string): Uint8Array<ArrayBuffer> => {
  const header = createHeadersOnlyPeWithAlignedImageSize();
  const table = createCoffLanguageSymbolTable(name);
  const bytes = new Uint8Array(header.length + table.length);
  bytes.set(header);
  bytes.set(table, header.length);
  const view = new DataView(bytes.buffer);
  const coff = view.getUint32(0x3c, true) + 4;
  view.setUint32(coff + 8, header.length, true);
  view.setUint32(coff + 12, 1, true);
  return bytes;
};
