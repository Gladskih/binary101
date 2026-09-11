"use strict";

import { createHeadersOnlyPeWithAlignedImageSize } from "./minimal-pe-headers.js";

export const createPagedPeExportsFile = (): Uint8Array<ArrayBuffer> => {
  const bytes = new Uint8Array(4096);
  bytes.set(createHeadersOnlyPeWithAlignedImageSize());
  const view = new DataView(bytes.buffer);
  const optionalHeader = view.getUint32(0x3c, true) + 24;
  const directory = 512;
  const eat = 1024;
  const namePointers = 2200;
  const ordinals = 2210;
  // PE32 optional-header and export-directory offsets:
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
  view.setUint32(optionalHeader + 60, bytes.length, true);
  view.setUint32(optionalHeader + 92, 16, true);
  view.setUint32(optionalHeader + 96, directory, true);
  view.setUint32(optionalHeader + 100, 40, true);
  view.setUint32(directory + 16, 1, true);
  view.setUint32(directory + 20, 251, true); // One entry beyond the UI page size.
  view.setUint32(directory + 24, 2, true);
  view.setUint32(directory + 28, eat, true);
  view.setUint32(directory + 32, namePointers, true);
  view.setUint32(directory + 36, ordinals, true);
  view.setUint32(namePointers, 2300, true);
  view.setUint32(namePointers + 4, 2320, true);
  view.setUint16(ordinals, 250, true);
  view.setUint16(ordinals + 2, 250, true);
  view.setUint32(eat + 250 * 4, 3000, true);
  bytes.set(new TextEncoder().encode("Alpha<\0"), 2300);
  bytes.set(new TextEncoder().encode("Beta&lt;\0"), 2320);
  return bytes;
};
