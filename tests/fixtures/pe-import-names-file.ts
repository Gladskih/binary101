"use strict";

import { createHeadersOnlyPeWithAlignedImageSize } from "./minimal-pe-headers.js";

export const createPeImportNamesFile = (
  mangledName = "??$square@H@demo@@YAHH@Z"
): Uint8Array<ArrayBuffer> => {
  const bytes = new Uint8Array(8192);
  bytes.set(createHeadersOnlyPeWithAlignedImageSize());
  const view = new DataView(bytes.buffer);
  const optional = view.getUint32(0x3c, true) + 24;
  // PE32 directory indices 1 (import), 13 (delay), and header RVA identity mapping:
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
  view.setUint32(optional + 60, bytes.length, true);
  view.setUint32(optional + 92, 16, true);
  view.setUint32(optional + 96 + 8, 512, true);
  view.setUint32(optional + 100 + 8, 40, true);
  view.setUint32(optional + 96 + 13 * 8, 576, true);
  view.setUint32(optional + 100 + 13 * 8, 64, true);
  view.setUint32(512, 1024, true);
  view.setUint32(512 + 12, 700, true);
  view.setUint32(512 + 16, 1024, true);
  view.setUint32(576, 1, true); // dlattrRva: delay descriptor fields contain RVAs.
  view.setUint32(576 + 4, 720, true);
  view.setUint32(576 + 12, 2048, true);
  view.setUint32(576 + 16, 2048, true);
  const encoder = new TextEncoder();
  bytes.set(encoder.encode("eager.dll\0"), 700);
  bytes.set(encoder.encode("delayed.dll\0"), 720);
  const names = ["Sleep", mangledName, "?f@@YAHH@Ztail", "Literal&lt;<"];
  names.forEach((name, index) => {
    view.setUint16(4096 + index * 128, index, true);
    bytes.set(encoder.encode(`${name}\0`), 4098 + index * 128);
  });
  for (const table of [1024, 2048]) {
    for (let index = 0; index < 251; index += 1) {
      view.setUint32(table + index * 4, 4096 + (index < 250 ? 0 : 1) * 128, true);
    }
  }
  return bytes;
};

export const createImportNameThunksFile = (
  width: number, ending: "terminated" | "truncated"
): Uint8Array<ArrayBuffer> => {
  const name = "?f@@YAHH@Z";
  // PE32/PE32+ thunks point to a two-byte hint followed by a NUL-terminated name.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#hintname-table
  const hintNameRva = 32;
  const bytes = new Uint8Array(hintNameRva + 2 + name.length + (ending === "terminated" ? 1 : 0));
  const view = new DataView(bytes.buffer);
  if (width === 4) view.setUint32(8, hintNameRva, true);
  else view.setBigUint64(8, BigInt(hintNameRva), true);
  bytes.set(new TextEncoder().encode(name), hintNameRva + 2);
  return bytes;
};
