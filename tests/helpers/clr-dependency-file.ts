"use strict";

import { createTinyPEHeader } from "../fixtures/minimal-pe-headers.js";
import { MockFile } from "./mock-file.js";

// PE32 offsets: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
// COR20/root/stream layout: ECMA-335 II.25.3.3, II.24.2.1, II.24.2.2, II.24.2.6.
export const clrDependencyFile = (): MockFile => {
  const bytes = new Uint8Array(0x400);
  bytes.set(createTinyPEHeader());
  const view = new DataView(bytes.buffer);
  const optional = 64 + 4 + 20;
  const clr = 0x180;
  const metadata = 0x200;
  view.setUint32(optional + 60, bytes.length, true);
  view.setUint32(optional + 92, 16, true);
  view.setUint32(optional + 96 + 14 * 8, clr, true);
  view.setUint32(optional + 96 + 14 * 8 + 4, 0x48, true);
  view.setUint32(clr, 0x48, true);
  view.setUint32(clr + 8, metadata, true);
  view.setUint32(clr + 12, 0x80, true);
  view.setUint32(metadata, 0x424a5342, true); // BSJB.
  view.setUint16(metadata + 4, 1, true);
  view.setUint16(metadata + 6, 1, true);
  view.setUint32(metadata + 12, 4, true);
  bytes.set(new TextEncoder().encode("v4\0\0"), metadata + 16);
  view.setUint16(metadata + 22, 1, true);
  view.setUint32(metadata + 24, 0x40, true);
  view.setUint32(metadata + 28, 24, true);
  bytes.set(new TextEncoder().encode("#~\0\0"), metadata + 32);
  bytes[metadata + 0x40 + 4] = 2;
  bytes[metadata + 0x40 + 7] = 1;
  return new MockFile(bytes, "dependency.dll");
};

export const changeDependencyU32 = (offset: number, value: number): MockFile => {
  const bytes = clrDependencyFile().data;
  new DataView(bytes.buffer).setUint32(offset, value, true);
  return new MockFile(bytes, "modified.dll");
};

export const clrAssemblyDependencyFile = (): MockFile => {
  const bytes = clrDependencyFile().data;
  const view = new DataView(bytes.buffer);
  const metadata = 0x200;
  const table = metadata + 0x40;
  const row = table + 28;
  view.setUint32(0x18c, 0xc0, true);
  view.setUint16(metadata + 22, 2, true);
  view.setUint32(metadata + 28, 52, true);
  view.setUint32(metadata + 36, 0x80, true);
  view.setUint32(metadata + 40, 12, true);
  bytes.set(new TextEncoder().encode("#Strings\0"), metadata + 44);
  view.setUint32(table + 12, 1, true); // Valid table mask bit 32 = Assembly (ECMA-335 II.22.2).
  view.setUint32(table + 24, 1, true);
  [1, 2, 3, 4].forEach((component, index) => view.setUint16(row + 4 + index * 2, component, true));
  view.setUint16(row + 18, 1, true);
  bytes.set(new TextEncoder().encode("\0Library\0"), metadata + 0x80);
  return new MockFile(bytes, "Library.dll");
};
