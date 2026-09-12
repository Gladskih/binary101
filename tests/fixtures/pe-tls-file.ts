"use strict";

import { createPeWithSectionAndIatFixture } from "./sample-files-pe.js";
import { MockFile } from "../helpers/mock-file.js";

export const createPeWithPartialTlsCallback = (): MockFile => {
  const { bytes, rawImageEnd } = createPeWithSectionAndIatFixture();
  const view = new DataView(bytes.buffer);
  // Microsoft PE format: 4-byte signature + 20-byte COFF header;
  // PE32 data directories start at optional-header offset 96; TLS is entry 9.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
  const optionalOffset = view.getUint32(0x3c, true) + 4 + 20;
  const imageBase = view.getUint32(optionalOffset + 28, true);
  const sectionHeader = optionalOffset + view.getUint16(optionalOffset - 4, true);
  const sectionRva = view.getUint32(sectionHeader + 12, true);
  const sectionOffset = view.getUint32(sectionHeader + 20, true);
  const tableOffset = rawImageEnd - 6; // One full DWORD, then only two mapped bytes.
  const headerOffset = sectionOffset + 0x20;
  view.setUint32(optionalOffset + 96 + 9 * 8, sectionRva + 0x20, true);
  view.setUint32(optionalOffset + 96 + 9 * 8 + 4, 24, true);
  view.setUint32(headerOffset + 8, imageBase + sectionRva + 0x60, true);
  view.setUint32(headerOffset + 12, imageBase + sectionRva + tableOffset - sectionOffset, true);
  view.setUint32(tableOffset, imageBase + sectionRva + 0x100, true);
  view.setUint32(tableOffset + 4, imageBase + sectionRva + 0x180, true);
  return new MockFile(bytes, "partial-tls.exe", "application/vnd.microsoft.portable-executable");
};
