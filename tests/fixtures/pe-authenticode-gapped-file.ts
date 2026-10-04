"use strict";

import assert from "node:assert/strict";
import { isPeWindowsCore, parsePeHeaders } from "../../analyzers/pe/core/index.js";
import { createHeadersOnlyPeWithAlignedImageSize } from "./minimal-pe-headers.js";
import { MockFile } from "../helpers/mock-file.js";

// PE/COFF Optional Header, Section Table and Attribute Certificate Table layouts:
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
const writeSection = (view: DataView, offset: number, rawOffset: number, address: number): void => {
  new Uint8Array(view.buffer, offset, 5).set(new TextEncoder().encode(".text"));
  view.setUint32(offset + 8, 0x200, true);
  view.setUint32(offset + 12, address, true);
  view.setUint32(offset + 16, 0x200, true);
  view.setUint32(offset + 20, rawOffset, true);
  view.setUint32(offset + 36, 0x60000020, true);
};

export const createGappedAuthenticodePeFile = (
  headerGapSize: number,
  sectionGapSize: number
): MockFile => {
  const firstSectionOffset = 0x200 + headerGapSize;
  const secondSectionOffset = firstSectionOffset + 0x200 + sectionGapSize;
  const certificateOffset = secondSectionOffset + 0x200;
  const bytes = new Uint8Array(certificateOffset + 16);
  bytes.forEach((_, index) => { bytes[index] = (index * 19 + 7) & 0xff; });
  bytes.set(createHeadersOnlyPeWithAlignedImageSize());
  const view = new DataView(bytes.buffer);
  const peOffset = view.getUint32(0x3c, true);
  const optionalOffset = peOffset + 24;
  const sectionTableOffset = optionalOffset + view.getUint16(peOffset + 20, true);
  view.setUint16(peOffset + 6, 2, true);
  view.setUint32(optionalOffset + 56, 0x3000, true);
  view.setUint16(optionalOffset + 68, 3, true);
  view.setUint32(optionalOffset + 92, 16, true);
  view.setUint32(optionalOffset + 96 + 4 * 8, certificateOffset, true);
  view.setUint32(optionalOffset + 96 + 4 * 8 + 4, 16, true);
  writeSection(view, sectionTableOffset, firstSectionOffset, 0x1000);
  writeSection(view, sectionTableOffset + 40, secondSectionOffset, 0x2000);
  // An opaque WIN_CERTIFICATE payload; only its excluded file range matters for these hash tests.
  view.setUint32(certificateOffset, 16, true);
  view.setUint16(certificateOffset + 4, 0x200, true);
  view.setUint16(certificateOffset + 6, 2, true);
  return new MockFile(bytes, "gapped-authenticode.exe");
};

export const createParsedGappedAuthenticodeFixture = async (
  headerGapSize: number,
  sectionGapSize: number
) => {
  const file = createGappedAuthenticodePeFile(headerGapSize, sectionGapSize);
  const core = await parsePeHeaders(file);
  assert.ok(core && isPeWindowsCore(core));
  const securityDir = core.dataDirs.find(directory => directory.name === "SECURITY");
  assert.ok(securityDir);
  return { file, core, securityDir };
};
