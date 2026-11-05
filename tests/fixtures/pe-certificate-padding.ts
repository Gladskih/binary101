"use strict";

import { MockFile } from "../helpers/mock-file.js";
import { parseSecurityDirectory } from "../../analyzers/pe/security/index.js";
import { createPeWithSectionAndIatFixture } from "./sample-files-pe.js";

export const createCertificatePaddingFixture = async (imageEnd = 116, certificateStart = 120) => {
  // PE/COFF: an 8-byte WIN_CERTIFICATE header, quadword-aligned table entries.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-attribute-certificate-table-image-only
  const bytes = new Uint8Array(certificateStart + 8);
  const view = new DataView(bytes.buffer);
  view.setUint32(certificateStart, 8, true);
  view.setUint16(certificateStart + 4, 0x0200, true);
  view.setUint16(certificateStart + 6, 0x0001, true);
  const file = new MockFile(bytes, "certificate-padding.exe");
  const dataDirs = [{ name: "SECURITY", rva: certificateStart, size: 8 }];
  return {
    bytes, file, security: await parseSecurityDirectory(file, dataDirs),
    inputs: {
      file, reader: file, optionalHeaderOffset: 0, optionalHeaderSize: 0, sectionCount: 0,
      declaredSizeOfHeaders: imageEnd, sections: [], dataDirs,
      pointerToSymbolTable: 0, numberOfSymbols: 0
    }
  };
};

export const createPeWithCertificatePadding = (): Uint8Array => {
  const fixture = createPeWithSectionAndIatFixture();
  const bytes = fixture.bytes.slice(0, fixture.rawImageEnd + 8);
  const view = new DataView(bytes.buffer);
  const coffOffset = view.getUint32(0x3c, true) + 4;
  const optionalOffset = coffOffset + 20;
  // PE32: data directories start at +96, SECURITY is entry 4; SizeOfRawData is +16.
  // Leave four zero bytes between a short final section and the certificate table.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
  view.setUint32(
    optionalOffset + view.getUint16(coffOffset + 16, true) + 16,
    fixture.fileAlignment - 4, true
  );
  view.setUint32(optionalOffset + 96 + 4 * 8, fixture.rawImageEnd, true);
  view.setUint32(optionalOffset + 96 + 4 * 8 + 4, 8, true);
  view.setUint32(fixture.rawImageEnd, 8, true);
  view.setUint16(fixture.rawImageEnd + 4, 0x0200, true);
  view.setUint16(fixture.rawImageEnd + 6, 0x0001, true);
  return bytes;
};
