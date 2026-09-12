"use strict";

import { parseTlsDirectory32, parseTlsDirectory64 } from "../../analyzers/pe/directories/tls.js";
import type { FileRangeReader } from "../../analyzers/file-range-reader.js";
import type { PeDataDirectory, PeSection, RvaToOffset } from "../../analyzers/pe/types.js";
import { MockFile } from "../helpers/mock-file.js";

// Microsoft PE format, The TLS Directory: four VA fields followed by two DWORDs.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-tls-directory
export const createTlsMappingFixture = (pointerSize: 4 | 8) => {
  const bytes = new Uint8Array(512);
  const view = new DataView(bytes.buffer);
  const headerRva = 0x20;
  const tableRva = 0x80;
  const headerSize = pointerSize * 4 + 8;
  const directories: PeDataDirectory[] = [{ name: "TLS", rva: headerRva, size: headerSize }];
  const writePointer = (offset: number, value: bigint): void => {
    if (pointerSize === 4) view.setUint32(offset, Number(value), true);
    else view.setBigUint64(offset, value, true);
  };
  const section: PeSection = {
    name: { kind: "inline", value: ".data" }, virtualAddress: 0x60,
    virtualSize: 4, sizeOfRawData: 4, pointerToRawData: 0x60, characteristics: 0
  };
  writePointer(headerRva + pointerSize * 2, BigInt(section.virtualAddress));
  writePointer(headerRva + pointerSize * 3, BigInt(tableRva));
  return {
    bytes, view, headerRva, headerSize, tableRva, section, writePointer, directories,
    parse: (mapping: RvaToOffset = rva => rva, reader: FileRangeReader = new MockFile(bytes)) =>
      (pointerSize === 4 ? parseTlsDirectory32 : parseTlsDirectory64)(
        reader, directories, mapping, 0n, [section]
      )
  };
};
