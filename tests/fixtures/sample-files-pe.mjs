"use strict";

import { MockFile } from "../helpers/mock-file.mjs";

export const createPeWithSectionAndIat = () => {
  const peHeaderOffset = 0x40;
  const coffHeaderSize = 20;
  const optionalHeaderSize = 224;

  const numberOfSections = 1;
  const fileAlignment = 0x200;
  const sectionAlignment = 0x1000;
  const sectionVirtualAddress = 0x1000;
  const sectionVirtualSize = 0x200;
  const sizeOfRawData = fileAlignment;
  const pointerToRawData = fileAlignment;
  const addressOfEntryPoint = 0x1100;
  const iatRva = 0x1100;
  const iatSize = 0x40;
  const sizeOfImage = 0x2000;
  const overlaySize = 0x20;
  const fileSize = pointerToRawData + sizeOfRawData + overlaySize;

  const buffer = new ArrayBuffer(fileSize);
  const view = new DataView(buffer);

  view.setUint16(0x00, 0x5a4d, true);
  view.setUint32(0x3c, peHeaderOffset, true);

  const peSignatureOffset = peHeaderOffset;
  view.setUint32(peSignatureOffset, 0x00004550, true);

  const coffOffset = peSignatureOffset + 4;
  view.setUint16(coffOffset, 0x014c, true);
  view.setUint16(coffOffset + 2, numberOfSections, true);
  view.setUint32(coffOffset + 4, 0x65c0e6a0, true);
  view.setUint32(coffOffset + 8, 0, true);
  view.setUint32(coffOffset + 12, 0, true);
  view.setUint16(coffOffset + 16, optionalHeaderSize, true);
  view.setUint16(coffOffset + 18, 0x0002, true);

  const optionalOffset = coffOffset + coffHeaderSize;
  let optPos = optionalOffset;
  view.setUint16(optPos, 0x10b, true); optPos += 2;
  view.setUint8(optPos, 14); optPos += 1;
  view.setUint8(optPos, 0); optPos += 1;
  view.setUint32(optPos, sizeOfRawData, true); optPos += 4;
  view.setUint32(optPos, sizeOfRawData, true); optPos += 4;
  view.setUint32(optPos, 0, true); optPos += 4;
  view.setUint32(optPos, addressOfEntryPoint, true); optPos += 4;
  view.setUint32(optPos, sectionVirtualAddress, true); optPos += 4;
  view.setUint32(optPos, sectionVirtualAddress, true); optPos += 4;
  view.setUint32(optPos, 0x00400000, true); optPos += 4;
  view.setUint32(optPos, sectionAlignment, true); optPos += 4;
  view.setUint32(optPos, fileAlignment, true); optPos += 4;
  view.setUint16(optPos, 6, true);
  view.setUint16(optPos + 2, 0, true);
  optPos += 4;
  view.setUint16(optPos, 1, true);
  view.setUint16(optPos + 2, 0, true);
  optPos += 4;
  view.setUint16(optPos, 5, true);
  view.setUint16(optPos + 2, 1, true);
  optPos += 4;
  view.setUint32(optPos, 0, true); optPos += 4;
  view.setUint32(optPos, sizeOfImage, true); optPos += 4;
  view.setUint32(optPos, fileAlignment, true); optPos += 4;
  view.setUint32(optPos, 0, true); optPos += 4;
  view.setUint16(optPos, 2, true); optPos += 2;
  view.setUint16(optPos, 0, true); optPos += 2;
  view.setUint32(optPos, 0x100000, true); optPos += 4;
  view.setUint32(optPos, 0x1000, true); optPos += 4;
  view.setUint32(optPos, 0x100000, true); optPos += 4;
  view.setUint32(optPos, 0x1000, true); optPos += 4;
  view.setUint32(optPos, 0, true); optPos += 4;
  view.setUint32(optPos, 16, true); optPos += 4;

  const dataDirectoryOffset = optPos + 12 * 8;
  view.setUint32(dataDirectoryOffset, iatRva, true);
  view.setUint32(dataDirectoryOffset + 4, iatSize, true);

  const sectionHeaderOffset = optionalOffset + optionalHeaderSize;
  const nameBytes = [0x2e, 0x74, 0x65, 0x78, 0x74];
  for (let index = 0; index < nameBytes.length; index += 1) {
    view.setUint8(sectionHeaderOffset + index, nameBytes[index]);
  }
  view.setUint32(sectionHeaderOffset + 8, sectionVirtualSize, true);
  view.setUint32(sectionHeaderOffset + 12, sectionVirtualAddress, true);
  view.setUint32(sectionHeaderOffset + 16, sizeOfRawData, true);
  view.setUint32(sectionHeaderOffset + 20, pointerToRawData, true);
  view.setUint32(sectionHeaderOffset + 36, 0x60000020, true);

  return new Uint8Array(buffer);
};

export const createPeFile = () =>
  new MockFile(createPeWithSectionAndIat(), "sample.exe", "application/vnd.microsoft.portable-executable");
