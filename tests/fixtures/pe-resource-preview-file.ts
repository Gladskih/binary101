"use strict";

import { MockFile } from "../helpers/mock-file.js";
import { buildResourceSection, RESOURCE_SECTION_RVA } from "./pe-resource-preview-section.js";

const PE_HEADER_OFFSET = 0x40;
const COFF_HEADER_SIZE = 20;
const OPTIONAL_HEADER_SIZE = 240;
const SECTION_HEADER_SIZE = 40;
const FILE_ALIGNMENT = 0x200;
const SECTION_ALIGNMENT = 0x1000;
const TEXT_SECTION_RVA = 0x1000;
const TEXT_SECTION_RAW_OFFSET = FILE_ALIGNMENT;
const TEXT_SECTION_RAW_SIZE = FILE_ALIGNMENT;
const RESOURCE_SECTION_RAW_OFFSET = TEXT_SECTION_RAW_OFFSET + TEXT_SECTION_RAW_SIZE;

const align = (value: number, alignment: number): number =>
  Math.ceil(value / alignment) * alignment;

const writeSectionName = (view: DataView, offset: number, name: string): void => {
  for (let index = 0; index < Math.min(name.length, 8); index += 1) {
    view.setUint8(offset + index, name.charCodeAt(index));
  }
};

export const createPeResourcePreviewFile = (): MockFile => {
  const resourceSection = buildResourceSection();
  const resourceSectionRawSize = align(resourceSection.length, FILE_ALIGNMENT);
  const sizeOfImage = RESOURCE_SECTION_RVA + align(resourceSection.length, SECTION_ALIGNMENT);
  const fileSize = RESOURCE_SECTION_RAW_OFFSET + resourceSectionRawSize;
  const bytes = new Uint8Array(fileSize).fill(0);
  const view = new DataView(bytes.buffer);

  view.setUint16(0x00, 0x5a4d, true);
  view.setUint32(0x3c, PE_HEADER_OFFSET, true);
  view.setUint32(PE_HEADER_OFFSET, 0x00004550, true);

  const coffOffset = PE_HEADER_OFFSET + 4;
  view.setUint16(coffOffset, 0x8664, true);
  view.setUint16(coffOffset + 2, 2, true);
  view.setUint16(coffOffset + 16, OPTIONAL_HEADER_SIZE, true);
  view.setUint16(coffOffset + 18, 0x0002, true);

  const optionalOffset = coffOffset + COFF_HEADER_SIZE;
  let pos = optionalOffset;
  view.setUint16(pos, 0x20b, true); pos += 2;
  view.setUint8(pos, 14); pos += 1;
  view.setUint8(pos, 0); pos += 1;
  view.setUint32(pos, TEXT_SECTION_RAW_SIZE, true); pos += 4;
  view.setUint32(pos, resourceSectionRawSize, true); pos += 4;
  view.setUint32(pos, 0, true); pos += 4;
  view.setUint32(pos, TEXT_SECTION_RVA, true); pos += 4;
  view.setUint32(pos, TEXT_SECTION_RVA, true); pos += 4;
  view.setBigUint64(pos, 0x140000000n, true); pos += 8;
  view.setUint32(pos, SECTION_ALIGNMENT, true); pos += 4;
  view.setUint32(pos, FILE_ALIGNMENT, true); pos += 4;
  view.setUint16(pos, 6, true); pos += 2;
  view.setUint16(pos, 0, true); pos += 2;
  view.setUint16(pos, 1, true); pos += 2;
  view.setUint16(pos, 0, true); pos += 2;
  view.setUint16(pos, 5, true); pos += 2;
  view.setUint16(pos, 1, true); pos += 2;
  view.setUint32(pos, 0, true); pos += 4;
  view.setUint32(pos, sizeOfImage, true); pos += 4;
  view.setUint32(pos, FILE_ALIGNMENT, true); pos += 4;
  view.setUint32(pos, 0, true); pos += 4;
  view.setUint16(pos, 2, true); pos += 2;
  view.setUint16(pos, 0, true); pos += 2;
  view.setBigUint64(pos, 0x100000n, true); pos += 8;
  view.setBigUint64(pos, 0x1000n, true); pos += 8;
  view.setBigUint64(pos, 0x100000n, true); pos += 8;
  view.setBigUint64(pos, 0x1000n, true); pos += 8;
  view.setUint32(pos, 0, true); pos += 4;
  view.setUint32(pos, 16, true); pos += 4;

  const resourceDirectoryOffset = pos + 2 * 8;
  view.setUint32(resourceDirectoryOffset, RESOURCE_SECTION_RVA, true);
  view.setUint32(resourceDirectoryOffset + 4, resourceSection.length, true);

  const sectionHeaderOffset = optionalOffset + OPTIONAL_HEADER_SIZE;
  writeSectionName(view, sectionHeaderOffset, ".text");
  view.setUint32(sectionHeaderOffset + 8, 1, true);
  view.setUint32(sectionHeaderOffset + 12, TEXT_SECTION_RVA, true);
  view.setUint32(sectionHeaderOffset + 16, TEXT_SECTION_RAW_SIZE, true);
  view.setUint32(sectionHeaderOffset + 20, TEXT_SECTION_RAW_OFFSET, true);
  view.setUint32(sectionHeaderOffset + 36, 0x60000020, true);

  const resourceSectionHeaderOffset = sectionHeaderOffset + SECTION_HEADER_SIZE;
  writeSectionName(view, resourceSectionHeaderOffset, ".rsrc");
  view.setUint32(resourceSectionHeaderOffset + 8, resourceSection.length, true);
  view.setUint32(resourceSectionHeaderOffset + 12, RESOURCE_SECTION_RVA, true);
  view.setUint32(resourceSectionHeaderOffset + 16, resourceSectionRawSize, true);
  view.setUint32(resourceSectionHeaderOffset + 20, RESOURCE_SECTION_RAW_OFFSET, true);
  view.setUint32(resourceSectionHeaderOffset + 36, 0x40000040, true);

  bytes[TEXT_SECTION_RAW_OFFSET] = 0xc3; // x86-64 `ret`
  bytes.set(resourceSection, RESOURCE_SECTION_RAW_OFFSET);

  return new MockFile(bytes, "resource-showcase.exe", "application/vnd.microsoft.portable-executable");
};
