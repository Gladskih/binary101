"use strict";

import { MockFile } from "./mock-file.js";
import { createNativeAotMetadataFixture } from "./pe-native-aot-metadata-fixture.js";
import { createPeNativeAotInitializerFixture } from "./pe-native-aot-initializer-fixture.js";

const ELF_HEADER_SIZE = 64;
const PROGRAM_HEADER_SIZE = 56;
const SECTION_HEADER_SIZE = 64;
const PAYLOAD_ADDRESS = 0x1000;
const RELOCATION_OFFSET = 0x2000;
const RELOCATION_ENTRY_SIZE = 24;
const SECTION_NAMES = new TextEncoder().encode("\0.rela.dyn\0.shstrtab\0");

export interface ElfNativeAotFixture {
  bytes: Uint8Array;
  file: MockFile;
  headerAddress: number;
  modulePointerAddress: number;
  relocationOffset: number;
  relocationCount: number;
  sectionHeaderOffset: number;
}

const writeElfHeader = (view: DataView, sectionHeaderOffset: number): void => {
  view.setUint32(0, 0x7f45_4c46, false);
  view.setUint8(4, 2);
  view.setUint8(5, 1);
  view.setUint8(6, 1);
  view.setUint16(16, 3, true);
  view.setUint16(18, 62, true);
  view.setUint32(20, 1, true);
  view.setBigUint64(32, BigInt(ELF_HEADER_SIZE), true);
  view.setBigUint64(40, BigInt(sectionHeaderOffset), true);
  view.setUint16(52, ELF_HEADER_SIZE, true);
  view.setUint16(54, PROGRAM_HEADER_SIZE, true);
  view.setUint16(56, 1, true);
  view.setUint16(58, SECTION_HEADER_SIZE, true);
  view.setUint16(60, 3, true);
  view.setUint16(62, 2, true);
};

const writeLoadProgramHeader = (view: DataView, fileSize: number): void => {
  view.setUint32(ELF_HEADER_SIZE, 1, true);
  view.setUint32(ELF_HEADER_SIZE + 4, 6, true);
  view.setBigUint64(ELF_HEADER_SIZE + 32, BigInt(fileSize), true);
  view.setBigUint64(ELF_HEADER_SIZE + 40, BigInt(fileSize), true);
  view.setBigUint64(ELF_HEADER_SIZE + 48, 0x1000n, true);
};

const writeRelaSection = (
  view: DataView,
  sectionHeaderOffset: number,
  relocationSize: number
): void => {
  const offset = sectionHeaderOffset + SECTION_HEADER_SIZE;
  view.setUint32(offset, 1, true);
  view.setUint32(offset + 4, 4, true);
  view.setBigUint64(offset + 8, 2n, true);
  view.setBigUint64(offset + 16, BigInt(RELOCATION_OFFSET), true);
  view.setBigUint64(offset + 24, BigInt(RELOCATION_OFFSET), true);
  view.setBigUint64(offset + 32, BigInt(relocationSize), true);
  view.setBigUint64(offset + 48, 8n, true);
  view.setBigUint64(offset + 56, BigInt(RELOCATION_ENTRY_SIZE), true);
};

const writeSectionNames = (bytes: Uint8Array, sectionHeaderOffset: number): void => {
  const namesOffset = sectionHeaderOffset + SECTION_HEADER_SIZE * 3;
  const offset = sectionHeaderOffset + SECTION_HEADER_SIZE * 2;
  const view = new DataView(bytes.buffer);
  view.setUint32(offset, 11, true);
  view.setUint32(offset + 4, 3, true);
  view.setBigUint64(offset + 24, BigInt(namesOffset), true);
  view.setBigUint64(offset + 32, BigInt(SECTION_NAMES.byteLength), true);
  view.setBigUint64(offset + 48, 1n, true);
  bytes.set(SECTION_NAMES, namesOffset);
};

export const createElfNativeAotInitializerFixture = () => {
  const nativeAot = createPeNativeAotInitializerFixture();
  const fixture = createElfNativeAotFixture(nativeAot);
  const view = new DataView(fixture.bytes.buffer);
  // ELF64 Phdr: p_flags follows uint32 p_type; PF_R | PF_X = 5.
  // https://gabi.xinuos.com/elf/07-pheader.html
  view.setUint32(ELF_HEADER_SIZE + Uint32Array.BYTES_PER_ELEMENT, 5, true);
  // Intel SDM Vol. 2, RET: C3 is a near return; the seed is one complete instruction.
  fixture.bytes[nativeAot.codeRva] = 0xc3;
  return { ...fixture, initializerTargetRva: nativeAot.codeRva,
    file: new MockFile(fixture.bytes, "native-aot.elf", "application/x-elf") };
};

export const createElfNativeAotFixture = (
  nativeAot = createNativeAotMetadataFixture()
): ElfNativeAotFixture => {
  const relocationSites = nativeAot.relocations.blocks[0]!.entries
    .filter(entry => entry.type !== 0)
    .map(entry => nativeAot.relocations.blocks[0]!.pageRva + entry.offset);
  const relocationSize = relocationSites.length * RELOCATION_ENTRY_SIZE;
  const sectionHeaderOffset = RELOCATION_OFFSET + relocationSize;
  const fileSize = sectionHeaderOffset + SECTION_HEADER_SIZE * 3 + SECTION_NAMES.byteLength;
  const bytes = new Uint8Array(fileSize);
  bytes.set(nativeAot.bytes, PAYLOAD_ADDRESS);
  const view = new DataView(bytes.buffer);
  writeElfHeader(view, sectionHeaderOffset);
  writeLoadProgramHeader(view, fileSize);
  relocationSites.forEach((site, index) => {
    const offset = RELOCATION_OFFSET + index * RELOCATION_ENTRY_SIZE;
    const rawTarget = nativeAot.view.getBigUint64(site - PAYLOAD_ADDRESS, true);
    view.setBigUint64(offset, BigInt(site), true);
    view.setBigUint64(offset + 8, 8n, true);
    view.setBigInt64(offset + 16, rawTarget - nativeAot.core.opt.ImageBase, true);
  });
  writeRelaSection(view, sectionHeaderOffset, relocationSize);
  writeSectionNames(bytes, sectionHeaderOffset);
  return {
    bytes,
    file: new MockFile(bytes, "native-aot.elf", "application/x-elf"),
    headerAddress: nativeAot.headerRva,
    modulePointerAddress: nativeAot.modulePointerRva,
    relocationOffset: RELOCATION_OFFSET,
    relocationCount: relocationSites.length,
    sectionHeaderOffset
  };
};
