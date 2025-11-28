"use strict";

/* eslint-disable max-lines */

import { readAsciiString, collectPrintableRuns } from "../../binary-utils.js";
import { DD_NAMES } from "./constants.js";
import type {
  PeCoffHeader,
  PeDataDirectory,
  PeDosHeader,
  PeOptionalHeader,
  PeSection,
  RvaToOffset
} from "./types.js";

function createRvaToOffsetMapper(sections: PeSection[]): RvaToOffset {
  const spans = sections.map(section => {
    const virtualAddress = section.virtualAddress >>> 0;
    const virtualSize = Math.max(section.virtualSize >>> 0, section.sizeOfRawData >>> 0);
    const fileOffset = section.pointerToRawData >>> 0;
    return { vaStart: virtualAddress, vaEnd: (virtualAddress + virtualSize) >>> 0, fileOffset };
  });
  return relativeVirtualAddress => {
    const normalized = relativeVirtualAddress >>> 0;
    for (const span of spans) {
      if (normalized >= span.vaStart && normalized < span.vaEnd) {
        return (span.fileOffset + (normalized - span.vaStart)) >>> 0;
      }
    }
    return null;
  };
}

export async function parseDosHeaderAndStub(
  file: File,
  headView: DataView,
  peHeaderOffset: number
): Promise<PeDosHeader> {
  const dos: PeDosHeader = {
    e_magic: readAsciiString(headView, 0, 2),
    e_cblp: headView.getUint16(0x02, true),
    e_cp: headView.getUint16(0x04, true),
    e_crlc: headView.getUint16(0x06, true),
    e_cparhdr: headView.getUint16(0x08, true),
    e_minalloc: headView.getUint16(0x0a, true),
    e_maxalloc: headView.getUint16(0x0c, true),
    e_ss: headView.getUint16(0x0e, true),
    e_sp: headView.getUint16(0x10, true),
    e_csum: headView.getUint16(0x12, true),
    e_ip: headView.getUint16(0x14, true),
    e_cs: headView.getUint16(0x16, true),
    e_lfarlc: headView.getUint16(0x18, true),
    e_ovno: headView.getUint16(0x1a, true),
    e_res: [
      headView.getUint16(0x1c, true),
      headView.getUint16(0x1e, true),
      headView.getUint16(0x20, true),
      headView.getUint16(0x22, true)
    ],
    e_oemid: headView.getUint16(0x24, true),
    e_oeminfo: headView.getUint16(0x26, true),
    e_res2: Array.from({ length: 10 }, (_, index) => headView.getUint16(0x28 + index * 2, true)),
    e_lfanew: peHeaderOffset,
    stub: { kind: "none", note: "" }
  };
  if (peHeaderOffset > 0x40) {
    const stubLength = Math.min(peHeaderOffset - 0x40, 64 * 1024);
    const stubBytes = new Uint8Array(await file.slice(0x40, 0x40 + stubLength).arrayBuffer());
    const printableRuns = collectPrintableRuns(stubBytes, 12);
    const classicMessage = printableRuns.find(text => /this program cannot be run in dos mode/i.test(text));
    if (classicMessage) dos.stub = { kind: "standard", note: "classic DOS message", strings: [classicMessage] };
    else if (printableRuns.length) {
      dos.stub = { kind: "non-standard", note: "printable text", strings: printableRuns.slice(0, 4) };
    }
  }
  return dos;
}

export async function parseCoffHeader(file: File, peHeaderOffset: number): Promise<PeCoffHeader | null> {
  const headerView = new DataView(await file.slice(peHeaderOffset, peHeaderOffset + 24).arrayBuffer());
  if (headerView.byteLength < 4) return null;
  const signature =
    String.fromCharCode(headerView.getUint8(0)) +
    String.fromCharCode(headerView.getUint8(1)) +
    String.fromCharCode(headerView.getUint8(2)) +
    String.fromCharCode(headerView.getUint8(3));
  if (signature !== "PE\0\0") return null;
  const coffOffset = 4;
  const u16 = (off: number): number =>
    off + 2 <= headerView.byteLength ? headerView.getUint16(off, true) : 0;
  const u32 = (off: number): number =>
    off + 4 <= headerView.byteLength ? headerView.getUint32(off, true) : 0;
  const Machine = u16(coffOffset + 0);
  const NumberOfSections = u16(coffOffset + 2);
  const TimeDateStamp = u32(coffOffset + 4);
  const PointerToSymbolTable = u32(coffOffset + 8);
  const NumberOfSymbols = u32(coffOffset + 12);
  const SizeOfOptionalHeader = u16(coffOffset + 16);
  const Characteristics = u16(coffOffset + 18);
  return {
    Machine,
    NumberOfSections,
    TimeDateStamp,
    PointerToSymbolTable,
    NumberOfSymbols,
    SizeOfOptionalHeader,
    Characteristics
  };
}

export async function parseOptionalHeaderAndDirectories(
  file: File,
  peHeaderOffset: number,
  sizeOfOptionalHeader: number
): Promise<{
  optOff: number;
  optSize: number;
  ddStartRel: number;
  ddCount: number;
  dataDirs: PeDataDirectory[];
  opt: PeOptionalHeader;
}> {
  const optionalHeaderOffset = peHeaderOffset + 24;
  const maxReadable = Math.max(0, Math.min(file.size - optionalHeaderOffset, 0x600));
  const declaredSize = Math.min(sizeOfOptionalHeader, maxReadable);
  const minimumIntent = Math.min(0x80, maxReadable);
  const viewSize = Math.min(maxReadable, Math.max(declaredSize, minimumIntent));
  const optionalHeaderView = new DataView(
    await file.slice(optionalHeaderOffset, optionalHeaderOffset + viewSize).arrayBuffer()
  );
  let position = 0;
  const has = (length: number): boolean => position + length <= optionalHeaderView.byteLength;
  const read = <T>(length: number, fn: () => T, fallback: T): T => {
    if (!has(length)) return fallback;
    return fn();
  };

  const Magic = read(2, () => optionalHeaderView.getUint16(position, true), 0); position += 2;
  const isPlus = Magic === 0x20b, is32 = Magic === 0x10b || Magic === 0x107;
  const linker = read<[number, number]>(2, () => [
    optionalHeaderView.getUint8(position),
    optionalHeaderView.getUint8(position + 1)
  ], [0, 0]);
  const [LinkerMajor, LinkerMinor] = linker; position += 2;
  const SizeOfCodeVal = read(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const SizeOfInitializedDataVal = read(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const SizeOfUninitializedDataVal = read(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const AddressOfEntryPointVal = read(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const BaseOfCodeVal = read(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  let BaseOfData: number | undefined;
  if (is32) {
    BaseOfData = read(4, () => optionalHeaderView.getUint32(position, true), 0);
    position += 4;
  }
  const ImageBase = read(
    isPlus ? 8 : 4,
    () => isPlus
      ? Number(optionalHeaderView.getBigUint64(position, true))
      : optionalHeaderView.getUint32(position, true),
    0
  );
  position += isPlus ? 8 : 4;
  const SectionAlignmentVal = read(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const FileAlignmentVal = read(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const osVersion = read<[number, number]>(4, () => [
    optionalHeaderView.getUint16(position, true),
    optionalHeaderView.getUint16(position + 2, true)
  ], [0, 0]);
  const [OSVersionMajor, OSVersionMinor] = osVersion;
  position += 4;
  const imageVersion = read<[number, number]>(4, () => [
    optionalHeaderView.getUint16(position, true),
    optionalHeaderView.getUint16(position + 2, true)
  ], [0, 0]);
  const [ImageVersionMajor, ImageVersionMinor] = imageVersion;
  position += 4;
  const subsystemVersion = read<[number, number]>(4, () => [
    optionalHeaderView.getUint16(position, true),
    optionalHeaderView.getUint16(position + 2, true)
  ], [0, 0]);
  const [SubsystemVersionMajor, SubsystemVersionMinor] = subsystemVersion;
  position += 4;
  const Win32VersionValueVal = read(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const SizeOfImageVal = read(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const SizeOfHeadersVal = read(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const CheckSumVal = read(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const SubsystemVal = read(2, () => optionalHeaderView.getUint16(position, true), 0);
  position += 2;
  const DllCharacteristicsVal = read(2, () => optionalHeaderView.getUint16(position, true), 0);
  position += 2;
  const SizeOfStackReserve = read(
    isPlus ? 8 : 4,
    () => isPlus
      ? Number(optionalHeaderView.getBigUint64(position, true))
      : optionalHeaderView.getUint32(position, true),
    0
  );
  position += isPlus ? 8 : 4;
  const SizeOfStackCommit = read(
    isPlus ? 8 : 4,
    () => isPlus
      ? Number(optionalHeaderView.getBigUint64(position, true))
      : optionalHeaderView.getUint32(position, true),
    0
  );
  position += isPlus ? 8 : 4;
  const SizeOfHeapReserve = read(
    isPlus ? 8 : 4,
    () => isPlus
      ? Number(optionalHeaderView.getBigUint64(position, true))
      : optionalHeaderView.getUint32(position, true),
    0
  );
  position += isPlus ? 8 : 4;
  const SizeOfHeapCommit = read(
    isPlus ? 8 : 4,
    () => isPlus
      ? Number(optionalHeaderView.getBigUint64(position, true))
      : optionalHeaderView.getUint32(position, true),
    0
  );
  position += isPlus ? 8 : 4;
  const LoaderFlagsVal = read(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const NumberOfRvaAndSizesVal = read(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const ddStartRel = position;
  const ddCount = Math.min(
    16,
    NumberOfRvaAndSizesVal,
    Math.max(0, Math.floor((optionalHeaderView.byteLength - position) / 8))
  );
  const dataDirs: PeDataDirectory[] = [];
  for (let index = 0; index < ddCount; index++) {
    const entryOffset = position + index * 8;
    const rva = optionalHeaderView.getUint32(entryOffset, true);
    const size = optionalHeaderView.getUint32(entryOffset + 4, true);
    dataDirs.push({ index, name: DD_NAMES[index] || "", rva, size });
  }
  const consumedSize = Math.min(optionalHeaderView.byteLength, position + ddCount * 8);
  const optSize = Math.max(consumedSize, declaredSize);
  const opt: PeOptionalHeader = {
    Magic,
    isPlus,
    is32,
    LinkerMajor,
    LinkerMinor,
    SizeOfCode: SizeOfCodeVal,
    SizeOfInitializedData: SizeOfInitializedDataVal,
    SizeOfUninitializedData: SizeOfUninitializedDataVal,
    AddressOfEntryPoint: AddressOfEntryPointVal,
    BaseOfCode: BaseOfCodeVal,
    ...(BaseOfData !== undefined ? { BaseOfData } : {}),
    ImageBase,
    SectionAlignment: SectionAlignmentVal,
    FileAlignment: FileAlignmentVal,
    OSVersionMajor,
    OSVersionMinor,
    ImageVersionMajor,
    ImageVersionMinor,
    SubsystemVersionMajor,
    SubsystemVersionMinor,
    Win32VersionValue: Win32VersionValueVal,
    SizeOfImage: SizeOfImageVal,
    SizeOfHeaders: SizeOfHeadersVal,
    CheckSum: CheckSumVal,
    Subsystem: SubsystemVal,
    DllCharacteristics: DllCharacteristicsVal,
    SizeOfStackReserve: SizeOfStackReserve as number,
    SizeOfStackCommit: SizeOfStackCommit as number,
    SizeOfHeapReserve: SizeOfHeapReserve as number,
    SizeOfHeapCommit: SizeOfHeapCommit as number,
    LoaderFlags: LoaderFlagsVal,
    NumberOfRvaAndSizes: NumberOfRvaAndSizesVal
  };
  return { optOff: optionalHeaderOffset, optSize, ddStartRel, ddCount, dataDirs, opt };
}

export async function parseSectionHeaders(
  file: File,
  optionalHeaderOffset: number,
  sizeOfOptionalHeader: number,
  numberOfSections: number
): Promise<{ sections: PeSection[]; rvaToOff: RvaToOffset; sectOff: number }> {
  const sectionHeadersOffset = optionalHeaderOffset + sizeOfOptionalHeader;
  const sectionHeadersView = new DataView(
    await file.slice(sectionHeadersOffset, sectionHeadersOffset + numberOfSections * 40).arrayBuffer()
  );
  const sections: PeSection[] = [];
  for (let sectionIndex = 0; sectionIndex < numberOfSections; sectionIndex += 1) {
    const baseOffset = sectionIndex * 40;
    if (sectionHeadersView.byteLength < baseOffset + 40) break;
    let name = "";
    for (let nameIndex = 0; nameIndex < 8; nameIndex += 1) {
      const codePoint = sectionHeadersView.getUint8(baseOffset + nameIndex);
      if (codePoint === 0) break;
      name += String.fromCharCode(codePoint);
    }
    const virtualSize = sectionHeadersView.getUint32(baseOffset + 8, true);
    const virtualAddress = sectionHeadersView.getUint32(baseOffset + 12, true);
    const sizeOfRawData = sectionHeadersView.getUint32(baseOffset + 16, true);
    const pointerToRawData = sectionHeadersView.getUint32(baseOffset + 20, true);
    const characteristics = sectionHeadersView.getUint32(baseOffset + 36, true);
    sections.push({
      name: name || "(unnamed)",
      virtualSize,
      virtualAddress,
      sizeOfRawData,
      pointerToRawData,
      characteristics
    });
  }
  const rvaToOff = createRvaToOffsetMapper(sections);
  return { sections, rvaToOff, sectOff: sectionHeadersOffset };
}
