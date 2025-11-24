"use strict";

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
  const signature =
    String.fromCharCode(headerView.getUint8(0)) +
    String.fromCharCode(headerView.getUint8(1)) +
    String.fromCharCode(headerView.getUint8(2)) +
    String.fromCharCode(headerView.getUint8(3));
  if (signature !== "PE\0\0") return null;
  const coffOffset = 4;
  const Machine = headerView.getUint16(coffOffset + 0, true);
  const NumberOfSections = headerView.getUint16(coffOffset + 2, true);
  const TimeDateStamp = headerView.getUint32(coffOffset + 4, true);
  const PointerToSymbolTable = headerView.getUint32(coffOffset + 8, true);
  const NumberOfSymbols = headerView.getUint32(coffOffset + 12, true);
  const SizeOfOptionalHeader = headerView.getUint16(coffOffset + 16, true);
  const Characteristics = headerView.getUint16(coffOffset + 18, true);
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
  ddStartRel: number;
  ddCount: number;
  dataDirs: PeDataDirectory[];
  opt: PeOptionalHeader;
}> {
  const optionalHeaderOffset = peHeaderOffset + 24;
  const optionalHeaderView = new DataView(
    await file.slice(optionalHeaderOffset, optionalHeaderOffset + Math.min(sizeOfOptionalHeader, 0x600)).arrayBuffer()
  );
  let position = 0;
  const Magic = optionalHeaderView.getUint16(position, true); position += 2;
  const isPlus = Magic === 0x20b, is32 = Magic === 0x10b;
  const LinkerMajor = optionalHeaderView.getUint8(position++), LinkerMinor = optionalHeaderView.getUint8(position++);
  const SizeOfCode = optionalHeaderView.getUint32(position, true); position += 4;
  const SizeOfInitializedData = optionalHeaderView.getUint32(position, true); position += 4;
  const SizeOfUninitializedData = optionalHeaderView.getUint32(position, true); position += 4;
  const AddressOfEntryPoint = optionalHeaderView.getUint32(position, true); position += 4;
  const BaseOfCode = optionalHeaderView.getUint32(position, true); position += 4;
  const BaseOfData = is32 ? optionalHeaderView.getUint32(position, true) : undefined;
  if (is32) position += 4;
  const ImageBase = isPlus
    ? Number(optionalHeaderView.getBigUint64(position, true))
    : optionalHeaderView.getUint32(position, true);
  position += isPlus ? 8 : 4;
  const SectionAlignment = optionalHeaderView.getUint32(position, true); position += 4;
  const FileAlignment = optionalHeaderView.getUint32(position, true); position += 4;
  const OSVersionMajor = optionalHeaderView.getUint16(position, true);
  const OSVersionMinor = optionalHeaderView.getUint16(position + 2, true);
  position += 4;
  const ImageVersionMajor = optionalHeaderView.getUint16(position, true);
  const ImageVersionMinor = optionalHeaderView.getUint16(position + 2, true);
  position += 4;
  const SubsystemVersionMajor = optionalHeaderView.getUint16(position, true);
  const SubsystemVersionMinor = optionalHeaderView.getUint16(position + 2, true);
  position += 4;
  const Win32VersionValue = optionalHeaderView.getUint32(position, true);
  position += 4;
  const SizeOfImage = optionalHeaderView.getUint32(position, true);
  position += 4;
  const SizeOfHeaders = optionalHeaderView.getUint32(position, true);
  position += 4;
  const CheckSum = optionalHeaderView.getUint32(position, true);
  position += 4;
  const Subsystem = optionalHeaderView.getUint16(position, true);
  position += 2;
  const DllCharacteristics = optionalHeaderView.getUint16(position, true);
  position += 2;
  const SizeOfStackReserve = isPlus
    ? Number(optionalHeaderView.getBigUint64(position, true))
    : optionalHeaderView.getUint32(position, true);
  position += isPlus ? 8 : 4;
  const SizeOfStackCommit = isPlus
    ? Number(optionalHeaderView.getBigUint64(position, true))
    : optionalHeaderView.getUint32(position, true);
  position += isPlus ? 8 : 4;
  const SizeOfHeapReserve = isPlus
    ? Number(optionalHeaderView.getBigUint64(position, true))
    : optionalHeaderView.getUint32(position, true);
  position += isPlus ? 8 : 4;
  const SizeOfHeapCommit = isPlus
    ? Number(optionalHeaderView.getBigUint64(position, true))
    : optionalHeaderView.getUint32(position, true);
  position += isPlus ? 8 : 4;
  const LoaderFlags = optionalHeaderView.getUint32(position, true);
  position += 4;
  const NumberOfRvaAndSizes = optionalHeaderView.getUint32(position, true);
  position += 4;
  const ddStartRel = position;
  const ddCount = Math.min(16, NumberOfRvaAndSizes, Math.floor((optionalHeaderView.byteLength - position) / 8));
  const dataDirs: PeDataDirectory[] = [];
  for (let index = 0; index < ddCount; index++) {
    const entryOffset = position + index * 8;
    const rva = optionalHeaderView.getUint32(entryOffset, true);
    const size = optionalHeaderView.getUint32(entryOffset + 4, true);
    dataDirs.push({ index, name: DD_NAMES[index] || "", rva, size });
  }
  const opt: PeOptionalHeader = {
    Magic,
    isPlus,
    is32,
    LinkerMajor,
    LinkerMinor,
    SizeOfCode,
    SizeOfInitializedData,
    SizeOfUninitializedData,
    AddressOfEntryPoint,
    BaseOfCode,
    BaseOfData,
    ImageBase,
    SectionAlignment,
    FileAlignment,
    OSVersionMajor,
    OSVersionMinor,
    ImageVersionMajor,
    ImageVersionMinor,
    SubsystemVersionMajor,
    SubsystemVersionMinor,
    Win32VersionValue,
    SizeOfImage,
    SizeOfHeaders,
    CheckSum,
    Subsystem,
    DllCharacteristics,
    SizeOfStackReserve,
    SizeOfStackCommit,
    SizeOfHeapReserve,
    SizeOfHeapCommit,
    LoaderFlags,
    NumberOfRvaAndSizes
  };
  return { optOff: optionalHeaderOffset, ddStartRel, ddCount, dataDirs, opt };
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
