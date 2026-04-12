"use strict";

import { readAsciiString, collectPrintableRuns } from "../../binary-utils.js";
import type { FileRangeReader } from "../file-range-reader.js";
export { parseOptionalHeaderAndDirectories } from "./optional-header-parse.js";
import { parseRichHeaderFromDosStub } from "./rich-header.js";
import type { PeCoffHeader, PeDosHeader } from "./types.js";

const IMAGE_FILE_HEADER_SIZE = 20;

export async function parseDosHeaderAndStub(
  reader: FileRangeReader,
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
    const stubLength = peHeaderOffset - 0x40;
    const stubBytes = await reader.readBytes(0x40, stubLength);
    dos.rich = parseRichHeaderFromDosStub(stubBytes);
    const printableRuns = collectPrintableRuns(stubBytes, 12);
    const classicMessage = printableRuns.find(text => /this program cannot be run in dos mode/i.test(text));
    if (classicMessage) dos.stub = { kind: "standard", note: "classic DOS message", strings: [classicMessage] };
    else if (printableRuns.length) {
      dos.stub = { kind: "non-standard", note: "printable text", strings: printableRuns };
    }
  }
  return dos;
}

export async function parseCoffHeader(
  reader: FileRangeReader,
  peHeaderOffset: number
): Promise<PeCoffHeader | null> {
  const headerView = await reader.read(peHeaderOffset, 24);
  if (headerView.byteLength < 4) return null;
  const signature =
    String.fromCharCode(headerView.getUint8(0)) +
    String.fromCharCode(headerView.getUint8(1)) +
    String.fromCharCode(headerView.getUint8(2)) +
    String.fromCharCode(headerView.getUint8(3));
  if (signature !== "PE\0\0") return null;
  if (headerView.byteLength < 4 + IMAGE_FILE_HEADER_SIZE) return null;
  const coffOffset = 4;
  const u16 = (off: number): number => headerView.getUint16(off, true);
  const u32 = (off: number): number => headerView.getUint32(off, true);
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
