"use strict";

import { readAsciiString, collectPrintableRuns } from "../../../binary-utils.js";
import { readCoffFileHeaderFields } from "../../coff/file-header.js";
import { COFF_FILE_HEADER_BYTE_LENGTH } from "../../coff/layout.js";
import type { CoffFileHeader } from "../../coff/types.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import { parseRichHeaderFromDosStub } from "./rich-header.js";
import { analyzePeDosStubCode } from "./dos-stub-code.js";
import { parseValveIntegrityBlock } from "./valve-integrity.js";
import type { PeDosHeader } from "../types.js";

const PE_SIGNATURE_BYTE_LENGTH = 4;
const PE_SIGNATURE_AND_COFF_HEADER_BYTE_LENGTH = PE_SIGNATURE_BYTE_LENGTH + COFF_FILE_HEADER_BYTE_LENGTH;

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
    const valveIntegrity = parseValveIntegrityBlock(stubBytes);
    if (valveIntegrity) {
      dos.stub = { kind: "valve-integrity", note: "Valve PE integrity block", valveIntegrity };
      return dos;
    }
    const code = await analyzePeDosStubCode(dos, stubBytes, peHeaderOffset);
    const printableRuns = collectPrintableRuns(stubBytes, 12);
    if (code.kind === "standard-print-exit" && code.message) {
      dos.stub = { kind: "standard", note: "DOS print-and-exit code", code };
    }
    else if (printableRuns.length) {
      dos.stub = { kind: "non-standard", note: "printable text", strings: printableRuns, code };
    } else {
      dos.stub = { ...dos.stub, code };
    }
  }
  return dos;
}

export async function parseCoffHeader(
  reader: FileRangeReader,
  peHeaderOffset: number
): Promise<CoffFileHeader | null> {
  const headerView = await reader.read(peHeaderOffset, PE_SIGNATURE_AND_COFF_HEADER_BYTE_LENGTH);
  if (headerView.byteLength < PE_SIGNATURE_BYTE_LENGTH) return null;
  const signature =
    String.fromCharCode(headerView.getUint8(0)) +
    String.fromCharCode(headerView.getUint8(1)) +
    String.fromCharCode(headerView.getUint8(2)) +
    String.fromCharCode(headerView.getUint8(3));
  if (signature !== "PE\0\0") return null;
  if (headerView.byteLength < PE_SIGNATURE_AND_COFF_HEADER_BYTE_LENGTH) return null;
  return readCoffFileHeaderFields(headerView, PE_SIGNATURE_BYTE_LENGTH);
}
