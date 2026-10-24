"use strict";

import { mappedRvaSize } from "../rva-mapping.js";
import { readMappedRvaPrefix } from "../rva-byte-reader.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { readArm64XdataCodes } from "./arm64-xdata-codes.js";
import type { Arm64DecodedUnwind, Arm64XdataCodeLayout } from "./arm64-unwind-types.js";

// Microsoft ARM64 exception-handling docs:
// https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling
// ARM64 .pdata entries are 8 bytes, and the low 2 bits of word 2 are the Flag field.
const ARM64_RUNTIME_FUNCTION_ENTRY_SIZE = 8;
// Microsoft ARM64 exception-handling docs, ".pdata records":
// Flag is the low 2 bits of word 2, and the remaining 30 bits hold either an .xdata RVA
// or packed unwind data, depending on Flag.
const ARM64_PDATA_FLAG_MASK = 0x3;
// Microsoft ARM64 exception-handling docs, ".xdata records":
// Function Length is 18 bits, Vers is 2 bits, and the X/E bits live at bit positions 20/21.
const ARM64_XDATA_HAS_EXCEPTION_DATA = 1 << 20;
const ARM64_XDATA_SINGLE_EPILOG = 1 << 21;
// Microsoft ARM64 exception-handling docs, "Packed unwind data":
// packed records use bits 2-12 for Function Length.

export type Arm64UnwindInfo = {
  chained: boolean;
  functionLengthBytes: number;
  handlerRva: number | null;
  hasHandler: boolean;
  key: string;
  version: number | null;
  unwind?: Arm64DecodedUnwind;
};

interface Arm64XdataHeader extends Arm64XdataCodeLayout {
  functionLengthBytes: number;
  version: number;
  handlerSlotRva: number | null;
}

const readUint32 = async (reader: FileRangeReader, rvaToOff: RvaToOffset, offset: number): Promise<number | null> => {
  const view = await readMappedRvaPrefix(reader, offset, Uint32Array.BYTES_PER_ELEMENT, rvaToOff);
  return view.byteLength === Uint32Array.BYTES_PER_ELEMENT ? view.getUint32(0, true) >>> 0 : null;
};

const readPackedUnwindInfo = (packedWord: number, issues: string[]): Arm64UnwindInfo => {
  if (((packedWord >>> 16) & 15) > 10) issues.push("ARM64 packed RegI exceeds the X19-X28 register group.");
  return {
  functionLengthBytes:
    ((packedWord >>> 2) & 0x7ff) * 4,
  handlerRva: null,
  hasHandler: false,
  key: `packed:${packedWord >>> 0}`,
  chained: false,
  version: null
  };
};

const decodeXdataHeader = (word: number, extension: number, rva: number): Arm64XdataHeader => {
  const extended = (word >>> 22) === 0;
  const count = extended ? extension & 0xffff : (word >>> 22) & 31;
  const words = extended ? (extension >>> 16) & 255 : word >>> 27;
  const single = (word & ARM64_XDATA_SINGLE_EPILOG) !== 0;
  const scopeRva = rva + (extended ? 8 : 4);
  const scopeCount = single ? 0 : count;
  const codeRva = scopeRva + scopeCount * 4;
  const codeSize = words * 4;
  return { functionLengthBytes: (word & 0x3ffff) * 4, version: (word >>> 18) & 3,
    scopeRva, scopeCount, codeRva, codeSize, epilogIndex: single ? count : null,
    handlerSlotRva: (word & ARM64_XDATA_HAS_EXCEPTION_DATA) !== 0 ? codeRva + codeSize : null };
};

const readXdataWord = async (
  reader: FileRangeReader, rvaToOff: RvaToOffset, xdataRva: number, issues: string[]
): Promise<number | null> => {
  const xdataOff = rvaToOff(xdataRva);
  if (xdataOff == null || xdataOff < 0 || xdataOff >= reader.size) {
    issues.push("ARM64 .pdata entry points to an .xdata RVA that does not map to file data.");
    return null;
  }
  const headerWord = await readUint32(reader, rvaToOff, xdataRva);
  if (headerWord == null) {
    issues.push("ARM64 .xdata header is truncated.");
    return null;
  }
  return headerWord;
};

const readXdataHeader = async (
  reader: FileRangeReader, rvaToOff: RvaToOffset, xdataRva: number, issues: string[]
): Promise<Arm64XdataHeader | null> => {
  const headerWord = await readXdataWord(reader, rvaToOff, xdataRva, issues);
  if (headerWord == null) return null;
  // Microsoft ARM64 exception-handling docs, ComputeXdataSize sample:
  // `(Xdata[0] >> 22) == 0` means Epilog Count and Code Words are both zero, so the
  // record carries the extra extension word with 16-bit Extended Epilog Count and 8-bit
  // Extended Code Words fields.
  const usesExtendedHeader = (headerWord >>> 22) === 0;
  const extendedHeader = usesExtendedHeader
    ? await readUint32(reader, rvaToOff, xdataRva + Uint32Array.BYTES_PER_ELEMENT)
    : 0;
  if (usesExtendedHeader && extendedHeader == null) {
    issues.push("ARM64 .xdata extended header is truncated.");
    return null;
  }
  if (usesExtendedHeader && (extendedHeader! >>> 24) !== 0) {
    issues.push("ARM64 .xdata extended header sets reserved bits.");
  }
  const header = decodeXdataHeader(headerWord, extendedHeader!, xdataRva);
  const endRva = header.handlerSlotRva == null ? header.codeRva + header.codeSize : header.handlerSlotRva + 4;
  const recordSize = endRva - xdataRva;
  if (mappedRvaSize(rvaToOff, xdataRva, recordSize, reader.size) < recordSize) {
    issues.push("ARM64 .xdata record is truncated before its unwind metadata ends.");
    return null;
  }
  return header;
};

const readXdataUnwindInfo = async (
  reader: FileRangeReader, rvaToOff: RvaToOffset, xdataRva: number, issues: string[]
): Promise<Arm64UnwindInfo | null> => {
  const header = await readXdataHeader(reader, rvaToOff, xdataRva, issues);
  if (!header) return null;
  const hasHandler = header.handlerSlotRva != null;
  const handlerRva = header.handlerSlotRva != null
    ? await readUint32(reader, rvaToOff, header.handlerSlotRva)
    : null;
  if (hasHandler && handlerRva == null) {
    issues.push("ARM64 .xdata declares exception data, but the handler RVA is truncated.");
    return null;
  }
  const unwind = header.version === 0
    ? await readArm64XdataCodes(reader, rvaToOff, header, header.functionLengthBytes, issues) : undefined;
  return {
    functionLengthBytes: header.functionLengthBytes,
    handlerRva,
    hasHandler,
    key: `xdata:${xdataRva >>> 0}`,
    chained: false,
    version: header.version,
    ...(unwind ? { unwind } : {})
  };
};

const readArm64UnwindInfo = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  unwindWord: number,
  issues: string[],
  resolveParent: (word: number, issues: string[]) => Promise<Arm64UnwindInfo | null>,
  readParent: (rva: number) => Promise<DataView>
): Promise<Arm64UnwindInfo | null> => {
  const flag = unwindWord & ARM64_PDATA_FLAG_MASK;
  if (flag === 0x3) {
    const targetPdataRva = unwindWord & ~ARM64_PDATA_FLAG_MASK;
    const chainedEntry = await readParent(targetPdataRva >>> 0);
    if (chainedEntry.byteLength < ARM64_RUNTIME_FUNCTION_ENTRY_SIZE) {
      issues.push("ARM64 chained .pdata target is truncated.");
      return null;
    }
    const chainedUnwindWord = chainedEntry.getUint32(Uint32Array.BYTES_PER_ELEMENT, true) >>> 0;
    const chainedInfo = await resolveParent(chainedUnwindWord, issues);
    return chainedInfo
      ? { ...chainedInfo, key: `chained:${targetPdataRva >>> 0}`, chained: true }
      : null;
  }
  if (flag === 0) {
    const xdataRva = unwindWord & ~ARM64_PDATA_FLAG_MASK;
    if (!xdataRva) {
      issues.push("ARM64 .pdata entry points to .xdata RVA 0.");
      return null;
    }
    return readXdataUnwindInfo(reader, rvaToOff, xdataRva >>> 0, issues);
  }
  return readPackedUnwindInfo(unwindWord, issues);
};

// Flag 3 links to a parent .pdata record; no format depth limit is specified.
// https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling#pdata-record-links
export const createArm64UnwindInfoReader = (
  reader: FileRangeReader, rvaToOff: RvaToOffset, source?: FileRangeReader, originRva?: number,
  originSize = source?.size ?? 0
) => {
  const cache = new Map<number, { info: Arm64UnwindInfo | null; issues: string[] }>();
  const visiting = new Set<number>();
  const readParent = (rva: number): Promise<DataView> => {
    if (source && originRva != null && rva >= originRva && rva - originRva < originSize) {
      return source.read(rva - originRva,
        Math.min(ARM64_RUNTIME_FUNCTION_ENTRY_SIZE, originSize - (rva - originRva)));
    }
    return readMappedRvaPrefix(reader, rva, ARM64_RUNTIME_FUNCTION_ENTRY_SIZE, rvaToOff);
  };
  const resolve = async (word: number, issues: string[]): Promise<Arm64UnwindInfo | null> => {
    const cached = cache.get(word);
    if (cached) {
      issues.push(...cached.issues);
      return cached.info;
    }
    if (visiting.has(word)) {
      issues.push("ARM64 chained .pdata entries contain a cycle.");
      return null;
    }
    visiting.add(word);
    const recordIssues: string[] = [];
    const info = await readArm64UnwindInfo(reader, rvaToOff, word, recordIssues, resolve, readParent);
    visiting.delete(word);
    cache.set(word, { info, issues: recordIssues });
    issues.push(...recordIssues);
    return info;
  };
  return resolve;
};
