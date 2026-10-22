"use strict";

import { mappedRvaSize } from "../rva-mapping.js";
import { readMappedRvaPrefix } from "../rva-byte-reader.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";

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

type Arm64UnwindInfo = {
  chained: boolean;
  functionLengthBytes: number;
  handlerRva: number | null;
  hasHandler: boolean;
  key: string;
  version: number | null;
};

const readUint32 = async (reader: FileRangeReader, rvaToOff: RvaToOffset, offset: number): Promise<number | null> => {
  const view = await readMappedRvaPrefix(reader, offset, Uint32Array.BYTES_PER_ELEMENT, rvaToOff);
  return view.byteLength === Uint32Array.BYTES_PER_ELEMENT ? view.getUint32(0, true) >>> 0 : null;
};

const readPackedUnwindInfo = (packedWord: number): Arm64UnwindInfo => ({
  functionLengthBytes:
    ((packedWord >>> 2) & 0x7ff) * 4,
  handlerRva: null,
  hasHandler: false,
  key: `packed:${packedWord >>> 0}`,
  chained: false,
  version: null
});

const readXdataHeader = async (
  reader: FileRangeReader, rvaToOff: RvaToOffset, xdataRva: number, issues: string[]
): Promise<{ headerWord: number; recordSize: number } | null> => {
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
  const epilogScopeCount = usesExtendedHeader
    ? extendedHeader! & 0xffff
    : (headerWord >>> 22) & 0x1f;
  const unwindWordCount = usesExtendedHeader
    ? (extendedHeader! >>> 16) & 0xff
    : (headerWord >>> 27) & 0x1f;
  const recordSize =
    (usesExtendedHeader ? 8 : 4) +
    ((headerWord & ARM64_XDATA_SINGLE_EPILOG) === 0 ? epilogScopeCount * 4 : 0) +
    unwindWordCount * 4 +
    ((headerWord & ARM64_XDATA_HAS_EXCEPTION_DATA) !== 0 ? 4 : 0);
  if (mappedRvaSize(rvaToOff, xdataRva, recordSize, reader.size) < recordSize) {
    issues.push("ARM64 .xdata record is truncated before its unwind metadata ends.");
    return null;
  }
  return { headerWord, recordSize };
};

const readXdataUnwindInfo = async (
  reader: FileRangeReader, rvaToOff: RvaToOffset, xdataRva: number, issues: string[]
): Promise<Arm64UnwindInfo | null> => {
  const header = await readXdataHeader(reader, rvaToOff, xdataRva, issues);
  if (!header) return null;
  const { headerWord, recordSize } = header;
  const hasHandler = (headerWord & ARM64_XDATA_HAS_EXCEPTION_DATA) !== 0;
  const handlerRva = hasHandler
    ? await readUint32(reader, rvaToOff, xdataRva + recordSize - Uint32Array.BYTES_PER_ELEMENT)
    : null;
  if (hasHandler && handlerRva == null) {
    issues.push("ARM64 .xdata declares exception data, but the handler RVA is truncated.");
    return null;
  }
  return {
    functionLengthBytes: (headerWord & 0x3ffff) * 4,
    handlerRva,
    hasHandler,
    key: `xdata:${xdataRva >>> 0}`,
    chained: false,
    version: (headerWord >>> 18) & 0x3
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
  return readPackedUnwindInfo(unwindWord);
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
