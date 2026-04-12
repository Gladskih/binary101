"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import { collectRuntimeFunctionSpans, readRuntimeFunctionSpan } from "./exception-runtime-spans.js";
import { createEmptyExceptionDirectory, type PeExceptionDirectory } from "./exception-types.js";
import type { PeDataDirectory, RvaToOffset } from "./types.js";

// Microsoft ARM64 exception-handling docs:
// https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling
// ARM64 .pdata entries are 8 bytes, and the low 2 bits of word 2 are the Flag field.
const ARM64_RUNTIME_FUNCTION_ENTRY_SIZE = 8;
// Microsoft ARM64 exception-handling docs, ".pdata records":
// Flag is the low 2 bits of word 2, and the remaining 30 bits hold either an .xdata RVA
// or packed unwind data, depending on Flag.
const ARM64_PDATA_FLAG_MASK = 0x3;
const ARM64_PDATA_FLAG_XDATA = 0;
const ARM64_PDATA_FLAG_RESERVED = 0x3;
// Microsoft ARM64 exception-handling docs, ".xdata records":
// Function Length is 18 bits, Vers is 2 bits, and the X/E bits live at bit positions 20/21.
const ARM64_XDATA_FUNCTION_LENGTH_MASK = 0x3ffff;
const ARM64_XDATA_VERSION_SHIFT = 18;
const ARM64_XDATA_VERSION_MASK = 0x3;
const ARM64_XDATA_HAS_EXCEPTION_DATA = 1 << 20;
const ARM64_XDATA_SINGLE_EPILOG = 1 << 21;
// Microsoft ARM64 exception-handling docs, "Packed unwind data":
// packed records use bits 2-12 for Function Length.
const ARM64_PACKED_FUNCTION_LENGTH_SHIFT = 2;
const ARM64_PACKED_FUNCTION_LENGTH_MASK = 0x7ff;

type Arm64UnwindInfo = {
  functionLengthBytes: number;
  handlerRva: number | null;
  hasHandler: boolean;
  key: string;
  version: number | null;
};

const readUint32 = async (reader: FileRangeReader, offset: number): Promise<number | null> => {
  if (offset < 0 || offset + Uint32Array.BYTES_PER_ELEMENT > reader.size) {
    return null;
  }
  const view = await reader.read(offset, Uint32Array.BYTES_PER_ELEMENT);
  return view.byteLength === Uint32Array.BYTES_PER_ELEMENT ? view.getUint32(0, true) >>> 0 : null;
};

const computeFunctionEndRva = (beginRva: number, functionLengthBytes: number): number | null => {
  if (!beginRva || functionLengthBytes <= 0) {
    return null;
  }
  const endRva = beginRva + functionLengthBytes;
  return Number.isSafeInteger(endRva) && endRva > beginRva && endRva <= 0xffffffff
    ? endRva >>> 0
    : null;
};

const readPackedUnwindInfo = (packedWord: number): Arm64UnwindInfo => ({
  functionLengthBytes:
    ((packedWord >>> ARM64_PACKED_FUNCTION_LENGTH_SHIFT) & ARM64_PACKED_FUNCTION_LENGTH_MASK) * 4,
  handlerRva: null,
  hasHandler: false,
  key: `packed:${packedWord >>> 0}`,
  version: null
});

const readXdataUnwindInfo = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  xdataRva: number,
  issues: string[]
): Promise<Arm64UnwindInfo | null> => {
  const xdataOff = rvaToOff(xdataRva);
  if (xdataOff == null || xdataOff < 0 || xdataOff >= reader.size) {
    issues.push("ARM64 .pdata entry points to an .xdata RVA that does not map to file data.");
    return null;
  }
  const headerWord = await readUint32(reader, xdataOff);
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
    ? await readUint32(reader, xdataOff + Uint32Array.BYTES_PER_ELEMENT)
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
  if (xdataOff + recordSize > reader.size) {
    issues.push("ARM64 .xdata record is truncated before its unwind metadata ends.");
    return null;
  }
  const hasHandler = (headerWord & ARM64_XDATA_HAS_EXCEPTION_DATA) !== 0;
  const handlerRva = hasHandler
    ? await readUint32(reader, xdataOff + recordSize - Uint32Array.BYTES_PER_ELEMENT)
    : null;
  if (hasHandler && handlerRva == null) {
    issues.push("ARM64 .xdata declares exception data, but the handler RVA is truncated.");
    return null;
  }
  return {
    functionLengthBytes: (headerWord & ARM64_XDATA_FUNCTION_LENGTH_MASK) * 4,
    handlerRva,
    hasHandler,
    key: `xdata:${xdataRva >>> 0}`,
    version: (headerWord >>> ARM64_XDATA_VERSION_SHIFT) & ARM64_XDATA_VERSION_MASK
  };
};

const readArm64UnwindInfo = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  unwindWord: number,
  issues: string[]
): Promise<Arm64UnwindInfo | null> => {
  const flag = unwindWord & ARM64_PDATA_FLAG_MASK;
  if (flag === ARM64_PDATA_FLAG_RESERVED) {
    issues.push("ARM64 .pdata entry uses reserved packed-unwind flag value 3.");
    return null;
  }
  if (flag === ARM64_PDATA_FLAG_XDATA) {
    const xdataRva = unwindWord & ~ARM64_PDATA_FLAG_MASK;
    if (!xdataRva) {
      issues.push("ARM64 .pdata entry points to .xdata RVA 0.");
      return null;
    }
    return readXdataUnwindInfo(reader, rvaToOff, xdataRva >>> 0, issues);
  }
  return readPackedUnwindInfo(unwindWord);
};

const isValidFunctionRange = (
  beginRva: number,
  functionLengthBytes: number,
  rvaToOff: RvaToOffset,
  fileSize: number
): boolean => {
  const endRva = computeFunctionEndRva(beginRva, functionLengthBytes);
  if (endRva == null) {
    return false;
  }
  const beginOff = rvaToOff(beginRva);
  const endOff = rvaToOff((endRva - 1) >>> 0);
  return beginOff != null && beginOff >= 0 && endOff != null && endOff >= 0 && endOff < fileSize;
};

export async function parseArm64ExceptionDirectory(
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset
): Promise<PeExceptionDirectory | null> {
  const dir = dataDirs.find(directory => directory.name === "EXCEPTION");
  if (!dir?.rva) {
    return null;
  }
  const base = rvaToOff(dir.rva);
  if (base == null) {
    return createEmptyExceptionDirectory([
      "Exception directory RVA could not be mapped to a file offset."
    ], "arm64");
  }
  if (base < 0 || base >= reader.size) {
    return createEmptyExceptionDirectory([
      "Exception directory location is outside the file."
    ], "arm64");
  }
  if (dir.size < ARM64_RUNTIME_FUNCTION_ENTRY_SIZE) {
    return createEmptyExceptionDirectory([
      `Exception directory size is smaller than one ARM64 .pdata entry (${ARM64_RUNTIME_FUNCTION_ENTRY_SIZE} bytes).`
    ], "arm64");
  }

  const issues: string[] = [];
  if (dir.size % ARM64_RUNTIME_FUNCTION_ENTRY_SIZE !== 0) {
    issues.push("Exception directory size is not a multiple of ARM64 .pdata entry size (8 bytes).");
  }
  const beginRvas: number[] = [];
  const handlerRvas: number[] = [];
  const handlerRvasSet = new Set<number>();
  const uniqueUnwindInfos = new Set<string>();
  let functionCount = 0;
  let invalidEntryCount = 0;
  let handlerUnwindInfoCount = 0;
  let unexpectedXdataVersionCount = 0;
  let previousBegin: number | null = null;
  let reportedUnsortedEntries = false;

  const spans = collectRuntimeFunctionSpans(
    dir.rva,
    Math.floor(dir.size / ARM64_RUNTIME_FUNCTION_ENTRY_SIZE),
    ARM64_RUNTIME_FUNCTION_ENTRY_SIZE,
    rvaToOff,
    reader.size,
    "Exception directory is truncated; some ARM64 .pdata entries are missing.",
    issues
  );
  for (const span of spans) {
    const spanView = await readRuntimeFunctionSpan(
      reader,
      span,
      ARM64_RUNTIME_FUNCTION_ENTRY_SIZE,
      "Exception directory is truncated; some ARM64 .pdata entries are missing.",
      issues
    );
    if (!spanView) {
      break;
    }
    const spanEntries = Math.floor(spanView.byteLength / ARM64_RUNTIME_FUNCTION_ENTRY_SIZE);
    for (let index = 0; index < spanEntries; index += 1) {
      const entryOffset = index * ARM64_RUNTIME_FUNCTION_ENTRY_SIZE;
      const beginRva = spanView.getUint32(entryOffset, true) >>> 0;
      const unwindWord = spanView.getUint32(entryOffset + Uint32Array.BYTES_PER_ELEMENT, true) >>> 0;
      functionCount += 1;

      const unwindInfo = await readArm64UnwindInfo(reader, rvaToOff, unwindWord, issues);
      if (unwindInfo?.key) {
        uniqueUnwindInfos.add(unwindInfo.key);
      }
      if (unwindInfo?.version != null && unwindInfo.version !== 0) {
        unexpectedXdataVersionCount += 1;
      }
      if (unwindInfo?.hasHandler) {
        handlerUnwindInfoCount += 1;
      }
      if (unwindInfo?.handlerRva && !handlerRvasSet.has(unwindInfo.handlerRva)) {
        handlerRvasSet.add(unwindInfo.handlerRva);
        handlerRvas.push(unwindInfo.handlerRva);
      }

      const valid = Boolean(
        unwindInfo &&
        isValidFunctionRange(beginRva, unwindInfo.functionLengthBytes, rvaToOff, reader.size)
      );
      if (!valid) {
        invalidEntryCount += 1;
        continue;
      }
      if (previousBegin != null && beginRva < previousBegin && !reportedUnsortedEntries) {
        issues.push("ARM64 .pdata entries are not sorted by function start RVA.");
        reportedUnsortedEntries = true;
      }
      previousBegin = beginRva;
      beginRvas.push(beginRva);
    }
  }
  if (functionCount === 0) {
    issues.push("Exception directory does not contain a complete ARM64 .pdata entry.");
    return createEmptyExceptionDirectory(issues, "arm64");
  }
  if (unexpectedXdataVersionCount > 0) {
    issues.push(`${unexpectedXdataVersionCount} ARM64 .xdata record(s) have an unexpected version.`);
  }
  return {
    functionCount,
    beginRvas,
    handlerRvas,
    uniqueUnwindInfoCount: uniqueUnwindInfos.size,
    handlerUnwindInfoCount,
    chainedUnwindInfoCount: 0,
    invalidEntryCount,
    issues,
    format: "arm64"
  };
}
