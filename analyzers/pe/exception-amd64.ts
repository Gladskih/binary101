"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import { collectRuntimeFunctionSpans, readRuntimeFunctionSpan } from "./exception-runtime-spans.js";
import type { PeDataDirectory, RvaToOffset } from "./types.js";
import { createEmptyExceptionDirectory, type PeExceptionDirectory } from "./exception-types.js";

// Microsoft PE format, ".pdata (Exception Information)":
// each x64 RUNTIME_FUNCTION entry is 12 bytes.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-pdata-section
const RUNTIME_FUNCTION_ENTRY_SIZE = 12;
// Microsoft x64 exception handling:
// UNW_FLAG_EHANDLER, UNW_FLAG_UHANDLER, and UNW_FLAG_CHAININFO are the public UNWIND_INFO flags.
// https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
const UNW_FLAG_EHANDLER = 0x01;
const UNW_FLAG_UHANDLER = 0x02;
const UNW_FLAG_CHAININFO = 0x04;
const alignTo4 = (value: number): number => (value + 3) & ~3;

const createCachedRvaOffsetReader = (
  rvaToOff: RvaToOffset
): ((rva: number) => number | null) => {
  const offsets = new Map<number, number | null>();
  return (rva: number): number | null => {
    if (offsets.has(rva)) {
      return offsets.get(rva) ?? null;
    }
    const offset = rvaToOff(rva);
    const mappedOffset = offset == null ? null : offset;
    offsets.set(rva, mappedOffset);
    return mappedOffset;
  };
};

const createRvaFileOffsetComparer = (
  getOffset: (rva: number) => number | null
): ((left: number, right: number) => number) =>
  (left: number, right: number): number => {
    const leftOffset = getOffset(left);
    const rightOffset = getOffset(right);
    if (leftOffset == null) {
      return rightOffset == null ? left - right : 1;
    }
    if (rightOffset == null) {
      return -1;
    }
    return leftOffset - rightOffset || left - right;
  };

const insertPendingUnwindRva = (
  pendingUnwindRvas: number[],
  firstPendingIndex: number,
  unwindInfoRva: number,
  compareRvas: (left: number, right: number) => number
): void => {
  let low = firstPendingIndex;
  let high = pendingUnwindRvas.length;
  while (low < high) {
    const mid = (low + high) >> 1;
    if (compareRvas(pendingUnwindRvas[mid]!, unwindInfoRva) <= 0) {
      low = mid + 1;
    } else {
      high = mid;
    }
  }
  pendingUnwindRvas.splice(low, 0, unwindInfoRva);
};

const readTrailingUint32 = async (
  readUint32: (offset: number) => Promise<number | null>,
  offset: number,
  issue: string,
  issues: string[]
): Promise<number | null> => {
  const value = await readUint32(offset);
  if (value == null) {
    issues.push(issue);
  }
  return value;
};

export const parseAmd64ExceptionDirectory = async (
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset
): Promise<PeExceptionDirectory | null> => {
  const dir = dataDirs.find(directory => directory.name === "EXCEPTION");
  if (!dir?.rva) {
    return null;
  }
  const base = rvaToOff(dir.rva);
  if (base == null) {
    return createEmptyExceptionDirectory(
      ["Exception directory RVA could not be mapped to a file offset."],
      "amd64"
    );
  }
  if (base < 0 || base >= reader.size) {
    return createEmptyExceptionDirectory(
      ["Exception directory location is outside the file."],
      "amd64"
    );
  }
  if (dir.size < RUNTIME_FUNCTION_ENTRY_SIZE) {
    return createEmptyExceptionDirectory(
      [
        `Exception directory size is smaller than one RUNTIME_FUNCTION entry (${RUNTIME_FUNCTION_ENTRY_SIZE} bytes).`
      ],
      "amd64"
    );
  }

  const issues: string[] = [];
  if (dir.size % RUNTIME_FUNCTION_ENTRY_SIZE !== 0) {
    issues.push("Exception directory size is not a multiple of RUNTIME_FUNCTION entry size (12 bytes).");
  }
  const beginRvas: number[] = [];
  const unwindRvas = new Set<number>();
  const handlerRvas: number[] = [];
  const handlerRvasSet = new Set<number>();
  let functionCount = 0;
  let invalidEntryCount = 0;
  let previousBegin: number | null = null;
  let reportedUnsortedEntries = false;

  const spans = collectRuntimeFunctionSpans(
    dir.rva,
    Math.floor(dir.size / RUNTIME_FUNCTION_ENTRY_SIZE),
    RUNTIME_FUNCTION_ENTRY_SIZE,
    rvaToOff,
    reader.size,
    "Exception directory is truncated; some RUNTIME_FUNCTION entries are missing.",
    issues
  );
  for (const span of spans) {
    const spanView = await readRuntimeFunctionSpan(
      reader,
      span,
      RUNTIME_FUNCTION_ENTRY_SIZE,
      "Exception directory is truncated; some RUNTIME_FUNCTION entries are missing.",
      issues
    );
    if (!spanView) {
      break;
    }
    const spanEntries = Math.floor(spanView.byteLength / RUNTIME_FUNCTION_ENTRY_SIZE);
    for (let index = 0; index < spanEntries; index += 1) {
      const entryOffset = index * RUNTIME_FUNCTION_ENTRY_SIZE;
      const begin = spanView.getUint32(entryOffset, true) >>> 0;
      const end = spanView.getUint32(entryOffset + 4, true) >>> 0;
      const unwindInfoRva = spanView.getUint32(entryOffset + 8, true) >>> 0;
      functionCount += 1;

      let invalid = !begin || !end || begin >= end;
      if (begin) {
        const beginOff = rvaToOff(begin);
        if (beginOff == null || beginOff < 0 || beginOff >= reader.size) {
          invalid = true;
        }
      }
      if (end) {
        const endOff = rvaToOff((end - 1) >>> 0);
        if (endOff == null || endOff < 0 || endOff >= reader.size) {
          invalid = true;
        }
      }
      if (unwindInfoRva) {
        const unwindOff = rvaToOff(unwindInfoRva);
        if (unwindOff == null || unwindOff < 0 || unwindOff >= reader.size) {
          invalid = true;
        }
      }
      if (!invalid && begin) {
        if (previousBegin != null && begin < previousBegin && !reportedUnsortedEntries) {
          issues.push("RUNTIME_FUNCTION entries are not sorted by BeginAddress.");
          reportedUnsortedEntries = true;
        }
        previousBegin = begin;
        beginRvas.push(begin);
      }
      if (unwindInfoRva) {
        unwindRvas.add(unwindInfoRva);
      }
      if (invalid) {
        invalidEntryCount += 1;
      }
    }
  }
  if (functionCount === 0) {
    issues.push("Exception directory does not contain a complete RUNTIME_FUNCTION entry.");
    return createEmptyExceptionDirectory(issues, "amd64");
  }

  const getUnwindOffset = createCachedRvaOffsetReader(rvaToOff);
  const readUint32 = async (offset: number): Promise<number | null> => {
    if (offset < 0 || offset + Uint32Array.BYTES_PER_ELEMENT > reader.size) {
      return null;
    }
    const view = await reader.read(offset, Uint32Array.BYTES_PER_ELEMENT);
    return view.byteLength === Uint32Array.BYTES_PER_ELEMENT ? view.getUint32(0, true) >>> 0 : null;
  };
  const compareUnwindRvas = createRvaFileOffsetComparer(getUnwindOffset);

  const unwindQueue = [...unwindRvas.values()].sort(compareUnwindRvas);
  const visitedUnwindRvas = new Set<number>(unwindRvas);
  let unwindQueueIndex = 0;
  const enqueueUnwindRva = (rva: number): void => {
    if (!rva || visitedUnwindRvas.has(rva)) {
      return;
    }
    visitedUnwindRvas.add(rva);
    insertPendingUnwindRva(unwindQueue, unwindQueueIndex, rva, compareUnwindRvas);
  };

  let unreadableUnwindCount = 0;
  let unexpectedUnwindVersionCount = 0;
  let handlerUnwindInfoCount = 0;
  let chainedUnwindInfoCount = 0;
  while (unwindQueueIndex < unwindQueue.length) {
    const unwindInfoRva = unwindQueue[unwindQueueIndex]!;
    unwindQueueIndex += 1;
    const offset = getUnwindOffset(unwindInfoRva);
    if (offset == null || offset < 0 || offset >= reader.size) {
      unreadableUnwindCount += 1;
      continue;
    }
    const headerView = await reader.read(offset, Uint32Array.BYTES_PER_ELEMENT);
    if (headerView.byteLength < Uint32Array.BYTES_PER_ELEMENT) {
      unreadableUnwindCount += 1;
      continue;
    }
    const countOfCodes = headerView.getUint8(2);
    const headerByte0 = headerView.getUint8(0);
    const version = headerByte0 & 0x07;
    const flags = headerByte0 >> 3;
    if (version !== 1) {
      unexpectedUnwindVersionCount += 1;
    }
    if ((flags & UNW_FLAG_CHAININFO) !== 0 && (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) !== 0) {
      issues.push("UNWIND_INFO sets CHAININFO together with EHANDLER/UHANDLER.");
    }
    const tailOffset = offset + alignTo4(4 + countOfCodes * 2);
    if ((flags & UNW_FLAG_CHAININFO) === 0 && (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) !== 0) {
      handlerUnwindInfoCount += 1;
      const handlerRva = await readTrailingUint32(
        readUint32,
        tailOffset,
        "UNWIND_INFO declares EHANDLER/UHANDLER, but the trailing handler RVA is truncated.",
        issues
      );
      if (handlerRva && !handlerRvasSet.has(handlerRva)) {
        handlerRvasSet.add(handlerRva);
        handlerRvas.push(handlerRva);
      }
    }
    if ((flags & UNW_FLAG_CHAININFO) !== 0) {
      chainedUnwindInfoCount += 1;
      const chainedUnwindInfoRva = await readTrailingUint32(
        readUint32,
        tailOffset + 8,
        "UNWIND_INFO declares CHAININFO, but the trailing chained RUNTIME_FUNCTION is truncated.",
        issues
      );
      if (chainedUnwindInfoRva) {
        enqueueUnwindRva(chainedUnwindInfoRva);
      }
    }
  }
  if (unreadableUnwindCount > 0) {
    issues.push(`${unreadableUnwindCount} UNWIND_INFO block(s) could not be read.`);
  }
  if (unexpectedUnwindVersionCount > 0) {
    issues.push(`${unexpectedUnwindVersionCount} UNWIND_INFO block(s) have an unexpected version.`);
  }
  return {
    functionCount,
    beginRvas,
    handlerRvas,
    uniqueUnwindInfoCount: visitedUnwindRvas.size,
    handlerUnwindInfoCount,
    chainedUnwindInfoCount,
    invalidEntryCount,
    issues,
    format: "amd64"
  };
};
