"use strict";

import { createPeRangeReader } from "./range-reader.js";
import { collectRuntimeFunctionSpans, readRuntimeFunctionSpan } from "./exception-runtime-spans.js";
import type { PeDataDirectory, RvaToOffset } from "./types.js";
import { createEmptyExceptionDirectory, type PeExceptionDirectory } from "./exception-types.js";

const RUNTIME_FUNCTION_ENTRY_SIZE = 12;
const UNW_FLAG_EHANDLER = 0x01;
const UNW_FLAG_UHANDLER = 0x02;
const UNW_FLAG_CHAININFO = 0x04;

const alignTo4 = (value: number): number => (value + 3) & ~3;

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
  file: File,
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
  if (base < 0 || base >= file.size) {
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

  const reader = createPeRangeReader(file, 0, file.size);
  const spans = collectRuntimeFunctionSpans(
    dir.rva,
    Math.floor(dir.size / RUNTIME_FUNCTION_ENTRY_SIZE),
    RUNTIME_FUNCTION_ENTRY_SIZE,
    rvaToOff,
    file.size,
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
        if (beginOff == null || beginOff < 0 || beginOff >= file.size) {
          invalid = true;
        }
      }
      if (end) {
        const endOff = rvaToOff((end - 1) >>> 0);
        if (endOff == null || endOff < 0 || endOff >= file.size) {
          invalid = true;
        }
      }
      if (unwindInfoRva) {
        const unwindOff = rvaToOff(unwindInfoRva);
        if (unwindOff == null || unwindOff < 0 || unwindOff >= file.size) {
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

  const chunkCache = new Map<number, Uint8Array>();
  const readChunk = async (chunkStartOff: number): Promise<Uint8Array> => {
    const normalizedStart = Math.max(0, Math.min(chunkStartOff, file.size));
    const cached = chunkCache.get(normalizedStart);
    if (cached) {
      return cached;
    }
    const chunkEnd = Math.min(file.size, normalizedStart + 262144);
    const bytes = new Uint8Array(await file.slice(normalizedStart, chunkEnd).arrayBuffer());
    chunkCache.set(normalizedStart, bytes);
    return bytes;
  };
  const readBytes = async (offset: number, length: number): Promise<Uint8Array | null> => {
    if (length <= 0) {
      return new Uint8Array();
    }
    if (offset < 0 || offset >= file.size || offset + length > file.size) {
      return null;
    }
    const chunkStart = offset - (offset % 262144);
    const chunk = await readChunk(chunkStart);
    const relativeOffset = offset - chunkStart;
    if (relativeOffset >= 0 && relativeOffset + length <= chunk.length) {
      return chunk.subarray(relativeOffset, relativeOffset + length);
    }
    const buffer = await file.slice(offset, offset + length).arrayBuffer();
    return buffer.byteLength < length ? null : new Uint8Array(buffer);
  };
  const readUint32 = async (offset: number): Promise<number | null> => {
    const bytes = await readBytes(offset, 4);
    if (!bytes || bytes.length < 4) {
      return null;
    }
    return (bytes[0]! | (bytes[1]! << 8) | (bytes[2]! << 16) | (bytes[3]! << 24)) >>> 0;
  };

  const unwindQueue = [...unwindRvas.values()];
  const visitedUnwindRvas = new Set<number>(unwindRvas);
  const enqueueUnwindRva = (rva: number): void => {
    if (!rva || visitedUnwindRvas.has(rva)) {
      return;
    }
    visitedUnwindRvas.add(rva);
    unwindQueue.push(rva);
  };

  let unreadableUnwindCount = 0;
  let unexpectedUnwindVersionCount = 0;
  let handlerUnwindInfoCount = 0;
  let chainedUnwindInfoCount = 0;
  while (unwindQueue.length > 0) {
    const unwindInfoRva = unwindQueue.pop();
    if (unwindInfoRva == null) {
      break;
    }
    const offset = rvaToOff(unwindInfoRva);
    if (offset == null || offset < 0 || offset >= file.size) {
      unreadableUnwindCount += 1;
      continue;
    }
    const headerBytes = await readBytes(offset, 4);
    if (!headerBytes || headerBytes.length < 4) {
      unreadableUnwindCount += 1;
      continue;
    }
    const countOfCodes = headerBytes[2] ?? 0;
    const version = (headerBytes[0] ?? 0) & 0x07;
    const flags = (headerBytes[0] ?? 0) >> 3;
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
