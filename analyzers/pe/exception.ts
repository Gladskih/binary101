"use strict";

import type { AddCoverageRegion, PeDataDirectory, RvaToOffset } from "./types.js";

const RUNTIME_FUNCTION_ENTRY_SIZE = 12;
const UNW_FLAG_EHANDLER = 0x01;
const UNW_FLAG_UHANDLER = 0x02;
const UNW_FLAG_CHAININFO = 0x04;

const alignTo4 = (value: number): number => (value + 3) & ~3;

export async function parseExceptionDirectory(
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: AddCoverageRegion
): Promise<{
  functionCount: number;
  beginRvas: number[];
  handlerRvas: number[];
  uniqueUnwindInfoCount: number;
  handlerUnwindInfoCount: number;
  chainedUnwindInfoCount: number;
  invalidEntryCount: number;
  issues: string[];
} | null> {
  const dir = dataDirs.find(d => d.name === "EXCEPTION");
  if (!dir?.rva || dir.size < RUNTIME_FUNCTION_ENTRY_SIZE) return null;
  const base = rvaToOff(dir.rva);
  if (base == null) return null;

  const maxBytes = Math.max(0, Math.min(dir.size, file.size - base));
  addCoverageRegion("EXCEPTION directory", base, maxBytes);

  const declaredCount = Math.floor(dir.size / RUNTIME_FUNCTION_ENTRY_SIZE);
  const parsedCount = Math.floor(maxBytes / RUNTIME_FUNCTION_ENTRY_SIZE);
  const issues: string[] = [];

  if (dir.size % RUNTIME_FUNCTION_ENTRY_SIZE !== 0) {
    issues.push("Exception directory size is not a multiple of RUNTIME_FUNCTION entry size (12 bytes).");
  }
  if (parsedCount < declaredCount) {
    issues.push("Exception directory is truncated; some RUNTIME_FUNCTION entries are missing.");
  }
  if (parsedCount === 0) {
    issues.push("Exception directory does not contain a complete RUNTIME_FUNCTION entry.");
    return {
      functionCount: 0,
      beginRvas: [],
      handlerRvas: [],
      uniqueUnwindInfoCount: 0,
      handlerUnwindInfoCount: 0,
      chainedUnwindInfoCount: 0,
      invalidEntryCount: 0,
      issues
    };
  }

  const dv = new DataView(
    await file.slice(base, base + parsedCount * RUNTIME_FUNCTION_ENTRY_SIZE).arrayBuffer()
  );

  const beginRvas: number[] = [];
  const unwindRvas = new Set<number>();
  const handlerRvas: number[] = [];
  const handlerRvasSet = new Set<number>();
  let invalidEntryCount = 0;

  for (let index = 0; index < parsedCount; index += 1) {
    const entryBase = index * RUNTIME_FUNCTION_ENTRY_SIZE;
    const begin = dv.getUint32(entryBase + 0, true) >>> 0;
    const end = dv.getUint32(entryBase + 4, true) >>> 0;
    const unwindInfoRva = dv.getUint32(entryBase + 8, true) >>> 0;

    if (begin) beginRvas.push(begin);
    if (unwindInfoRva) unwindRvas.add(unwindInfoRva);

    let invalid = false;
    if (!begin || !end || begin >= end) invalid = true;

    if (begin) {
      const beginOff = rvaToOff(begin);
      if (beginOff == null || beginOff < 0 || beginOff >= file.size) invalid = true;
    }

    if (end) {
      const endOff = end > 0 ? rvaToOff((end - 1) >>> 0) : null;
      if (endOff == null || endOff < 0 || endOff >= file.size) invalid = true;
    }

    if (unwindInfoRva) {
      const unwindOff = rvaToOff(unwindInfoRva);
      if (unwindOff == null || unwindOff < 0 || unwindOff >= file.size) invalid = true;
    }

    if (invalid) invalidEntryCount += 1;
  }

  let unreadableUnwindCount = 0;
  let unexpectedUnwindVersionCount = 0;
  let handlerUnwindInfoCount = 0;
  let chainedUnwindInfoCount = 0;

  const unwindQueue = [...unwindRvas.values()];
  const unwindVisited = new Set<number>(unwindRvas);
  const enqueueUnwindRva = (rva: number): void => {
    const normalized = rva >>> 0;
    if (!normalized) return;
    if (unwindVisited.has(normalized)) return;
    unwindVisited.add(normalized);
    unwindQueue.push(normalized);
  };

  while (unwindQueue.length > 0) {
    const unwindInfoRva = unwindQueue.pop();
    if (unwindInfoRva == null) break;

    const directOff = rvaToOff(unwindInfoRva);
    const alignedRva = (unwindInfoRva - (unwindInfoRva % 4)) >>> 0;
    const alignedOff = alignedRva !== unwindInfoRva ? rvaToOff(alignedRva) : null;
    const off = directOff ?? alignedOff;
    if (off == null || off < 0 || off >= file.size) {
      unreadableUnwindCount += 1;
      continue;
    }

    const headerBuf = await file.slice(off, off + 4).arrayBuffer();
    if (headerBuf.byteLength < 4) {
      unreadableUnwindCount += 1;
      continue;
    }

    const header = new DataView(headerBuf);
    const b0 = header.getUint8(0);
    const countOfCodes = header.getUint8(2);
    const version = b0 & 0x07;
    const flags = b0 >> 3;
    if (version !== 1) unexpectedUnwindVersionCount += 1;

    if ((flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) !== 0) {
      handlerUnwindInfoCount += 1;

      const handlerOff = off + alignTo4(4 + countOfCodes * 2);
      if (handlerOff >= 0 && handlerOff + 4 <= file.size) {
        const handlerBuf = await file.slice(handlerOff, handlerOff + 4).arrayBuffer();
        if (handlerBuf.byteLength >= 4) {
          const handlerRva = new DataView(handlerBuf).getUint32(0, true) >>> 0;
          if (handlerRva && !handlerRvasSet.has(handlerRva)) {
            handlerRvasSet.add(handlerRva);
            handlerRvas.push(handlerRva);
          }
        }
      }
    }
    if ((flags & UNW_FLAG_CHAININFO) !== 0) {
      chainedUnwindInfoCount += 1;

      const chainOff = off + alignTo4(4 + countOfCodes * 2);
      if (chainOff >= 0 && chainOff + RUNTIME_FUNCTION_ENTRY_SIZE <= file.size) {
        const chainBuf = await file.slice(chainOff, chainOff + RUNTIME_FUNCTION_ENTRY_SIZE).arrayBuffer();
        if (chainBuf.byteLength >= RUNTIME_FUNCTION_ENTRY_SIZE) {
          const chainView = new DataView(chainBuf);
          const chainedUnwindInfoRva = chainView.getUint32(8, true) >>> 0;
          enqueueUnwindRva(chainedUnwindInfoRva);
        }
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
    functionCount: parsedCount,
    beginRvas,
    handlerRvas,
    uniqueUnwindInfoCount: unwindVisited.size,
    handlerUnwindInfoCount,
    chainedUnwindInfoCount,
    invalidEntryCount,
    issues
  };
}
