"use strict";

// Windows SDK winnt.h: IMAGE_{PROLOGUE,EPILOGUE}_DYNAMIC_RELOCATION_HEADER
// and IMAGE_BASE_RELOCATION. The variable header precedes V2 FixupInfo.
// https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/winnt.h
const BLOCK_HEADER_SIZE = 8;
const EPILOGUE_HEADER_SIZE = 8;

export type PeGuardRfSite = { rva: number; type: number };
export type PeGuardRf =
  | { kind: "prologue"; prologueBytes?: number[]; sites: PeGuardRfSite[] }
  | { kind: "epilogue"; epilogueCount?: number; epilogueByteCount?: number;
      branchDescriptorElementSize?: number; branchDescriptors?: number[][];
      branchDescriptorBitmap?: number[]; sites: PeGuardRfSite[] };

const parseSites = (
  view: DataView, start: number, end: number, warnings: string[]
): PeGuardRfSite[] => {
  const sites: PeGuardRfSite[] = [];
  let cursor = start;
  while (cursor < end) {
    if (end - cursor < BLOCK_HEADER_SIZE) {
      warnings.push("Guard RF: truncated base relocation block header.");
      break;
    }
    const pageRva = view.getUint32(cursor, true);
    const blockSize = view.getUint32(cursor + 4, true);
    if (pageRva % 0x1000 !== 0) {
      warnings.push("Guard RF: unaligned base relocation page RVA.");
      break;
    }
    if (blockSize < BLOCK_HEADER_SIZE || blockSize > end - cursor || blockSize % 2 !== 0) {
      warnings.push("Guard RF: invalid or truncated base relocation block size.");
      break;
    }
    for (let offset = cursor + BLOCK_HEADER_SIZE; offset < cursor + blockSize; offset += 2) {
      const raw = view.getUint16(offset, true);
      if (raw === 0) continue; // IMAGE_REL_BASED_ABSOLUTE padding.
      const rva = pageRva + (raw & 0xfff);
      if (rva > 0xffff_ffff) {
        warnings.push("Guard RF: relocation RVA exceeds 32 bits.");
        continue;
      }
      sites.push({ rva, type: raw >>> 12 });
    }
    cursor += blockSize;
  }
  return sites;
};

const parsePrologue = (
  view: DataView, headerStart: number, headerEnd: number,
  sites: PeGuardRfSite[], warnings: string[]
): PeGuardRf | null => {
  if (headerStart === headerEnd) return { kind: "prologue", sites };
  const count = view.getUint8(headerStart);
  if (count > headerEnd - headerStart - 1) {
    warnings.push("Guard RF: truncated prologue bytes.");
    return null;
  }
  if (count < headerEnd - headerStart - 1) {
    warnings.push("Guard RF: unexpected bytes after prologue header.");
  }
  return { kind: "prologue", prologueBytes: Array.from(
    new Uint8Array(view.buffer, view.byteOffset + headerStart + 1, count)), sites };
};

const parseDescriptors = (
  view: DataView, start: number, count: number, elementSize: number
): number[][] => Array.from({ length: count }, (_, index) => Array.from(
  new Uint8Array(view.buffer, view.byteOffset + start + index * elementSize, elementSize)));

const parseEpilogue = (
  view: DataView, headerStart: number, headerEnd: number,
  sites: PeGuardRfSite[], warnings: string[]
): PeGuardRf | null => {
  if (headerStart === headerEnd) return { kind: "epilogue", sites };
  if (headerEnd - headerStart < EPILOGUE_HEADER_SIZE) {
    warnings.push("Guard RF: truncated epilogue header.");
    return null;
  }
  const branchDescriptorElementSize = view.getUint8(headerStart + 5);
  const count = view.getUint16(headerStart + 6, true);
  const descriptorBytes = count * branchDescriptorElementSize;
  if ((count > 0 && branchDescriptorElementSize === 0) ||
    descriptorBytes > headerEnd - headerStart - EPILOGUE_HEADER_SIZE) {
    warnings.push("Guard RF: truncated or invalid branch descriptors.");
    return null;
  }
  const descriptorStart = headerStart + EPILOGUE_HEADER_SIZE;
  return { kind: "epilogue", epilogueCount: view.getUint32(headerStart, true),
    epilogueByteCount: view.getUint8(headerStart + 4), branchDescriptorElementSize,
    branchDescriptors: parseDescriptors(view, descriptorStart, count, branchDescriptorElementSize),
    branchDescriptorBitmap: Array.from(new Uint8Array(view.buffer,
      view.byteOffset + descriptorStart + descriptorBytes,
      headerEnd - descriptorStart - descriptorBytes)), sites };
};

export const parseGuardRf = (
  view: DataView, symbol: bigint, headerStart: number, headerEnd: number,
  fixupStart: number, fixupEnd: number, warnings: string[]
): PeGuardRf | null => {
  if (!Number.isSafeInteger(headerStart) || !Number.isSafeInteger(headerEnd) ||
    !Number.isSafeInteger(fixupStart) || !Number.isSafeInteger(fixupEnd) ||
    headerStart < 0 || headerEnd < headerStart || fixupStart < headerEnd ||
    fixupEnd < fixupStart || fixupEnd > view.byteLength) {
    warnings.push("Guard RF: invalid header or fixup bounds.");
    return null;
  }
  if (symbol !== 1n && symbol !== 2n) {
    warnings.push(`Guard RF: unsupported symbol ${symbol}.`);
    return null;
  }
  const sites = parseSites(view, fixupStart, fixupEnd, warnings);
  return symbol === 1n
    ? parsePrologue(view, headerStart, headerEnd, sites, warnings)
    : parseEpilogue(view, headerStart, headerEnd, sites, warnings);
};
