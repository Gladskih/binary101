"use strict";

import { readLoadConfigPointerRva, type PeLoadConfig } from "./load-config.js";
import type { PeSection, RvaToOffset } from "./types.js";

export type PeDynamicRelocationEntry =
  | { kind: "v1"; symbol: number; baseRelocSize: number; availableBytes: number }
  | {
      kind: "v2";
      headerSize: number;
      fixupInfoSize: number;
      symbol: number;
      symbolGroup: number;
      flags: number;
      availableBytes: number;
    };

export type PeDynamicRelocations = {
  version: number;
  dataSize: number;
  entries: PeDynamicRelocationEntry[];
  warnings?: string[];
};

const toSafeU64 = (value: bigint): number => {
  const maxSafeBigInt = BigInt(Number.MAX_SAFE_INTEGER);
  return value <= maxSafeBigInt ? Number(value) : 0;
};

const readU64Maybe = (view: DataView, offset: number): number => {
  if (view.byteLength < offset + 8) return 0;
  return toSafeU64(view.getBigUint64(offset, true));
};

const resolveDynamicRelocTableOffset = (
  fileSize: number,
  sections: PeSection[],
  rvaToOff: RvaToOffset,
  imageBase: number,
  lc: PeLoadConfig,
  warnings: string[]
): number | null => {
  const pointerRva =
    lc.DynamicValueRelocTable && Number.isSafeInteger(imageBase)
      ? readLoadConfigPointerRva(imageBase, lc.DynamicValueRelocTable)
      : null;
  const pointerOff = pointerRva != null ? rvaToOff(pointerRva) : null;

  const sectionIndex = Number.isSafeInteger(lc.DynamicValueRelocTableSection) ? lc.DynamicValueRelocTableSection : 0;
  const sectionOffset = Number.isSafeInteger(lc.DynamicValueRelocTableOffset) ? lc.DynamicValueRelocTableOffset : 0;
  const hasSectionRef = sectionIndex > 0;

  let sectionOff: number | null = null;
  if (hasSectionRef) {
    if (sectionIndex > sections.length) {
      warnings.push(
        `DynamicRelocations: DynamicValueRelocTableSection=${sectionIndex} is out of range (sections=${sections.length}).`
      );
    } else {
      const section = sections[sectionIndex - 1];
      if (!section) {
        warnings.push(
          `DynamicRelocations: DynamicValueRelocTableSection=${sectionIndex} does not map to a section header.`
        );
      } else {
        const rva = (section.virtualAddress + sectionOffset) >>> 0;
        sectionOff = rvaToOff(rva);
        if (sectionOff == null && Number.isSafeInteger(section.pointerToRawData)) {
          const rawOff = (section.pointerToRawData + sectionOffset) >>> 0;
          sectionOff = rawOff;
        }
      }
    }
  }

  const choose = (candidate: number | null, source: string): number | null => {
    if (candidate == null) return null;
    if (!Number.isSafeInteger(candidate) || candidate < 0 || candidate >= fileSize) {
      warnings.push(`DynamicRelocations: ${source} offset 0x${(candidate >>> 0).toString(16)} is not in file.`);
      return null;
    }
    return candidate >>> 0;
  };

  const pointerCandidate = choose(pointerOff, "DynamicValueRelocTable");
  const sectionCandidate = choose(sectionOff, "DynamicValueRelocTableSection/Offset");

  if (pointerCandidate != null && sectionCandidate != null && pointerCandidate !== sectionCandidate) {
    warnings.push(
      `DynamicRelocations: table offset mismatch (pointer=0x${pointerCandidate.toString(16)}, section=0x${sectionCandidate.toString(16)}).`
    );
  }

  return pointerCandidate ?? sectionCandidate;
};

export async function parseDynamicRelocationsFromLoadConfig(
  file: File,
  sections: PeSection[],
  rvaToOff: RvaToOffset,
  imageBase: number,
  isPlus: boolean,
  lc: PeLoadConfig
): Promise<PeDynamicRelocations | null> {
  const warnings: string[] = [];
  const off = resolveDynamicRelocTableOffset(file.size, sections, rvaToOff, imageBase, lc, warnings);
  if (off == null) return null;
  if (file.size - off < 8) {
    return { version: 0, dataSize: 0, entries: [], warnings: [...warnings, "DynamicRelocations: truncated header."] };
  }

  const header = new DataView(await file.slice(off, off + 8).arrayBuffer());
  const version = header.getUint32(0, true);
  const dataSize = header.getUint32(4, true);

  const availableBytes = Math.max(0, file.size - off);
  const totalSize = 8 + dataSize;
  const toRead = Math.min(totalSize, availableBytes);
  const view = new DataView(await file.slice(off, off + toRead).arrayBuffer());

  const end = view.byteLength;
  const entries: PeDynamicRelocationEntry[] = [];

  const warn = (message: string): void => {
    warnings.push(message);
  };

  let cursor = 8;
  const dataEnd = Math.min(end, 8 + dataSize);
  if (dataEnd < 8 + dataSize) {
    warn(`DynamicRelocations: declared size 0x${dataSize.toString(16)} is truncated by EOF.`);
  }

  if (version === 1) {
    const symbolBytes = isPlus ? 8 : 4;
    const headerBytes = symbolBytes + 4;
    while (cursor + headerBytes <= dataEnd) {
      const symbol = isPlus ? readU64Maybe(view, cursor) : view.getUint32(cursor, true);
      const baseRelocSize = view.getUint32(cursor + symbolBytes, true);
      const relocStart = cursor + headerBytes;
      const available = Math.max(0, dataEnd - relocStart);
      const take = Math.min(baseRelocSize, available);
      entries.push({ kind: "v1", symbol: symbol >>> 0, baseRelocSize, availableBytes: take });
      cursor = relocStart + take;
      if (take < baseRelocSize) {
        warn(
          `DynamicRelocations: V1 entry with symbol=${symbol} has BaseRelocSize=0x${baseRelocSize.toString(16)} but only 0x${take.toString(16)} bytes are available.`
        );
        break;
      }
    }
    if (cursor < dataEnd) {
      warn(`DynamicRelocations: trailing ${dataEnd - cursor} bytes after last parsed V1 entry header/data.`);
    }
  } else if (version === 2) {
    const minHeaderBytes = isPlus ? 24 : 20;
    while (cursor + minHeaderBytes <= dataEnd) {
      const headerSize = view.getUint32(cursor, true);
      const fixupInfoSize = view.getUint32(cursor + 4, true);
      const symbolOff = cursor + 8;
      const symbol = isPlus ? readU64Maybe(view, symbolOff) : view.getUint32(symbolOff, true);
      const afterSymbol = symbolOff + (isPlus ? 8 : 4);
      const symbolGroup = view.getUint32(afterSymbol, true);
      const flags = view.getUint32(afterSymbol + 4, true);

      const headerSkip = Math.max(minHeaderBytes, headerSize >>> 0);
      const fixupStart = cursor + headerSkip;
      const available = Math.max(0, dataEnd - fixupStart);
      const take = Math.min(fixupInfoSize, available);
      entries.push({
        kind: "v2",
        headerSize: headerSize >>> 0,
        fixupInfoSize,
        symbol: symbol >>> 0,
        symbolGroup: symbolGroup >>> 0,
        flags: flags >>> 0,
        availableBytes: take
      });
      cursor = fixupStart + take;
      if (take < fixupInfoSize) {
        warn(
          `DynamicRelocations: V2 entry with symbol=${symbol} has FixupInfoSize=0x${fixupInfoSize.toString(16)} but only 0x${take.toString(16)} bytes are available.`
        );
        break;
      }
    }
    if (cursor < dataEnd) {
      warn(`DynamicRelocations: trailing ${dataEnd - cursor} bytes after last parsed V2 entry header/data.`);
    }
  } else {
    warn(`DynamicRelocations: unsupported version ${version}.`);
  }

  return {
    version,
    dataSize,
    entries,
    ...(warnings.length ? { warnings } : {})
  };
}
