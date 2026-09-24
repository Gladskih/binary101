"use strict";

// Windows SDK winnt.h: IMAGE_*_CONTROL_TRANSFER_DYNAMIC_RELOCATION,
// IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION and IMAGE_BASE_RELOCATION.
// https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/winnt.h
const BLOCK_HEADER_SIZE = 8;

export type PeControlTransferRecord =
  | { kind: "import"; rva: number; indirectCall: boolean; iatIndex: number;
      importLink?: { entryIndex: number; functionIndex: number } }
  | { kind: "arm64Import"; rva: number; indirectCall: boolean;
      registerIndex: number; delayImport: boolean; iatIndex: number | null }
  | { kind: "indirect"; rva: number; indirectCall: boolean;
      rexWPrefix: boolean; cfgCheck: boolean }
  | { kind: "switch"; rva: number; registerNumber: number };

const recordSizeForSymbol = (symbol: bigint): number =>
  symbol === 3n || symbol === 8n ? 4 : symbol === 4n || symbol === 5n ? 2 : 0;

const decodeRecord = (
  symbol: bigint,
  pageRva: number,
  raw: number,
  warnings: string[]
): PeControlTransferRecord | null => {
  if (symbol === 3n) {
    return { kind: "import", rva: pageRva + (raw & 0xfff),
      indirectCall: Boolean(raw & 0x1000), iatIndex: raw >>> 13 };
  }
  if (symbol === 8n) {
    const iatIndex = raw >>> 17;
    return { kind: "arm64Import", rva: pageRva + (raw & 0x3ff) * 4,
      indirectCall: Boolean(raw & 0x400), registerIndex: (raw >>> 11) & 0x1f,
      delayImport: Boolean(raw & 0x10000), iatIndex: iatIndex === 0x7fff ? null : iatIndex };
  }
  if (symbol === 4n) {
    if (raw & 0x8000) {
      warnings.push("DynamicRelocations: indirect transfer has a reserved bit set.");
      return null;
    }
    return { kind: "indirect", rva: pageRva + (raw & 0xfff),
      indirectCall: Boolean(raw & 0x1000), rexWPrefix: Boolean(raw & 0x2000),
      cfgCheck: Boolean(raw & 0x4000) };
  }
  return { kind: "switch", rva: pageRva + (raw & 0xfff), registerNumber: raw >>> 12 };
};

export const parseControlTransfers = (
  view: DataView,
  start: number,
  end: number,
  symbol: bigint,
  warnings: string[]
): PeControlTransferRecord[] => {
  const records: PeControlTransferRecord[] = [];
  const entrySize = recordSizeForSymbol(symbol);
  if (!entrySize) {
    warnings.push(`DynamicRelocations: unsupported control transfer symbol ${symbol}.`);
    return records;
  }
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 ||
    end < start || end > view.byteLength) {
    warnings.push("DynamicRelocations: invalid control transfer payload bounds.");
    return records;
  }
  let cursor = start;
  while (cursor < end) {
    if (end - cursor < BLOCK_HEADER_SIZE) {
      warnings.push("DynamicRelocations: truncated control transfer block header.");
      break;
    }
    const pageRva = view.getUint32(cursor, true);
    const blockSize = view.getUint32(cursor + 4, true);
    if (blockSize < BLOCK_HEADER_SIZE || blockSize > end - cursor ||
      (blockSize - BLOCK_HEADER_SIZE) % entrySize !== 0) {
      warnings.push("DynamicRelocations: invalid control transfer block size.");
      break;
    }
    // IMAGE_BASE_RELOCATION.VirtualAddress names a 4 KiB page in PE/COFF.
    if (pageRva % 0x1000 !== 0) {
      warnings.push("DynamicRelocations: control transfer page RVA is not aligned.");
      break;
    }
    for (let offset = cursor + BLOCK_HEADER_SIZE; offset < cursor + blockSize;
      offset += entrySize) {
      const raw = entrySize === 4 ? view.getUint32(offset, true) : view.getUint16(offset, true);
      const decoded = decodeRecord(symbol, pageRva, raw, warnings);
      if (decoded) records.push(decoded);
    }
    cursor += blockSize;
  }
  return records;
};
