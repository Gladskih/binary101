"use strict";

// LLVM COFFObjectFile.cpp Arm64XRelocRef and COFF.h Arm64XFixupType.
// https://github.com/llvm/llvm-project/blob/main/llvm/lib/Object/COFFObjectFile.cpp
// https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/Object/COFF.h
const BLOCK_HEADER_SIZE = 8;

export type PeArm64xFixup =
  | { kind: "zeroFill"; rva: number; size: number }
  | { kind: "value"; rva: number; size: number; value: bigint }
  | { kind: "delta"; rva: number; size: 4; delta: number };

const decodeRecord = (
  view: DataView, cursor: number, end: number, pageRva: number,
  warnings: string[]
): { fixup: PeArm64xFixup; next: number } | null => {
  const raw = view.getUint16(cursor, true);
  const type = (raw >>> 12) & 3;
  const arg = raw >>> 14;
  const rva = pageRva + (raw & 0xfff);
  const size = type === 2 ? 4 : 1 << arg;
  const followingBytes = type === 1 ? size : type === 2 ? 2 : 0;
  if (raw === 0 || type === 3 || (type === 1 && arg === 0)) {
    warnings.push("ARM64X: invalid fixup record or unexpected terminator.");
    return null;
  }
  if (followingBytes > end - cursor - 2) {
    warnings.push("ARM64X: truncated fixup value or delta.");
    return null;
  }
  if (rva > 0xffff_ffff || rva + size > 0x1_0000_0000 || rva % size !== 0) {
    warnings.push("ARM64X: invalid or unaligned fixup RVA.");
    return null;
  }
  if (type === 0) return { fixup: { kind: "zeroFill", rva, size }, next: cursor + 2 };
  if (type === 2) return { fixup: { kind: "delta", rva, size: 4,
    delta: view.getUint16(cursor + 2, true) * (arg & 2 ? 8 : 4) * (arg & 1 ? -1 : 1) },
  next: cursor + 4 };
  const value = Array.from({ length: size }, (_, index) =>
    BigInt(view.getUint8(cursor + 2 + index)) << BigInt(index * 8))
    .reduce((sum, part) => sum | part, 0n);
  return { fixup: { kind: "value", rva, size, value }, next: cursor + 2 + size };
};

export const parseArm64xFixups = (
  view: DataView, start: number, end: number, warnings: string[]
): PeArm64xFixup[] => {
  const fixups: PeArm64xFixup[] = [];
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 ||
    end < start || end > view.byteLength) {
    warnings.push("ARM64X: invalid fixup payload bounds.");
    return fixups;
  }
  let cursor = start;
  while (cursor < end) {
    if (end - cursor < BLOCK_HEADER_SIZE) {
      warnings.push("ARM64X: truncated block header.");
      break;
    }
    const pageRva = view.getUint32(cursor, true);
    const blockSize = view.getUint32(cursor + 4, true);
    if (pageRva % 0x1000 !== 0) {
      warnings.push("ARM64X: unaligned page RVA.");
      break;
    }
    if (blockSize <= BLOCK_HEADER_SIZE || blockSize > end - cursor || blockSize % 4 !== 0) {
      warnings.push("ARM64X: invalid or truncated block size.");
      break;
    }
    const blockEnd = cursor + blockSize;
    let recordCursor = cursor + BLOCK_HEADER_SIZE;
    while (recordCursor < blockEnd) {
      if (blockEnd - recordCursor < 2) {
        warnings.push("ARM64X: truncated fixup record.");
        break;
      }
      if (view.getUint16(recordCursor, true) === 0 && recordCursor + 2 === blockEnd) break;
      const decoded = decodeRecord(view, recordCursor, blockEnd, pageRva, warnings);
      if (!decoded) break;
      fixups.push(decoded.fixup);
      recordCursor = decoded.next;
    }
    cursor = blockEnd;
  }
  return fixups;
};
