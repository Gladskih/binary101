import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { readMappedRvaPrefix } from "../rva-byte-reader.js";
import { decodeArm64UnwindPool } from "./arm64-unwind-code-pool.js";
import type { Arm64DecodedUnwind, Arm64XdataCodeLayout } from "./arm64-unwind-types.js";

// Microsoft ARM64 .xdata epilog scope: start/4 (18), reserved (4), code index (10).
// https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling#xdata-records
const scopeStarts = (view: DataView, functionLength: number, issues: string[]): Set<number> => {
  const starts = new Set<number>([0]);
  let previous = -1;
  for (let position = 0; position + 4 <= view.byteLength; position += 4) {
    const word = view.getUint32(position, true);
    const offset = (word & 0x3ffff) * 4;
    if (word & 0x003c0000) issues.push("ARM64 epilog scope sets reserved bits.");
    if (offset >= functionLength) issues.push("ARM64 epilog starts outside its function.");
    if (offset < previous) issues.push("ARM64 epilog scopes are not ordered by start offset.");
    previous = offset;
    starts.add(word >>> 22);
  }
  return starts;
};

export const readArm64XdataCodes = async (reader: FileRangeReader, rvaToOff: RvaToOffset,
  layout: Arm64XdataCodeLayout, functionLength: number, issues: string[]): Promise<Arm64DecodedUnwind> => {
  const before = issues.length;
  const scopes = await readMappedRvaPrefix(reader, layout.scopeRva, layout.scopeCount * 4, rvaToOff);
  if (scopes.byteLength < layout.scopeCount * 4) issues.push("ARM64 epilog scope array is truncated.");
  const starts = scopeStarts(scopes, functionLength, issues);
  if (layout.epilogIndex != null) starts.add(layout.epilogIndex);
  const codes = await readMappedRvaPrefix(reader, layout.codeRva, layout.codeSize, rvaToOff);
  if (codes.byteLength < layout.codeSize) issues.push("ARM64 unwind code pool is truncated.");
  const decoded = decodeArm64UnwindPool(codes, starts, issues);
  return { operations: decoded.operations, hasDecodeGaps: issues.length !== before };
};
