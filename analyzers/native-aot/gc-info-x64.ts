import { GcBitReader } from "./gc-bit-reader.js";
import { readX64GcHeader } from "./gc-info-x64-header.js";
import { readX64GcSlots } from "./gc-info-x64-slots.js";
import { readGcSafePointStates } from "./gc-safe-points.js";
import { readGcTransitions } from "./gc-transitions.js";
import type { ManagedGcInfo } from "./gc-info-types.js";

const safePoints = (reader: GcBitReader, count: number, result: ManagedGcInfo): void => {
  const length = result.header.codeLength;
  if (count > length) throw new Error("GC safe-point count exceeds the code length.");
  const width = Math.ceil(Math.log2(length)); // The header requires nonzero code length.
  let previous = -1;
  for (let index = 0; index < count; index++) {
    const offset = reader.bits(width);
    if (offset <= previous) throw new Error("GC safe-point offsets must be increasing.");
    if (offset >= length) throw new Error("GC safe-point offset is outside the method.");
    previous = offset;
    result.safePoints.push({ offset, liveSlots: [] });
  }
};

const ranges = (reader: GcBitReader, count: number, result: ManagedGcInfo): void => {
  let previousEnd = 0;
  for (let index = 0; index < count; index++) {
    const startOffset = previousEnd + reader.unsigned(6);
    const endOffset = startOffset + reader.unsigned(6) + 1;
    if (endOffset > result.header.codeLength) throw new Error("GC interruptible range is outside the method.");
    result.interruptibleRanges.push({ startOffset, endOffset });
    previousEnd = endOffset;
  }
};

// Versions 3 and 4 are selected per runtime/R2R header, not guessed from payload bytes.
// Safe points and interruptible ranges are mutually exclusive in GCInfoEncoder::Build.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/gcinfo/gcinfoencoder.cpp
export const parseX64GcInfo = (bytes: Uint8Array, version: 3 | 4,
  warnings: Set<string> = new Set()): ManagedGcInfo | null => {
  const reader = new GcBitReader(bytes);
  let context: ReturnType<typeof readX64GcHeader>;
  try { context = readX64GcHeader(reader, version); }
  catch (error) { warnings.add((error as Error).message); return null; }
  const result: ManagedGcInfo = { header: context.header, safePoints: [],
    interruptibleRanges: [], slots: [], transitions: [] };
  try {
    const count = reader.unsigned(2);
    const rangeCount = context.format === "fat" ? reader.unsigned(1) : 0;
    if (count && rangeCount) throw new Error("GC method uses both safe points and interruptible ranges.");
    safePoints(reader, count, result);
    ranges(reader, rangeCount, result);
    readX64GcSlots(reader, result.slots);
    const tracked = result.slots.filter(slot => !(slot.flags & 4)).length;
    if (count) readGcSafePointStates(reader, result.safePoints, tracked);
    result.transitions = readGcTransitions(reader, result.interruptibleRanges, tracked);
  } catch (error) { warnings.add((error as Error).message); }
  if (warnings.size) result.warnings = [...warnings];
  return result;
};
