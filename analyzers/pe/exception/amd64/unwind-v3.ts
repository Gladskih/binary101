import type { Amd64UnwindV3, Amd64UnwindV3Epilog } from "./unwind-v3-types.js";
import { createV3WindingReader } from "./unwind-v3-winding.js";

type FullEpilog = Omit<Extract<Amd64UnwindV3Epilog, { kind: "full" }>, "operations">;
type EncodedEpilog = FullEpilog | Extract<Amd64UnwindV3Epilog, { kind: "inherited" }>;

// The payload boundary excludes alignment padding and handler/chain bytes.
// https://learn.microsoft.com/en-us/cpp/build/x64-unwind-information-v3#payload-layout
const createPayloadCursor = (payload: DataView, issues: string[]) => {
  let offset = 0;
  return {
    read(width: 1 | 2, label: string): number | null {
      if (offset + width > payload.byteLength) {
        issues.push(`UNWIND_INFO v3 payload is truncated reading ${label}.`);
        return null;
      }
      const value = width === 1 ? payload.getUint8(offset) : payload.getUint16(offset, true);
      offset += width;
      return value;
    },
    remaining: (): DataView => new DataView(payload.buffer, payload.byteOffset + offset, payload.byteLength - offset)
  };
};

type PayloadCursor = ReturnType<typeof createPayloadCursor>;

const readIpOffsets = (cursor: PayloadCursor, count: number, width: 1 | 2): number[] | null => {
  const offsets: number[] = [];
  for (let index = 0; index < count; index++) {
    const offset = cursor.read(width, "instruction offset");
    if (offset == null) return null;
    offsets.push(offset);
  }
  return offsets;
};

const readFullEpilog = (cursor: PayloadCursor, flags: number, offset: number, count: number): FullEpilog | null => {
  const firstOp = cursor.read(2, "epilog FirstOp");
  const width = (flags & 2) !== 0 ? 2 : 1;
  const lastInstructionOffset = cursor.read(width, "epilog last instruction");
  if (firstOp == null || lastInstructionOffset == null) return null;
  const ipOffsets = readIpOffsets(cursor, count, width);
  return ipOffsets ? { kind: "full", flags, offset, firstOp, lastInstructionOffset, ipOffsets } : null;
};

const validateEpilogControl = (flags: number, offset: number, direction: number, issues: string[]): void => {
  if (Math.sign(offset) !== 0 && direction !== 0 && Math.sign(offset) !== direction) {
    issues.push("UNWIND_INFO v3 epilog displacements do not have a consistent direction.");
  }
  if ((flags & 4) !== 0) issues.push("UNWIND_INFO v3 epilog sets a reserved flag.");
};

const readInheritedEpilog = (flags: number, offset: number, baseIndex: number | null,
  epilogs: EncodedEpilog[], issues: string[]): EncodedEpilog => {
  if (baseIndex == null) issues.push("UNWIND_INFO v3 epilog inherits without a preceding full descriptor.");
  else if ((epilogs[baseIndex]!.flags & 3) !== (flags & 3)) {
    issues.push("UNWIND_INFO v3 inherited epilog flags disagree with its full descriptor.");
  }
  return { kind: "inherited", flags, offset, baseEpilogIndex: baseIndex };
};

const readEpilogs = (cursor: PayloadCursor, count: number, issues: string[]): EncodedEpilog[] | null => {
  const epilogs: EncodedEpilog[] = [];
  let baseIndex: number | null = null;
  let resolvedOffset = 0;
  let direction = 0;
  for (let index = 0; index < count; index++) {
    const control = cursor.read(1, "epilog flags");
    const encodedOffset = cursor.read(2, "epilog offset");
    if (control == null || encodedOffset == null) return null;
    const offset = (encodedOffset << 16) >> 16;
    if (direction === 0) direction = Math.sign(offset);
    resolvedOffset += offset;
    const flags = control & 7;
    validateEpilogControl(flags, offset, direction, issues);
    if ((control >>> 3) === 0) {
      epilogs.push(readInheritedEpilog(flags, resolvedOffset, baseIndex, epilogs, issues));
      continue;
    }
    const full = readFullEpilog(cursor, flags, resolvedOffset, control >>> 3);
    if (!full) return null;
    baseIndex = index;
    epilogs.push(full);
  }
  return epilogs;
};

const validateIpOffsets = (record: Amd64UnwindV3, issues: string[]): void => {
  if (record.prologIpOffsets.some((offset, index, values) =>
    offset >= record.prologSize || (index > 0 && offset > values[index - 1]!))) {
    issues.push("UNWIND_INFO v3 prolog instruction offsets are outside the prolog or out of order.");
  }
  for (const epilog of record.epilogs) {
    if (epilog.kind === "full" && epilog.ipOffsets.some((offset, index, values) =>
      offset > epilog.lastInstructionOffset || (index > 0 && offset < values[index - 1]!))) {
      issues.push("UNWIND_INFO v3 epilog instruction offsets are outside the epilog or out of order.");
    }
  }
};

const readV3Header = (data: DataView, issues: string[]) => {
  if (data.byteLength < 4 || (data.getUint8(0) & 7) !== 3) {
    issues.push("UNWIND_INFO v3 header is truncated or has an invalid version.");
    return null;
  }
  const payloadSize = data.getUint8(2) * 2;
  if (data.byteLength - 4 < payloadSize) {
    issues.push("UNWIND_INFO v3 payload is shorter than PayloadWords declares.");
    return null;
  }
  const flags = data.getUint8(0) >>> 3;
  if ((flags & 16) !== 0) issues.push("UNWIND_INFO v3 sets a reserved header flag.");
  return { flags, prologSize: data.getUint8(1), operationCount: data.getUint8(3) & 31,
    epilogCount: data.getUint8(3) >>> 5, payload: new DataView(data.buffer, data.byteOffset + 4, payloadSize) };
};

/** Decode only the declared V3 payload; references may share byte ranges of the WOD pool. */
export const decodeAmd64UnwindV3 = (data: DataView, issues: string[]): Amd64UnwindV3 | null => {
  const header = readV3Header(data, issues);
  if (!header) return null;
  const { flags } = header;
  const cursor = createPayloadCursor(header.payload, issues);
  const highPrologSize = (flags & 8) !== 0 ? cursor.read(1, "large prolog extension") : 0;
  if (highPrologSize == null) return null;
  const prologIpOffsets = readIpOffsets(cursor, header.operationCount, (flags & 8) !== 0 ? 2 : 1);
  if (!prologIpOffsets) return null;
  const epilogs = readEpilogs(cursor, header.epilogCount, issues);
  if (!epilogs) return null;
  const readWinding = createV3WindingReader(cursor.remaining());
  const record: Amd64UnwindV3 = {
    flags,
    prologSize: header.prologSize | (highPrologSize << 8),
    prologIpOffsets,
    prologOperations: readWinding(0, prologIpOffsets.length, issues),
    epilogs: epilogs.map(epilog => epilog.kind === "inherited" ? epilog :
      { ...epilog, operations: readWinding(epilog.firstOp, epilog.ipOffsets.length, issues) })
  };
  validateIpOffsets(record, issues);
  return record;
};
